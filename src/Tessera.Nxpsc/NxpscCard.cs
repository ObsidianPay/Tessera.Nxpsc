using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

/// <summary>
/// One card session through libnxpsc (nxpsc_card_t). Every method maps a
/// negative return code to an <see cref="NxpscException"/> carrying the card
/// status byte and whether the PICC dropped the secure session.
/// <para>
/// A card is used from one thread at a time, as libnxpsc requires. The
/// transport callbacks are static [UnmanagedCallersOnly] functions, not
/// marshalled delegates, so nothing can be collected under the library; what
/// must outlive the native card is the context handle, which is freed only
/// after nxpsc_close.
/// </para>
/// <para>
/// The partial files group the API as nxpsc.h does: this one holds the life
/// cycle, session state, identification and keys; the others applications,
/// files, EV2 extras, ISO / NTAG and MIFARE Plus.
/// </para>
/// </summary>
public sealed unsafe partial class NxpscCard : IDisposable
{
    private unsafe delegate int BufferCall(byte* buffer, nuint capacity, nuint* length);

    private static volatile bool _mockRngActive;

    private readonly ICardTransport _transport;
    private GCHandle _self;
    private nint _card;

    static NxpscCard() => NativeLibraryResolver.EnsureRegistered();

    private NxpscCard(ICardTransport transport)
    {
        _transport = transport;
    }

    /// <summary>
    /// Opens a session over <paramref name="transport"/>. The command set starts
    /// as <paramref name="cmdSet"/>; the default, ISO-wrapped native commands, is
    /// what PC/SC and most phone NFC stacks need.
    /// </summary>
    public static NxpscCard Open(ICardTransport transport, NxpscCmdSet cmdSet = NxpscCmdSet.NativeIso)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (_mockRngActive && !transport.IsMock)
        {
            throw new InvalidOperationException(
                "The mock card's deterministic RNG is active in this process; refusing to open a real card with it.");
        }

        var card = new NxpscCard(transport);
        card._self = GCHandle.Alloc(card, GCHandleType.Normal);

        var native = new NativeTransport
        {
            Ctx = GCHandle.ToIntPtr(card._self),
            Transceive = &Transceive,
            GetUid = transport is IUidTransport ? &GetUid : null,
            Reselect = transport is IReselectTransport ? &Reselect : null,
        };

        nint handle;
        var rc = NxpscNative.nxpsc_open(&native, &handle);
        if (rc != NxpscError.Ok)
        {
            card._self.Free();
            throw Interop.Failure(rc, 0, nameof(Open));
        }

        card._card = handle;
        NxpscNative.nxpsc_set_cmdset(handle, (int)cmdSet);
        return card;
    }

    public string TransportDescription => _transport.Description;

    public void Dispose()
    {
        if (_card != 0)
        {
            NxpscNative.nxpsc_close(_card);
            _card = 0;
        }
        if (_self.IsAllocated)
            _self.Free();
    }

    // ---- session state -----------------------------------------------------------

    public NxpscCmdSet CmdSet
    {
        get => (NxpscCmdSet)NxpscNative.nxpsc_get_cmdset(Handle);
        set => NxpscNative.nxpsc_set_cmdset(Handle, (int)value);
    }

    /// <summary>Default communication mode for commands that do not derive one from a file.</summary>
    public void SetCommMode(NxpscCommMode mode) => NxpscNative.nxpsc_set_commmode(Handle, (int)mode);

    public bool IsAuthenticated => NxpscNative.nxpsc_is_authenticated(Handle);

    /// <summary>The secure channel in use; <see cref="NxpscChannel.Auto"/> when there is no session.</summary>
    public NxpscChannel ActiveChannel => (NxpscChannel)NxpscNative.nxpsc_active_channel(Handle);

    /// <summary>
    /// The PICC dropped secure messaging after answering an in-session command
    /// with an error. Nothing that needs the session can succeed until a fresh
    /// authentication or <see cref="ResetChannel"/>.
    /// </summary>
    public bool SessionLost => NxpscNative.nxpsc_session_lost(Handle);

    public uint SelectedAid => NxpscNative.nxpsc_selected_aid(Handle);

    /// <summary>Status byte of the last card answer.</summary>
    public byte LastStatus => NxpscNative.nxpsc_last_status(Handle);

    /// <summary>Forget the secure channel on the host side.</summary>
    public void ResetChannel() => NxpscNative.nxpsc_reset_channel(Handle);

    /// <summary>ISO chaining (0xAD / 0x8D / 0xAB / 0x8B / 0xBA) instead of the native file access opcodes.</summary>
    public bool IsoChaining
    {
        get => NxpscNative.nxpsc_get_iso_chaining(Handle);
        set => NxpscNative.nxpsc_set_iso_chaining(Handle, value);
    }

    // ---- identification ------------------------------------------------------------

    public CardVersion GetVersion()
    {
        NativeVersion v = default;
        Check(NxpscNative.nxpsc_get_version(Handle, &v));
        return Interop.FromNative(v);
    }

    /// <summary>libnxpsc's identification from GetVersion and its product table (calls GetVersion if needed).</summary>
    public NxpscCardType Identify()
    {
        int type = 0;
        Check(NxpscNative.nxpsc_identify(Handle, &type));
        return (NxpscCardType)type;
    }

    /// <summary>The cached identification, <see cref="NxpscCardType.Unknown"/> before <see cref="Identify"/>.</summary>
    public NxpscCardType CardType => (NxpscCardType)NxpscNative.nxpsc_card_type(Handle);

    /// <summary>GetCardUID: the real UID through the secure channel.</summary>
    public byte[] GetCardUid() =>
        ReadBuffer(16, (p, cap, len) => NxpscNative.nxpsc_get_card_uid(Handle, p, cap, len));

    public uint GetFreeMemory()
    {
        uint bytes = 0;
        Check(NxpscNative.nxpsc_get_free_memory(Handle, &bytes));
        return bytes;
    }

    /// <summary>The raw NXP originality signature. libnxpsc does not verify it.</summary>
    public byte[] GetSignature() =>
        ReadBuffer(64, (p, cap, len) => NxpscNative.nxpsc_get_signature(Handle, p, cap, len));

    // ---- authentication and keys -------------------------------------------------------

    public void SelectApplication(uint aid) => Check(NxpscNative.nxpsc_select_application(Handle, aid));

    public void Authenticate(byte keyNo, NxpscKey key, NxpscChannel channel = NxpscChannel.Auto)
    {
        ArgumentNullException.ThrowIfNull(key);
        NativeKey k = default;
        try
        {
            Interop.Load(key, ref k);
            Check(NxpscNative.nxpsc_authenticate(Handle, keyNo, &k, (int)channel));
        }
        finally
        {
            Interop.Wipe(ref k);
        }
    }

    /// <summary>EV2 only: continue an established EV2 session with another key.</summary>
    public void AuthenticateNonFirst(byte keyNo, NxpscKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        NativeKey k = default;
        try
        {
            Interop.Load(key, ref k);
            Check(NxpscNative.nxpsc_authenticate_nonfirst(Handle, keyNo, &k));
        }
        finally
        {
            Interop.Wipe(ref k);
        }
    }

    /// <summary>
    /// ChangeKey. Changing the key the session was built on ends the session;
    /// select and authenticate again to prove the change.
    /// </summary>
    public void ChangeKey(byte keyNo, NxpscKey oldKey, NxpscKey newKey)
    {
        ArgumentNullException.ThrowIfNull(oldKey);
        ArgumentNullException.ThrowIfNull(newKey);
        NativeKey o = default, n = default;
        try
        {
            Interop.Load(oldKey, ref o);
            Interop.Load(newKey, ref n);
            Check(NxpscNative.nxpsc_change_key(Handle, keyNo, &o, &n));
        }
        finally
        {
            Interop.Wipe(ref o);
            Interop.Wipe(ref n);
        }
    }

    /// <summary>ChangeKeyEV2, key set aware (EV2 and later).</summary>
    public void ChangeKeyEv2(byte keySet, byte keyNo, NxpscKey oldKey, NxpscKey newKey)
    {
        ArgumentNullException.ThrowIfNull(oldKey);
        ArgumentNullException.ThrowIfNull(newKey);
        NativeKey o = default, n = default;
        try
        {
            Interop.Load(oldKey, ref o);
            Interop.Load(newKey, ref n);
            Check(NxpscNative.nxpsc_change_key_ev2(Handle, keySet, keyNo, &o, &n));
        }
        finally
        {
            Interop.Wipe(ref o);
            Interop.Wipe(ref n);
        }
    }

    public byte GetKeyVersion(byte keyNo)
    {
        byte version = 0;
        Check(NxpscNative.nxpsc_get_key_version(Handle, keyNo, &version));
        return version;
    }

    public NxpscKeySettings GetKeySettings()
    {
        byte settings = 0, numKeys = 0;
        int keyType = 0;
        Check(NxpscNative.nxpsc_get_key_settings(Handle, &settings, &numKeys, &keyType));
        return new NxpscKeySettings(settings, numKeys, (NxpscKeyType)keyType);
    }

    /// <summary>
    /// ChangeKeySettings. Some settings (a frozen master key, a frozen
    /// configuration) cannot be undone.
    /// </summary>
    public void ChangeKeySettings(byte keySettings) =>
        Check(NxpscNative.nxpsc_change_key_settings(Handle, keySettings));

    // ---- escape hatch ---------------------------------------------------------------------

    /// <summary>
    /// Sends any native DESFire command through the active secure channel. The
    /// answer excludes the status byte, which lands in <see cref="LastStatus"/>.
    /// </summary>
    public byte[] Command(byte command, ReadOnlySpan<byte> data, NxpscCommMode txMode, NxpscCommMode rxMode,
        int responseCapacity = NxpscLimits.MaxResponse)
    {
        var copy = data.ToArray();
        return ReadBuffer(responseCapacity, (p, cap, len) =>
        {
            fixed (byte* d = copy)
                return NxpscNative.nxpsc_command(Handle, command, d, (nuint)copy.Length, (int)txMode, (int)rxMode, p, cap, len);
        });
    }

    // ---- the mock card ------------------------------------------------------------------

    /// <summary>
    /// libnxpsc's mock card answers every handshake as if the host's RndA were
    /// 0x10, 0x11, 0x12, ... — the value libnxpsc's own tests inject through its
    /// internal RNG hook. Driving the mock means doing the same. It is one-way
    /// for the process: afterwards <see cref="Open"/> refuses any transport that
    /// is not a mock, so a real card never sees a predictable RndA.
    /// </summary>
    internal static void EnableMockRng()
    {
        NativeLibraryResolver.EnsureRegistered();
        _mockRngActive = true;
        NxpscNative.nxpsc_set_rng(&MockRng, 0);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int MockRng(nint ctx, byte* output, nuint length)
    {
        for (nuint i = 0; i < length; i++)
            output[i] = (byte)(0x10 + i);
        return NxpscError.Ok;
    }

    // ---- plumbing ---------------------------------------------------------------------------

    private nint Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_card == 0, this);
            return _card;
        }
    }

    private void Check(int rc, [CallerMemberName] string operation = "") => Interop.Check(rc, _card, operation);

    private byte[] ReadBuffer(int capacity, BufferCall call, [CallerMemberName] string operation = "")
    {
        var buffer = new byte[capacity];
        nuint length = 0;
        int rc;
        fixed (byte* p = buffer)
            rc = call(p, (nuint)buffer.Length, &length);
        Check(rc, operation);
        return buffer.AsSpan(0, (int)Math.Min(length, (nuint)buffer.Length)).ToArray();
    }

    private static NxpscCard? FromContext(nint ctx) =>
        ctx == 0 ? null : GCHandle.FromIntPtr(ctx).Target as NxpscCard;

    /// <summary>
    /// The transceive callback. It must never throw (an exception crossing into
    /// native code terminates the process), so every failure becomes
    /// NXPSC_E_TRANSPORT. A card error status is NOT a failure here: the frame
    /// goes back with NXPSC_OK for libnxpsc to decode.
    /// </summary>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Transceive(nint ctx, byte* tx, nuint txLen, byte* rx, nuint rxCap, nuint* rxLen)
    {
        try
        {
            if (FromContext(ctx) is not { } self)
                return NxpscError.Transport;

            var command = new ReadOnlySpan<byte>(tx, checked((int)txLen));
            var response = new Span<byte>(rx, checked((int)rxCap));
            if (!self._transport.TryTransceive(command, response, out var received))
                return NxpscError.Transport;
            if (received < 0 || received > response.Length)
                return NxpscError.Transport;

            *rxLen = (nuint)received;
            return NxpscError.Ok;
        }
        catch
        {
            return NxpscError.Transport;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int GetUid(nint ctx, byte* uid, nuint cap, nuint* uidLen)
    {
        try
        {
            if (FromContext(ctx)?._transport is not IUidTransport transport)
                return NxpscError.Unsupported;
            var span = new Span<byte>(uid, checked((int)cap));
            if (!transport.TryGetUid(span, out var length) || length < 0 || length > span.Length)
                return NxpscError.Transport;
            *uidLen = (nuint)length;
            return NxpscError.Ok;
        }
        catch
        {
            return NxpscError.Transport;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Reselect(nint ctx)
    {
        try
        {
            return FromContext(ctx)?._transport is IReselectTransport transport && transport.TryReselect()
                ? NxpscError.Ok
                : NxpscError.Transport;
        }
        catch
        {
            return NxpscError.Transport;
        }
    }
}
