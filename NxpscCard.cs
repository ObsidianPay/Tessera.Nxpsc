using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

/// <summary>
/// One card session through libnxpsc: the only class that calls into the
/// library. Every method maps a negative return code to an
/// <see cref="NxpscException"/> carrying nxpsc_last_status() and
/// nxpsc_session_lost().
/// <para>
/// The transport callback is a static [UnmanagedCallersOnly] function, not a
/// marshalled delegate, so there is no delegate for the GC to collect under the
/// library. What does have to outlive the native card is the context handle
/// passed as ctx: it is held in <see cref="_self"/> and freed only after
/// nxpsc_close.
/// </para>
/// </summary>
public sealed unsafe class NxpscCard : IDisposable
{
    private readonly ICardTransport _transport;
    private GCHandle _self;
    private nint _card;

    static NxpscCard() => NativeLibraryResolver.EnsureRegistered();

    private NxpscCard(ICardTransport transport)
    {
        _transport = transport;
    }

    /// <summary>
    /// Opens a session over <paramref name="transport"/> and selects the
    /// ISO-wrapped native command set, before any command is sent: PC/SC cannot
    /// carry raw native frames.
    /// </summary>
    public static NxpscCard Open(ICardTransport transport)
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
        };

        nint handle;
        var rc = NxpscNative.nxpsc_open(&native, &handle);
        if (rc != NxpscError.Ok)
        {
            card._self.Free();
            throw Failure("nxpsc_open", rc, 0);
        }

        card._card = handle;
        NxpscNative.nxpsc_set_cmdset(handle, NxpscCmdSet.NativeIso);
        return card;
    }

    // ---- library-level calls (no card) ------------------------------------------

    private static volatile bool _mockRngActive;

    /// <summary>
    /// libnxpsc's mock card answers every handshake as if the host's RndA were
    /// 0x10, 0x11, 0x12, ... — the value libnxpsc's own tests inject through its
    /// internal RNG hook. Driving the mock means doing the same. It is one-way
    /// for the process: after this, <see cref="Open"/> refuses any transport
    /// that is not the mock, so a real card never sees a predictable RndA.
    /// </summary>
    internal static void EnableMockRng()
    {
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

    /// <summary>
    /// libnxpsc's crypto known-answer tests, AN10922 vectors included. Anything
    /// but true means the crypto is wrong at run time and no card may be touched.
    /// </summary>
    public static bool SelfTest() => NxpscNative.nxpsc_selftest(false) == NxpscError.Ok;

    /// <summary>The version the loaded library was built from.</summary>
    public static string LibraryVersion() =>
        Marshal.PtrToStringAnsi(NxpscNative.nxpsc_version_string()) ?? "unknown";

    public static string CardTypeName(NxpscCardType type) =>
        Marshal.PtrToStringAnsi(NxpscNative.nxpsc_cardtype_str((int)type)) ?? type.ToString();

    /// <summary>
    /// AN10922 diversification by libnxpsc. <paramref name="diversificationInput"/>
    /// excludes the padding constant and is at most 31 bytes. The derived key keeps
    /// the master key's type and takes <paramref name="derivedVersion"/> as its
    /// version: the version belongs to the key as loaded, not to the derivation.
    /// </summary>
    public static NxpscKey DiversifyAn10922(NxpscKey master, ReadOnlySpan<byte> diversificationInput, byte derivedVersion)
    {
        ArgumentNullException.ThrowIfNull(master);

        NativeKey m = default, derived = default;
        try
        {
            Load(master, ref m);
            int rc;
            fixed (byte* input = diversificationInput)
                rc = NxpscNative.nxpsc_diversify_an10922(&m, input, (nuint)diversificationInput.Length, &derived);
            if (rc != NxpscError.Ok)
                throw Failure("nxpsc_diversify_an10922", rc, 0);

            var size = NxpscKey.SizeOf((NxpscKeyType)derived.Type);
            return new NxpscKey((NxpscKeyType)derived.Type, new ReadOnlySpan<byte>(derived.Data, size), derivedVersion);
        }
        finally
        {
            Wipe(ref m);
            Wipe(ref derived);
        }
    }

    // ---- session state -----------------------------------------------------------

    public string TransportDescription => _transport.Description;

    public bool IsAuthenticated => NxpscNative.nxpsc_is_authenticated(Handle);

    /// <summary>
    /// The PICC dropped secure messaging after answering an in-session command
    /// with an error. Nothing that needs the session can succeed until a fresh
    /// authentication.
    /// </summary>
    public bool SessionLost => NxpscNative.nxpsc_session_lost(Handle);

    public NxpscChannel ActiveChannel => (NxpscChannel)NxpscNative.nxpsc_active_channel(Handle);

    public byte LastStatus => NxpscNative.nxpsc_last_status(Handle);

    public void ResetChannel() => NxpscNative.nxpsc_reset_channel(Handle);

    // ---- commands ------------------------------------------------------------------

    public CardVersion GetVersion()
    {
        NativeVersion v = default;
        Check(NxpscNative.nxpsc_get_version(Handle, &v));
        return new CardVersion(v.HwVendor, v.HwType, v.HwMajor, v.HwMinor, v.HwStorage,
            v.SwMajor, v.SwMinor, new ReadOnlySpan<byte>(v.Uid, 7).ToArray(), v.Week, v.Year);
    }

    /// <summary>libnxpsc's own identification from GetVersion and its product table.</summary>
    public NxpscCardType Identify()
    {
        int type = 0;
        Check(NxpscNative.nxpsc_identify(Handle, &type));
        return (NxpscCardType)type;
    }

    /// <summary>The raw originality signature. libnxpsc does not verify it.</summary>
    public byte[] GetSignature()
    {
        Span<byte> sig = stackalloc byte[64];
        nuint len = 0;
        fixed (byte* p = sig)
            Check(NxpscNative.nxpsc_get_signature(Handle, p, (nuint)sig.Length, &len));
        return sig[..(int)len].ToArray();
    }

    /// <summary>GetCardUID: the real UID through the secure channel. Needs a session.</summary>
    public byte[] GetCardUid()
    {
        Span<byte> uid = stackalloc byte[16];
        nuint len = 0;
        fixed (byte* p = uid)
            Check(NxpscNative.nxpsc_get_card_uid(Handle, p, (nuint)uid.Length, &len));
        return uid[..(int)len].ToArray();
    }

    public void SelectApplication(uint aid) => Check(NxpscNative.nxpsc_select_application(Handle, aid));

    public void Authenticate(byte keyNo, NxpscKey key, NxpscChannel channel = NxpscChannel.Auto)
    {
        ArgumentNullException.ThrowIfNull(key);
        NativeKey k = default;
        try
        {
            Load(key, ref k);
            Check(NxpscNative.nxpsc_authenticate(Handle, keyNo, &k, (int)channel));
        }
        finally
        {
            Wipe(ref k);
        }
    }

    public void CreateApplication(uint aid, byte keySettings, byte numKeys, NxpscKeyType keyType) =>
        Check(NxpscNative.nxpsc_create_application(Handle, aid, keySettings, numKeys, (int)keyType));

    /// <summary>
    /// ChangeKey. Changing the key the session was built on ends the session, so
    /// the caller must select and authenticate again to prove the change.
    /// </summary>
    public void ChangeKey(byte keyNo, NxpscKey oldKey, NxpscKey newKey)
    {
        ArgumentNullException.ThrowIfNull(oldKey);
        ArgumentNullException.ThrowIfNull(newKey);
        NativeKey o = default, n = default;
        try
        {
            Load(oldKey, ref o);
            Load(newKey, ref n);
            Check(NxpscNative.nxpsc_change_key(Handle, keyNo, &o, &n));
        }
        finally
        {
            Wipe(ref o);
            Wipe(ref n);
        }
    }

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

    // ---- plumbing ------------------------------------------------------------------

    private nint Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_card == 0, this);
            return _card;
        }
    }

    private void Check(int rc, [CallerMemberName] string operation = "")
    {
        if (rc >= NxpscError.Ok)
            return;
        throw Failure(operation, rc, _card);
    }

    private static NxpscException Failure(string operation, int rc, nint card)
    {
        var code = Enum.IsDefined(typeof(NxpscErrorCode), rc) ? (NxpscErrorCode)rc : NxpscErrorCode.Param;
        var codeText = Marshal.PtrToStringAnsi(NxpscNative.nxpsc_strerror(rc)) ?? rc.ToString();

        byte? status = null;
        string? statusText = null;
        var sessionLost = false;
        if (card != 0)
        {
            if (rc == NxpscError.Card)
            {
                status = NxpscNative.nxpsc_last_status(card);
                statusText = Marshal.PtrToStringAnsi(NxpscNative.nxpsc_status_str(status.Value));
            }
            sessionLost = NxpscNative.nxpsc_session_lost(card);
        }
        return new NxpscException(operation, code, codeText, status, statusText, sessionLost);
    }

    private static void Load(NxpscKey key, ref NativeKey native)
    {
        native.Type = (int)key.Type;
        native.Version = key.Version;
        fixed (byte* d = native.Data)
            key.Bytes.CopyTo(new Span<byte>(d, 32));
    }

    private static void Wipe(ref NativeKey native)
    {
        fixed (NativeKey* p = &native)
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(new Span<byte>(p, sizeof(NativeKey)));
    }

    /// <summary>
    /// The transceive callback. It must never throw (an exception crossing into
    /// native code terminates the process), so every failure becomes
    /// NXPSC_E_TRANSPORT. A card error status is NOT a failure here: the frame
    /// is passed back with NXPSC_OK for libnxpsc to decode, exactly as the PC/SC
    /// transceive in the hardware suites does.
    /// </summary>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Transceive(nint ctx, byte* tx, nuint txLen, byte* rx, nuint rxCap, nuint* rxLen)
    {
        try
        {
            if (GCHandle.FromIntPtr(ctx).Target is not NxpscCard self)
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
}
