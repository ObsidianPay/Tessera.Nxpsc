using System.Runtime.InteropServices;
using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc.Mock;

/// <summary>
/// libnxpsc's own mock card (tests/mockcard.c), behind native/tessera_mockcard.c
/// so it remembers its keys and applications. It runs the real framing and the
/// real card-side crypto, so a personalisation run against it exercises
/// libnxpsc, the interop layer and the transport callback end to end.
/// <para>
/// It cannot witness what a ChangeKey cryptogram actually carried: the caller
/// states up front what a changed key reads as (<see cref="SetChangeKeyResult"/>).
/// Whether the key really changed is a hardware question for an independent
/// reader.
/// </para>
/// </summary>
public sealed unsafe class MockCard : ICardTransport
{
    private const string Library = "tessera_mockcard";

    private nint _handle;

    static MockCard() => NativeLibraryResolver.EnsureRegistered();

    public MockCard(NxpscCardType type, ReadOnlySpan<byte> uid)
    {
        if (uid.Length != 7)
            throw new ArgumentException("The mock models a 7-byte UID.", nameof(uid));
        fixed (byte* p = uid)
            _handle = tmock_create((int)type, p, 7);
        if (_handle == 0)
            throw new OutOfMemoryException("tmock_create failed.");
        Uid = uid.ToArray();

        // the mock expects the fixed RndA libnxpsc's tests use; one-way for the process
        NxpscCard.EnableMockRng();
    }

    public string Description => "libnxpsc mock card";

    public bool IsMock => true;

    public byte[] Uid { get; }

    /// <summary>Puts <paramref name="key"/> in a key slot the card already has. AID 0 key 0 is the PICC master key.</summary>
    public void SetKey(uint aid, byte keyNo, NxpscKey key)
    {
        fixed (byte* p = key.Bytes)
            if (tmock_set_key(Handle, aid, keyNo, (int)key.Type, p, (nuint)key.Bytes.Length) != 0)
                throw new ArgumentException($"No key {keyNo} in application {aid:X6}.");
    }

    public void AddApplication(uint aid, NxpscKeyType type, byte numKeys)
    {
        if (tmock_add_application(Handle, aid, (int)type, numKeys) != 0)
            throw new ArgumentException($"Could not add application {aid:X6}.");
    }

    public bool HasApplication(uint aid) => tmock_has_application(Handle, aid);

    /// <summary>What a key slot holds after a ChangeKey the card acknowledged.</summary>
    public void SetChangeKeyResult(NxpscKey key)
    {
        fixed (byte* p = key.Bytes)
            tmock_set_change_key_result(Handle, true, (int)key.Type, p, (nuint)key.Bytes.Length);
    }

    /// <summary>The card acknowledges ChangeKey and silently keeps the old key.</summary>
    public void SetChangeKeyIgnored() => tmock_set_change_key_result(Handle, false, 0, null, 0);

    public bool KeyEquals(uint aid, byte keyNo, NxpscKey key)
    {
        fixed (byte* p = key.Bytes)
            return tmock_key_equals(Handle, aid, keyNo, p, (nuint)key.Bytes.Length) == 1;
    }

    public void SetSignature(ReadOnlySpan<byte> signature)
    {
        fixed (byte* p = signature)
            tmock_set_signature(Handle, p, (nuint)signature.Length);
    }

    /// <summary>The card leaves the field at the first frame carrying <paramref name="nativeCommand"/>.</summary>
    public void TearOn(byte nativeCommand, bool afterExecute) => tmock_tear_on(Handle, nativeCommand, afterExecute);

    public bool Torn => tmock_torn(Handle);

    public void Reinsert() => tmock_reinsert(Handle);

    public bool TryTransceive(ReadOnlySpan<byte> command, Span<byte> response, out int responseLength)
    {
        responseLength = 0;
        nuint received = 0;
        int rc;
        fixed (byte* tx = command)
        fixed (byte* rx = response)
            rc = tmock_transceive(Handle, tx, (nuint)command.Length, rx, (nuint)response.Length, &received);
        if (rc != 0)
            return false;
        responseLength = (int)received;
        return true;
    }

    public void Dispose()
    {
        if (_handle != 0)
        {
            tmock_free(_handle);
            _handle = 0;
        }
    }

    private nint Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_handle == 0, this);
            return _handle;
        }
    }

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern nint tmock_create(int cardType, byte* uid, nuint uidLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void tmock_free(nint mock);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int tmock_set_key(nint mock, uint aid, byte keyNo, int keyType, byte* key, nuint keyLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int tmock_add_application(nint mock, uint aid, int keyType, byte numKeys);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool tmock_has_application(nint mock, uint aid);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void tmock_set_change_key_result(nint mock, [MarshalAs(UnmanagedType.U1)] bool takes,
        int keyType, byte* key, nuint keyLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int tmock_key_equals(nint mock, uint aid, byte keyNo, byte* key, nuint keyLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void tmock_set_signature(nint mock, byte* sig, nuint len);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void tmock_tear_on(nint mock, byte nativeCmd, [MarshalAs(UnmanagedType.U1)] bool afterExecute);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool tmock_torn(nint mock);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void tmock_reinsert(nint mock);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int tmock_transceive(nint mock, byte* tx, nuint txLen, byte* rx, nuint cap, nuint* rxLen);
}
