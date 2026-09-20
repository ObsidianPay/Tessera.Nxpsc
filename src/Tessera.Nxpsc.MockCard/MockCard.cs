using System.Runtime.InteropServices;
using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc.Mock;

/// <summary>
/// libnxpsc's own mock card (tests/mockcard.c), behind native/nxpsc_mockcard.c
/// so it remembers its keys and applications. It runs the real framing and the
/// real card-side crypto, so a whole flow against it exercises
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
    private const string Library = "nxpsc_mockcard";

    private nint _handle;

    static MockCard() => NativeLibraryResolver.Register(typeof(MockCard).Assembly);

    public MockCard(NxpscCardType type, ReadOnlySpan<byte> uid)
    {
        if (uid.Length != 7)
            throw new ArgumentException("The mock models a 7-byte UID.", nameof(uid));
        fixed (byte* p = uid)
            _handle = mockcard_create((int)type, p, 7);
        if (_handle == 0)
            throw new OutOfMemoryException("mockcard_create failed.");
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
            if (mockcard_set_key(Handle, aid, keyNo, (int)key.Type, p, (nuint)key.Bytes.Length) != 0)
                throw new ArgumentException($"No key {keyNo} in application {aid:X6}.");
    }

    public void AddApplication(uint aid, NxpscKeyType type, byte numKeys)
    {
        if (mockcard_add_application(Handle, aid, (int)type, numKeys) != 0)
            throw new ArgumentException($"Could not add application {aid:X6}.");
    }

    public bool HasApplication(uint aid) => mockcard_has_application(Handle, aid);

    /// <summary>What a key slot holds after a ChangeKey the card acknowledged.</summary>
    public void SetChangeKeyResult(NxpscKey key)
    {
        fixed (byte* p = key.Bytes)
            mockcard_set_change_key_result(Handle, true, (int)key.Type, p, (nuint)key.Bytes.Length, key.Version);
    }

    /// <summary>The card acknowledges ChangeKey and silently keeps the old key.</summary>
    public void SetChangeKeyIgnored() => mockcard_set_change_key_result(Handle, false, 0, null, 0, 0);

    public bool KeyEquals(uint aid, byte keyNo, NxpscKey key)
    {
        fixed (byte* p = key.Bytes)
            return mockcard_key_equals(Handle, aid, keyNo, p, (nuint)key.Bytes.Length) == 1;
    }

    /// <summary>
    /// The AppTransactionMACKey the card computes its transaction MAC with. A
    /// real card is told it inside CreateTransactionMACFile, enciphered; the
    /// mock does not decipher command data, so it is stated here. The file
    /// still has to be created on the card before a commit returns a MAC.
    /// </summary>
    public void SetTransactionMacKey(NxpscKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        fixed (byte* p = key.Bytes)
        {
            if (mockcard_set_transaction_mac_key(Handle, p, (nuint)key.Bytes.Length) != 0)
                throw new ArgumentException("The transaction MAC key must be AES-128.", nameof(key));
        }
    }

    /// <summary>The counter the card reported for its last committed transaction.</summary>
    public uint TransactionCounter => mockcard_transaction_counter(Handle);

    /// <summary>
    /// A file the card already holds, as if an earlier run had created it.
    /// <paramref name="recordSize"/> and <paramref name="maxRecords"/> are for
    /// record files, <paramref name="size"/> for data files.
    /// </summary>
    public void AddFile(byte fileNo, NxpscFileType type, NxpscCommMode comm, NxpscAccessRights access,
        uint recordSize = 0, uint maxRecords = 0, uint size = 0)
    {
        if (mockcard_add_file(Handle, fileNo, (byte)type, (byte)comm, Pack(access), size, recordSize, maxRecords) != 0)
            throw new ArgumentException($"Could not add file {fileNo:X2}.", nameof(fileNo));
    }

    /// <summary>
    /// What the card reports for its transaction MAC file. Those settings reach
    /// a real card inside CreateTransactionMACFile, enciphered, so the mock is
    /// told them the same way it is told the key.
    /// </summary>
    public void SetTransactionMacFileSettings(byte fileNo, NxpscCommMode comm, NxpscAccessRights access)
    {
        if (mockcard_set_transaction_mac_file(Handle, fileNo, (byte)comm, Pack(access)) != 0)
            throw new ArgumentException("Could not set the transaction MAC file settings.", nameof(fileNo));
    }

    /// <summary>
    /// Switches the transaction MAC feature on without a CreateTransactionMACFile,
    /// for a card an earlier run already finished.
    /// </summary>
    public void EnableTransactionMac() => mockcard_enable_transaction_mac(Handle);

    private static ushort Pack(NxpscAccessRights a) => (ushort)(
        ((a.Read & 0x0F) << 12) | ((a.Write & 0x0F) << 8) | ((a.ReadWrite & 0x0F) << 4) | (a.Change & 0x0F));

    public void SetSignature(ReadOnlySpan<byte> signature)
    {
        fixed (byte* p = signature)
            mockcard_set_signature(Handle, p, (nuint)signature.Length);
    }

    /// <summary>The card leaves the field at the first frame carrying <paramref name="nativeCommand"/>.</summary>
    public void TearOn(byte nativeCommand, bool afterExecute) => mockcard_tear_on(Handle, nativeCommand, afterExecute);

    public bool Torn => mockcard_torn(Handle);

    public void Reinsert() => mockcard_reinsert(Handle);

    public bool TryTransceive(ReadOnlySpan<byte> command, Span<byte> response, out int responseLength)
    {
        responseLength = 0;
        nuint received = 0;
        int rc;
        fixed (byte* tx = command)
        fixed (byte* rx = response)
            rc = mockcard_transceive(Handle, tx, (nuint)command.Length, rx, (nuint)response.Length, &received);
        if (rc != 0)
            return false;
        responseLength = (int)received;
        return true;
    }

    public void Dispose()
    {
        if (_handle != 0)
        {
            mockcard_free(_handle);
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
    private static extern nint mockcard_create(int cardType, byte* uid, nuint uidLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void mockcard_free(nint mock);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int mockcard_set_key(nint mock, uint aid, byte keyNo, int keyType, byte* key, nuint keyLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int mockcard_add_application(nint mock, uint aid, int keyType, byte numKeys);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool mockcard_has_application(nint mock, uint aid);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void mockcard_set_change_key_result(nint mock, [MarshalAs(UnmanagedType.U1)] bool takes,
        int keyType, byte* key, nuint keyLen, byte keyVersion);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int mockcard_key_equals(nint mock, uint aid, byte keyNo, byte* key, nuint keyLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void mockcard_set_signature(nint mock, byte* sig, nuint len);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int mockcard_set_transaction_mac_key(nint mock, byte* key, nuint keyLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern uint mockcard_transaction_counter(nint mock);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int mockcard_add_file(nint mock, byte fileNo, byte type, byte comm, ushort access,
        uint size, uint recordSize, uint maxRecords);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int mockcard_set_transaction_mac_file(nint mock, byte fileNo, byte comm, ushort access);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void mockcard_enable_transaction_mac(nint mock);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void mockcard_tear_on(nint mock, byte nativeCmd, [MarshalAs(UnmanagedType.U1)] bool afterExecute);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool mockcard_torn(nint mock);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void mockcard_reinsert(nint mock);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int mockcard_transceive(nint mock, byte* tx, nuint txLen, byte* rx, nuint cap, nuint* rxLen);
}
