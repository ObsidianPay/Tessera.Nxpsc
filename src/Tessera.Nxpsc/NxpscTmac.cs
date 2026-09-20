using System.Security.Cryptography;
using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

/// <summary>
/// What a card returned for a committed transaction: the transaction MAC
/// counter (4 bytes, LSB first) and the 8 byte transaction MAC value. The
/// counter only moves forward, so a back office refuses a value whose counter
/// it has already seen.
/// </summary>
public sealed record TransactionMac(byte[] Tmc, byte[] Tmv)
{
    /// <summary>The counter as a number, for comparing with the last one seen.</summary>
    public uint Counter => (uint)(Tmc[0] | (Tmc[1] << 8) | (Tmc[2] << 16) | (Tmc[3] << 24));
}

/// <summary>
/// The transaction MAC a card would compute, worked out on the host: no card,
/// no reader. This is the back office side of the feature — it holds the
/// transaction MAC key, which a terminal never does, so only it can tell a
/// genuine transaction from a terminal's invention.
/// <para>
/// NXP publish no test vectors for this construction and no other
/// implementation computes it, so libnxpsc checks it only against a mock card
/// written independently from the same data sheet. Prove it against real
/// silicon before trusting it.
/// </para>
/// </summary>
public static unsafe class NxpscTmac
{
    /// <summary>
    /// The 8 byte value for a transaction: the session key comes from
    /// <paramref name="tmKey"/>, the card's UID and the counter the card
    /// reported, and the value is the MAC over <paramref name="tmi"/>.
    /// <paramref name="tmc"/> is passed exactly as the card reported it.
    /// </summary>
    public static byte[] Compute(NxpscKey tmKey, ReadOnlySpan<byte> uid, ReadOnlySpan<byte> tmc, ReadOnlySpan<byte> tmi)
    {
        ArgumentNullException.ThrowIfNull(tmKey);
        if (tmc.Length != 4)
            throw new ArgumentException("The transaction MAC counter is 4 bytes.", nameof(tmc));

        var tmv = new byte[8];
        NativeKey k = default;
        try
        {
            Interop.Load(tmKey, ref k);
            fixed (byte* u = uid)
            fixed (byte* c = tmc)
            fixed (byte* i = tmi)
            fixed (byte* v = tmv)
            {
                Interop.Check(NxpscNative.nxpsc_tmac_compute(&k, u, (nuint)uid.Length, c, i, (nuint)tmi.Length, v),
                    0, nameof(Compute));
            }
        }
        finally
        {
            Interop.Wipe(ref k);
        }
        return tmv;
    }

    /// <summary>
    /// The transaction MAC input a card accumulates for one WriteRecord:
    /// command, file, offset, length, zero padding, then the record. Built from
    /// the record the caller expected to be written, never from bytes a
    /// terminal reports.
    /// </summary>
    public static byte[] BuildWriteRecordTmi(byte fileNo, uint offset, ReadOnlySpan<byte> data)
    {
        var tmi = new byte[16 + (data.Length + 15) / 16 * 16];
        nuint length = 0;
        fixed (byte* d = data)
        fixed (byte* t = tmi)
        {
            Interop.Check(NxpscNative.nxpsc_tmac_tmi_write_record(fileNo, offset, d, (nuint)data.Length,
                t, (nuint)tmi.Length, &length), 0, nameof(BuildWriteRecordTmi));
        }
        return (int)length == tmi.Length ? tmi : tmi[..(int)length];
    }

    /// <summary>
    /// Whether a card's value matches the one computed here, compared in
    /// constant time. A mismatch is a refusal, never a retry.
    /// </summary>
    public static bool Verify(NxpscKey tmKey, ReadOnlySpan<byte> uid, TransactionMac reported, ReadOnlySpan<byte> tmi)
    {
        ArgumentNullException.ThrowIfNull(reported);
        var expected = Compute(tmKey, uid, reported.Tmc, tmi);
        return CryptographicOperations.FixedTimeEquals(expected, reported.Tmv);
    }
}
