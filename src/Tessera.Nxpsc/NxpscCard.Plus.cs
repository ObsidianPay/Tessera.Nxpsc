using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

// MIFARE Plus EV1 / EV2, security level 3. Block numbers use MIFARE Plus
// addressing; key numbers are the AES key block addresses (0x4000 + n for data
// sectors).
public sealed unsafe partial class NxpscCard
{
    public void PlusAuthenticate(ushort keyBlock, NxpscKey key, bool first)
    {
        ArgumentNullException.ThrowIfNull(key);
        NativeKey k = default;
        try
        {
            Interop.Load(key, ref k);
            Check(NxpscNative.nxpsc_plus_authenticate(Handle, keyBlock, &k, first));
        }
        finally
        {
            Interop.Wipe(ref k);
        }
    }

    public byte[] PlusRead(ushort block, byte count, bool encrypted, bool maced) =>
        ReadBuffer(count * 16 + 16, (p, cap, len) =>
            NxpscNative.nxpsc_plus_read(Handle, block, count, encrypted, maced, p, cap, len));

    public void PlusWrite(ushort block, ReadOnlySpan<byte> data, bool encrypted)
    {
        fixed (byte* d = data)
            Check(NxpscNative.nxpsc_plus_write(Handle, block, d, (nuint)data.Length, encrypted));
    }

    /// <summary>WritePerso (security level 0).</summary>
    public void PlusWritePerso(ushort block, ReadOnlySpan<byte> data)
    {
        fixed (byte* d = data)
            Check(NxpscNative.nxpsc_plus_write_perso(Handle, block, d, (nuint)data.Length));
    }

    /// <summary>CommitPerso: leaves security level 0. <b>One-way.</b></summary>
    public void PlusCommitPerso() => Check(NxpscNative.nxpsc_plus_commit_perso(Handle));

    /// <summary>Increment (credit) or decrement a value block into the transfer buffer.</summary>
    public void PlusValueOperation(ushort block, int delta, bool credit, bool encrypted) =>
        Check(NxpscNative.nxpsc_plus_value_op(Handle, block, delta, credit, encrypted));

    public void PlusTransfer(ushort block) => Check(NxpscNative.nxpsc_plus_transfer(Handle, block));

    /// <summary>A value operation that transfers to the same block in one command.</summary>
    public void PlusValueTransfer(ushort block, int delta, bool credit, bool encrypted) =>
        Check(NxpscNative.nxpsc_plus_value_transfer(Handle, block, delta, credit, encrypted));

    public void PlusRestore(ushort block) => Check(NxpscNative.nxpsc_plus_restore(Handle, block));

    /// <summary>Ends the session on the card as well as in the library.</summary>
    public void PlusResetAuth() => Check(NxpscNative.nxpsc_plus_reset_auth(Handle));

    /// <summary>Security level 1 configuration; payload per the card manual.</summary>
    public void PlusSetConfigSl1(ReadOnlySpan<byte> payload)
    {
        fixed (byte* d = payload)
            Check(NxpscNative.nxpsc_plus_set_config_sl1(Handle, d, (nuint)payload.Length));
    }

    /// <summary>UID personalisation (7-byte, random, ...); <paramref name="uidType"/> per the manual. <b>One-way.</b></summary>
    public void PlusPersonalizeUid(byte uidType) => Check(NxpscNative.nxpsc_plus_personalize_uid(Handle, uidType));

    /// <summary>Virtual card support: whether the card answered the last ISO level 3.</summary>
    public byte[] PlusVcSupportLastIsoL3() =>
        ReadBuffer(64, (p, cap, len) => NxpscNative.nxpsc_plus_vc_support_last_iso_l3(Handle, p, cap, len));
}
