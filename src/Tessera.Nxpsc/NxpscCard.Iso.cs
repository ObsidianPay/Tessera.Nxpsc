using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

// ISO 7816-4 level access (DESFire ISO mode, NTAG 4xx DNA) and NTAG 413 / 424
// DNA secure dynamic messaging.
public sealed unsafe partial class NxpscCard
{
    public void IsoSelectDfName(ReadOnlySpan<byte> dfName)
    {
        fixed (byte* d = dfName)
            Check(NxpscNative.nxpsc_iso_select_df_name(Handle, d, (nuint)dfName.Length));
    }

    public void IsoSelectFid(ushort fid, bool isElementaryFile) =>
        Check(NxpscNative.nxpsc_iso_select_fid(Handle, fid, isElementaryFile));

    /// <summary>READ BINARY. <paramref name="sfi"/> 0 reads the currently selected EF.</summary>
    public byte[] IsoReadBinary(byte sfi, ushort offset, int length, int capacity = NxpscLimits.MaxResponse) =>
        ReadBuffer(capacity, (p, cap, len) =>
            NxpscNative.nxpsc_iso_read_binary(Handle, sfi, offset, (nuint)length, p, cap, len));

    public void IsoUpdateBinary(byte sfi, ushort offset, ReadOnlySpan<byte> data)
    {
        fixed (byte* d = data)
            Check(NxpscNative.nxpsc_iso_update_binary(Handle, sfi, offset, d, (nuint)data.Length));
    }

    /// <summary>Selects the NTAG 424 DNA application (ISO DF name D2760000850101).</summary>
    public void Ntag424Select() => Check(NxpscNative.nxpsc_ntag424_select(Handle));

    /// <summary>Configures secure dynamic messaging on a file (ChangeFileSettings with SDM).</summary>
    public void ConfigureSdm(byte fileNo, NxpscCommMode comm, NxpscAccessRights access, NxpscSdmSettings sdm)
    {
        ArgumentNullException.ThrowIfNull(sdm);
        var a = Interop.ToNative(access);
        var s = Interop.ToNative(sdm);
        Check(NxpscNative.nxpsc_sdm_configure(Handle, fileNo, (int)comm, &a, &s));
    }
}
