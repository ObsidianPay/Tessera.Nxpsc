using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

// Applications and PICC level management.
public sealed unsafe partial class NxpscCard
{
    public void CreateApplication(uint aid, byte keySettings, byte numKeys, NxpscKeyType keyType) =>
        Check(NxpscNative.nxpsc_create_application(Handle, aid, keySettings, numKeys, (int)keyType));

    /// <summary>CreateApplication with an ISO file id and a DF name (up to 16 bytes).</summary>
    public void CreateApplicationIso(uint aid, byte keySettings, byte numKeys, NxpscKeyType keyType,
        ushort isoFid, ReadOnlySpan<byte> dfName)
    {
        fixed (byte* name = dfName)
            Check(NxpscNative.nxpsc_create_application_iso(Handle, aid, keySettings, numKeys, (int)keyType,
                isoFid, name, (nuint)dfName.Length));
    }

    /// <summary>The full CreateApplication payload, key sets and all.</summary>
    public void CreateApplication(uint aid, NxpscApplicationConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var native = Interop.ToNative(config);
        fixed (byte* name = config.DfName)
        {
            native.DfName = name;
            native.DfNameLen = (nuint)(config.DfName?.Length ?? 0);
            Check(NxpscNative.nxpsc_create_application_ex(Handle, aid, &native));
        }
    }

    public void DeleteApplication(uint aid) => Check(NxpscNative.nxpsc_delete_application(Handle, aid));

    public uint[] GetApplicationIds()
    {
        var aids = new uint[NxpscLimits.MaxApplications];
        nuint count = 0;
        fixed (uint* p = aids)
            Check(NxpscNative.nxpsc_get_application_ids(Handle, p, (nuint)aids.Length, &count));
        return aids[..(int)count];
    }

    public NxpscApplication[] GetDfNames()
    {
        var apps = new NativeApp[NxpscLimits.MaxApplications];
        nuint count = 0;
        fixed (NativeApp* p = apps)
            Check(NxpscNative.nxpsc_get_df_names(Handle, p, (nuint)apps.Length, &count));
        return apps[..(int)count].Select(Interop.FromNative).ToArray();
    }

    /// <summary>
    /// FormatPICC: deletes every application and file and reclaims the memory.
    /// The PICC master key is kept. Needs the PICC master key session.
    /// </summary>
    public void FormatPicc() => Check(NxpscNative.nxpsc_format_picc(Handle));

    /// <summary>
    /// SetConfiguration with a raw option and payload. The typed wrappers
    /// (<see cref="SetPiccConfig(NxpscPiccConfig)"/>, <see cref="SetDefaultKey"/>, <see cref="SetAts"/>)
    /// cover the documented options. Some options are one-way.
    /// </summary>
    public void SetConfiguration(byte option, ReadOnlySpan<byte> data)
    {
        fixed (byte* d = data)
            Check(NxpscNative.nxpsc_set_configuration(Handle, option, d, (nuint)data.Length));
    }

    /// <summary>
    /// SetConfiguration option 0x00. All four flags are written at once, so pass
    /// back what the card already has for the ones you do not mean to change.
    /// <b>Disabling format and enabling random UID are one-way on most cards.</b>
    /// </summary>
    public void SetPiccConfig(NxpscPiccConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var native = Interop.ToNative(config);
        Check(NxpscNative.nxpsc_set_picc_config_ex(Handle, &native));
    }

    /// <summary>
    /// The two-flag form of <see cref="SetPiccConfig(NxpscPiccConfig)"/>; it writes zero into the
    /// proximity check and virtual card flags. <b>One-way on most cards.</b>
    /// </summary>
    public void SetPiccConfig(bool disableFormat, bool randomUid) =>
        Check(NxpscNative.nxpsc_set_picc_config(Handle, disableFormat, randomUid));

    /// <summary>The key new applications' keys are initialised to.</summary>
    public void SetDefaultKey(NxpscKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        NativeKey k = default;
        try
        {
            Interop.Load(key, ref k);
            Check(NxpscNative.nxpsc_set_default_key(Handle, &k));
        }
        finally
        {
            Interop.Wipe(ref k);
        }
    }

    /// <summary>Replaces the card's ATS.</summary>
    public void SetAts(ReadOnlySpan<byte> ats)
    {
        fixed (byte* a = ats)
            Check(NxpscNative.nxpsc_set_ats(Handle, a, (nuint)ats.Length));
    }
}
