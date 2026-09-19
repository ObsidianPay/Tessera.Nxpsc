using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

// DESFire EV2 and later: transaction MAC, delegated applications, MIFARE
// Classic mapping, key sets and the proximity check.
public sealed unsafe partial class NxpscCard
{
    public void CreateTransactionMacFile(byte fileNo, NxpscCommMode comm, NxpscAccessRights access,
        NxpscKey tmKey, byte keyVersion)
    {
        ArgumentNullException.ThrowIfNull(tmKey);
        var a = Interop.ToNative(access);
        NativeKey k = default;
        try
        {
            Interop.Load(tmKey, ref k);
            Check(NxpscNative.nxpsc_create_transaction_mac_file(Handle, fileNo, (int)comm, &a, &k, keyVersion));
        }
        finally
        {
            Interop.Wipe(ref k);
        }
    }

    /// <summary>
    /// CreateDelegatedApplication. <paramref name="encK"/> and <paramref name="damMac"/>
    /// are produced by the DAM authority; see the card manual.
    /// </summary>
    public void CreateDelegatedApplication(uint aid, ushort damSlot, byte damSlotVersion, ushort quotaLimit,
        byte keySettings, byte numKeys, NxpscKeyType keyType, ushort isoFid, ReadOnlySpan<byte> dfName,
        ReadOnlySpan<byte> encK, ReadOnlySpan<byte> damMac)
    {
        fixed (byte* name = dfName)
        fixed (byte* enck = encK)
        fixed (byte* mac = damMac)
        {
            Check(NxpscNative.nxpsc_create_delegated_application(Handle, aid, damSlot, damSlotVersion, quotaLimit,
                keySettings, numKeys, (int)keyType, isoFid, name, (nuint)dfName.Length,
                enck, (nuint)encK.Length, mac, (nuint)damMac.Length));
        }
    }

    public NxpscDelegateInfo GetDelegatedInfo(ushort damSlot)
    {
        NativeDelegateInfo info = default;
        Check(NxpscNative.nxpsc_get_delegated_info(Handle, damSlot, &info));
        return Interop.FromNative(info);
    }

    /// <summary>MIFARE Classic mapping of EV2 XL and EV3; payload per the card manual.</summary>
    public void CreateMfcMapping(ReadOnlySpan<byte> payload)
    {
        fixed (byte* d = payload)
            Check(NxpscNative.nxpsc_create_mfc_mapping(Handle, d, (nuint)payload.Length));
    }

    /// <summary>RestrictMFCUpdate; payload per the card manual. Restrictions cannot be lifted.</summary>
    public void RestrictMfcUpdate(ReadOnlySpan<byte> payload)
    {
        fixed (byte* d = payload)
            Check(NxpscNative.nxpsc_restrict_mfc_update(Handle, d, (nuint)payload.Length));
    }

    /// <summary>Tells the card a transaction completed (ECP capable readers).</summary>
    public void NotifyTransactionSuccess() => Check(NxpscNative.nxpsc_notify_transaction_success(Handle));

    /// <summary>
    /// InitializeKeySet. <paramref name="keyType"/> is the new set's type and must
    /// match the application's own key type. Needs an application created with
    /// two or more key sets.
    /// </summary>
    public void InitKeySet(byte keySet, NxpscKeyType keyType) =>
        Check(NxpscNative.nxpsc_init_key_set(Handle, keySet, (int)keyType));

    public void FinalizeKeySet(byte keySet, byte keySetVersion) =>
        Check(NxpscNative.nxpsc_finalize_key_set(Handle, keySet, keySetVersion));

    /// <summary>RollKeySet: makes the set active and ends the session.</summary>
    public void RollKeySet(byte keySet) => Check(NxpscNative.nxpsc_roll_key_set(Handle, keySet));

    /// <summary>
    /// Proximity check, the relay attack countermeasure. <paramref name="rounds"/>
    /// is 1 to 8. Throws when the card's answer MAC does not verify.
    /// </summary>
    public void ProximityCheck(NxpscKey pcKey, byte rounds)
    {
        ArgumentNullException.ThrowIfNull(pcKey);
        NativeKey k = default;
        byte macOk = 0;
        try
        {
            Interop.Load(pcKey, ref k);
            Check(NxpscNative.nxpsc_proximity_check(Handle, &k, rounds, &macOk));
        }
        finally
        {
            Interop.Wipe(ref k);
        }
    }
}
