using System.Runtime.InteropServices;

namespace Tessera.Nxpsc.Native;

// ---------------------------------------------------------------------------
// Every public function of libnxpsc's nxpsc.h, in header order. Nothing else in
// this library declares a libnxpsc entry point. Types follow the header
// exactly: enums are int, size_t is nuint, C bool is one byte, and every struct
// is one of the blittable mirrors in NativeStructs.cs.
// ---------------------------------------------------------------------------

internal static class NxpscError
{
    public const int Ok = 0;
    public const int Param = -1;
    public const int Transport = -2;
    public const int Card = -3;
    public const int Crypto = -4;
    public const int Auth = -5;
    public const int Length = -6;
    public const int Unsupported = -7;
    public const int Memory = -8;
}

internal static unsafe class NxpscNative
{
    public const string Library = "nxpsc";

    private const CallingConvention Cdecl = CallingConvention.Cdecl;

    // ---- life cycle ------------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_open(NativeTransport* transport, nint* card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_close(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_reset_channel(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_version_string();

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_strerror(int rc);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern byte nxpsc_last_status(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_status_str(byte status);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_cardtype_str(int type);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_keytype_str(int type);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern nuint nxpsc_key_size(int type);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_set_cmdset(nint card, int cmdset);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_cmdset(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_set_commmode(nint card, int mode);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool nxpsc_is_authenticated(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_active_channel(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool nxpsc_session_lost(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern uint nxpsc_selected_aid(nint card);

    // ---- identification ----------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_version(nint card, NativeVersion* version);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_card_uid(nint card, byte* uid, nuint cap, nuint* len);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_free_memory(nint card, uint* bytes);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_signature(nint card, byte* sig, nuint cap, nuint* len);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_identify(nint card, int* type);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_card_type(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_card_type_from_version(byte type, byte major, byte minor);

    // ---- authentication and keys ----------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_select_application(nint card, uint aid);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_authenticate(nint card, byte keyNo, NativeKey* key, int channel);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_authenticate_nonfirst(nint card, byte keyNo, NativeKey* key);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_change_key(nint card, byte keyNo, NativeKey* oldKey, NativeKey* newKey);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_change_key_ev2(nint card, byte keySet, byte keyNo, NativeKey* oldKey, NativeKey* newKey);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_key_version(nint card, byte keyNo, byte* version);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_key_settings(nint card, byte* keySettings, byte* numKeys, int* keyType);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_change_key_settings(nint card, byte keySettings);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_diversify_an10922(NativeKey* master, byte* divInput, nuint divInputLen, NativeKey* output);

    // ---- applications -------------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_application(nint card, uint aid, byte keySettings, byte numKeys, int keyType);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_application_iso(nint card, uint aid, byte keySettings, byte numKeys, int keyType,
        ushort isoFid, byte* dfName, nuint dfNameLen);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_application_ex(nint card, uint aid, NativeAppConfig* config);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_delete_application(nint card, uint aid);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_application_ids(nint card, uint* aids, nuint cap, nuint* count);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_df_names(nint card, NativeApp* apps, nuint cap, nuint* count);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_format_picc(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_set_configuration(nint card, byte option, byte* data, nuint len);

    // ---- files ------------------------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern ushort nxpsc_pack_access(NativeAccess* access);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_unpack_access(ushort raw, NativeAccess* access);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_file_ids(nint card, byte* ids, nuint cap, nuint* count);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_iso_file_ids(nint card, ushort* ids, nuint cap, nuint* count);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_file_settings(nint card, byte fileNo, NativeFileSettings* settings);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_change_file_settings(nint card, byte fileNo, int comm, NativeAccess* access);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_change_file_settings_raw(nint card, byte fileNo, byte* data, nuint len);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_std_file(nint card, byte fileNo, ushort isoFid, int comm, NativeAccess* access, uint size);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_backup_file(nint card, byte fileNo, ushort isoFid, int comm, NativeAccess* access, uint size);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_value_file(nint card, byte fileNo, int comm, NativeAccess* access,
        int lower, int upper, int value, [MarshalAs(UnmanagedType.U1)] bool limitedCredit);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_record_file(nint card, [MarshalAs(UnmanagedType.U1)] bool cyclic, byte fileNo,
        ushort isoFid, int comm, NativeAccess* access, uint recordSize, uint maxRecords);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_delete_file(nint card, byte fileNo);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_read_data(nint card, byte fileNo, uint offset, uint length, int comm,
        byte* output, nuint cap, nuint* outLen);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_write_data(nint card, byte fileNo, uint offset, byte* data, nuint len, int comm);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_value(nint card, byte fileNo, int comm, int* value);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_credit(nint card, byte fileNo, int delta, int comm);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_limited_credit(nint card, byte fileNo, int delta, int comm);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_debit(nint card, byte fileNo, int delta, int comm);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_write_record(nint card, byte fileNo, uint offset, byte* data, nuint len, int comm);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_update_record(nint card, byte fileNo, uint recordNo, uint offset, byte* data, nuint len, int comm);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_read_records(nint card, byte fileNo, uint recordNo, uint recordCount, int comm,
        byte* output, nuint cap, nuint* outLen);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_clear_record_file(nint card, byte fileNo);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_commit_transaction(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_commit_transaction_tmac(nint card, byte* tmc, byte* tmv);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_abort_transaction(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_commit_reader_id(nint card, byte* readerId, nuint len, byte* encPrevReaderId, nuint cap, nuint* outLen);

    // ---- EV2 and later ------------------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_set_iso_chaining(nint card, [MarshalAs(UnmanagedType.U1)] bool enable);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool nxpsc_get_iso_chaining(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_transaction_mac_file(nint card, byte fileNo, int comm, NativeAccess* access,
        NativeKey* tmKey, byte keyVersion);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_tmac_compute(NativeKey* tmKey, byte* uid, nuint uidLen, byte* tmc,
        byte* tmi, nuint tmiLen, byte* tmv);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_tmac_tmi_write_record(byte fileNo, uint offset, byte* data, nuint dataLen,
        byte* tmi, nuint cap, nuint* tmiLen);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_delegated_application(nint card, uint aid, ushort damSlot, byte damSlotVersion,
        ushort quotaLimit, byte keySettings, byte numKeys, int keyType, ushort isoFid, byte* dfName, nuint dfNameLen,
        byte* enck, nuint enckLen, byte* damMac, nuint damMacLen);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_delegated_info(nint card, ushort damSlot, NativeDelegateInfo* info);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_mfc_mapping(nint card, byte* data, nuint len);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_restrict_mfc_update(nint card, byte* data, nuint len);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_notify_transaction_success(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_init_key_set(nint card, byte keySet, int keyType);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_finalize_key_set(nint card, byte keySet, byte keySetVersion);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_roll_key_set(nint card, byte keySet);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_proximity_check(nint card, NativeKey* pcKey, byte rounds, byte* macOk);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_set_picc_config_ex(nint card, NativePiccConfig* config);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_set_picc_config(nint card, [MarshalAs(UnmanagedType.U1)] bool disableFormat,
        [MarshalAs(UnmanagedType.U1)] bool randomUid);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_set_default_key(nint card, NativeKey* key);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_set_ats(nint card, byte* ats, nuint len);

    // ---- ISO 7816-4 ---------------------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_iso_select_df_name(nint card, byte* dfName, nuint len);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_iso_select_fid(nint card, ushort fid, [MarshalAs(UnmanagedType.U1)] bool isEf);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_iso_read_binary(nint card, byte sfi, ushort offset, nuint length,
        byte* output, nuint cap, nuint* outLen);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_iso_update_binary(nint card, byte sfi, ushort offset, byte* data, nuint len);

    // ---- NTAG 413 / 424 DNA ---------------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_ntag424_select(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_sdm_configure(nint card, byte fileNo, int comm, NativeAccess* access, NativeSdmSettings* sdm);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_sdm_build_settings(int comm, NativeAccess* access, NativeSdmSettings* sdm,
        byte* output, nuint cap, nuint* outLen);

    // ---- MIFARE Plus EV1 / EV2, SL3 ---------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_authenticate(nint card, ushort keyBlock, NativeKey* key,
        [MarshalAs(UnmanagedType.U1)] bool first);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_read(nint card, ushort block, byte count, [MarshalAs(UnmanagedType.U1)] bool encrypted,
        [MarshalAs(UnmanagedType.U1)] bool maced, byte* output, nuint cap, nuint* outLen);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_write(nint card, ushort block, byte* data, nuint len, [MarshalAs(UnmanagedType.U1)] bool encrypted);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_write_perso(nint card, ushort block, byte* data, nuint len);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_commit_perso(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_value_op(nint card, ushort block, int delta, [MarshalAs(UnmanagedType.U1)] bool credit,
        [MarshalAs(UnmanagedType.U1)] bool encrypted);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_transfer(nint card, ushort block);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_value_transfer(nint card, ushort block, int delta, [MarshalAs(UnmanagedType.U1)] bool credit,
        [MarshalAs(UnmanagedType.U1)] bool encrypted);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_restore(nint card, ushort block);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_reset_auth(nint card);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_set_config_sl1(nint card, byte* data, nuint len);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_personalize_uid(nint card, byte uidType);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_plus_vc_support_last_iso_l3(nint card, byte* output, nuint cap, nuint* outLen);

    // ---- escape hatch and self test --------------------------------------------------------

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_command(nint card, byte cmd, byte* data, nuint len, int txMode, int rxMode,
        byte* resp, nuint cap, nuint* respLen);

    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_selftest([MarshalAs(UnmanagedType.U1)] bool verbose);

    // ---- not public API ----------------------------------------------------------------------

    // Declared in libnxpsc's src/nxpsc_crypto.h, not nxpsc.h, and exported only
    // because the shared library exports every symbol. libnxpsc's protocol tests
    // use it to give the mock card the fixed RndA it expects. Only
    // NxpscCard.EnableMockRng calls it (for Tessera.Nxpsc.MockCard), and after
    // that NxpscCard refuses to open anything but the mock.
    [DllImport(Library, CallingConvention = Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_set_rng(delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> rng, nint ctx);
}
