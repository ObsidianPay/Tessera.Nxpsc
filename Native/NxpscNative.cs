using System.Runtime.InteropServices;

namespace Tessera.Nxpsc.Native;

// ---------------------------------------------------------------------------
// The libnxpsc interop surface. Every [DllImport] of libnxpsc lives in this
// file and nowhere else; NxpscCard is the only caller. libnxpsc is GPLv3, so
// this file and NxpscCard are the boundary to move behind a process (or onto an
// NXP-licensed stack) before anything containing it is distributed.
//
// Only the calls the personaliser needs are declared. Deliberately absent:
// nxpsc_set_picc_config*, nxpsc_set_default_key, nxpsc_set_ats,
// nxpsc_change_key_settings and nxpsc_format_picc — none may be reachable from
// this tool (random UID and key-settings changes are one-way on this silicon).
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

internal enum NxpscCmdSet
{
    Native = 0,
    NativeIso = 1,
    Iso = 2,
}

/// <summary>Mirrors nxpsc_key_t: an int enum, 32 key bytes, a version byte (sizeof 40).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeKey
{
    public int Type;
    public fixed byte Data[32];
    public byte Version;
}

/// <summary>Mirrors nxpsc_version_t: 29 single-byte fields, no padding.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeVersion
{
    public byte HwVendor, HwType, HwSubtype, HwMajor, HwMinor, HwStorage, HwProtocol;
    public byte SwVendor, SwType, SwSubtype, SwMajor, SwMinor, SwStorage, SwProtocol;
    public fixed byte Uid[7];
    public fixed byte Batch[5];
    public byte Week;
    public byte Year;
    public byte HasBatchExtra;     // C bool
}

/// <summary>Mirrors nxpsc_transport_t. The library copies the struct; ctx must outlive the card.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeTransport
{
    public nint Ctx;
    public delegate* unmanaged[Cdecl]<nint, byte*, nuint, byte*, nuint, nuint*, int> Transceive;
    public nint GetUid;     // optional, left null: UIDs come from GetVersion and GetCardUID
    public nint Reselect;   // optional, left null
}

internal static unsafe class NxpscNative
{
    public const string Library = "nxpsc";

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_open(NativeTransport* transport, nint* card);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_close(nint card);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_reset_channel(nint card);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_version_string();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_strerror(int rc);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern byte nxpsc_last_status(nint card);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_status_str(byte status);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern nint nxpsc_cardtype_str(int type);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_set_cmdset(nint card, NxpscCmdSet cmdset);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool nxpsc_is_authenticated(nint card);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool nxpsc_session_lost(nint card);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_active_channel(nint card);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_version(nint card, NativeVersion* version);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_identify(nint card, int* type);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_card_uid(nint card, byte* uid, nuint cap, nuint* len);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_get_signature(nint card, byte* sig, nuint cap, nuint* len);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_select_application(nint card, uint aid);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_authenticate(nint card, byte keyNo, NativeKey* key, int channel);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_change_key(nint card, byte keyNo, NativeKey* oldKey, NativeKey* newKey);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_create_application(nint card, uint aid, byte keySettings, byte numKeys, int keyType);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_diversify_an10922(NativeKey* master, byte* divInput, nuint divInputLen, NativeKey* output);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int nxpsc_selftest([MarshalAs(UnmanagedType.U1)] bool verbose);

    // NOT public libnxpsc API: declared in src/nxpsc_crypto.h and exported only
    // because the shared build exports every symbol. libnxpsc's own protocol
    // tests use it to give the mock card the fixed RndA it expects. Tessera
    // calls it only when a MockCard is created, and from then on NxpscCard
    // refuses to open anything but the mock (see NxpscCard.EnableMockRng).
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void nxpsc_set_rng(delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> rng, nint ctx);
}
