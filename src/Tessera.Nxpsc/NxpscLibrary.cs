using System.Runtime.InteropServices;
using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

/// <summary>
/// libnxpsc functions that need no card: version, self test, names of codes,
/// AN10922 diversification, access-right packing and SDM payload building.
/// Everything that talks to a card is on <see cref="NxpscCard"/>.
/// </summary>
public static unsafe class NxpscLibrary
{
    static NxpscLibrary() => NativeLibraryResolver.EnsureRegistered();

    /// <summary>"major.minor.patch" of the loaded libnxpsc.</summary>
    public static string LibraryVersion => Marshal.PtrToStringAnsi(NxpscNative.nxpsc_version_string()) ?? "unknown";

    /// <summary>
    /// libnxpsc's crypto known-answer tests, AN10922 vectors included. Anything
    /// but true means the crypto is wrong at run time.
    /// </summary>
    public static bool SelfTest(bool verbose = false) => NxpscNative.nxpsc_selftest(verbose) == NxpscError.Ok;

    public static string ErrorText(NxpscErrorCode code) => ErrorText((int)code);

    internal static string ErrorText(int rc) => Marshal.PtrToStringAnsi(NxpscNative.nxpsc_strerror(rc)) ?? rc.ToString();

    /// <summary>The name of a DESFire status byte.</summary>
    public static string StatusText(byte status) =>
        Marshal.PtrToStringAnsi(NxpscNative.nxpsc_status_str(status)) ?? $"0x{status:X2}";

    public static string CardTypeName(NxpscCardType type) =>
        Marshal.PtrToStringAnsi(NxpscNative.nxpsc_cardtype_str((int)type)) ?? type.ToString();

    public static string KeyTypeName(NxpscKeyType type) =>
        Marshal.PtrToStringAnsi(NxpscNative.nxpsc_keytype_str((int)type)) ?? type.ToString();

    /// <summary>Key length in bytes, as libnxpsc sees it.</summary>
    public static int KeySize(NxpscKeyType type) => (int)NxpscNative.nxpsc_key_size((int)type);

    /// <summary>libnxpsc's product table, applied to GetVersion's hardware type and version bytes.</summary>
    public static NxpscCardType CardTypeFromVersion(byte type, byte major, byte minor) =>
        (NxpscCardType)NxpscNative.nxpsc_card_type_from_version(type, major, minor);

    /// <summary>
    /// AN10922 diversification. <paramref name="diversificationInput"/> excludes
    /// the padding constant and is at most 31 bytes, typically UID || AID ||
    /// system identifier. The derived key keeps the master key's type and takes
    /// <paramref name="derivedVersion"/> as its version: a version belongs to the
    /// key as loaded, not to the derivation.
    /// </summary>
    public static NxpscKey DiversifyAn10922(NxpscKey master, ReadOnlySpan<byte> diversificationInput, byte derivedVersion = 0)
    {
        ArgumentNullException.ThrowIfNull(master);

        NativeKey m = default, derived = default;
        try
        {
            Interop.Load(master, ref m);
            int rc;
            fixed (byte* input = diversificationInput)
                rc = NxpscNative.nxpsc_diversify_an10922(&m, input, (nuint)diversificationInput.Length, &derived);
            Interop.Check(rc, 0, nameof(DiversifyAn10922));

            var type = (NxpscKeyType)derived.Type;
            return new NxpscKey(type, new ReadOnlySpan<byte>(derived.Data, NxpscKey.SizeOf(type)), derivedVersion);
        }
        finally
        {
            Interop.Wipe(ref m);
            Interop.Wipe(ref derived);
        }
    }

    public static ushort PackAccess(NxpscAccessRights access)
    {
        var native = Interop.ToNative(access);
        return NxpscNative.nxpsc_pack_access(&native);
    }

    public static NxpscAccessRights UnpackAccess(ushort raw)
    {
        NativeAccess native;
        NxpscNative.nxpsc_unpack_access(raw, &native);
        return Interop.FromNative(native);
    }

    /// <summary>
    /// The ChangeFileSettings payload that <see cref="NxpscCard.ConfigureSdm"/>
    /// would send, built without a card.
    /// </summary>
    public static byte[] BuildSdmSettings(NxpscCommMode comm, NxpscAccessRights access, NxpscSdmSettings sdm)
    {
        ArgumentNullException.ThrowIfNull(sdm);
        var a = Interop.ToNative(access);
        var s = Interop.ToNative(sdm);
        var buffer = new byte[64];
        nuint length = 0;
        int rc;
        fixed (byte* p = buffer)
            rc = NxpscNative.nxpsc_sdm_build_settings((int)comm, &a, &s, p, (nuint)buffer.Length, &length);
        Interop.Check(rc, 0, nameof(BuildSdmSettings));
        return buffer[..(int)length];
    }
}
