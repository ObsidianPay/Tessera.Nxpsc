using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Tessera.Nxpsc.Native;

/// <summary>Return-code checking and conversions between the native mirrors and the public types.</summary>
internal static unsafe class Interop
{
    /// <summary>
    /// Throws <see cref="NxpscException"/> for a negative code. <paramref name="card"/>
    /// may be 0 for calls that involve no card; otherwise the exception carries
    /// nxpsc_last_status() and nxpsc_session_lost().
    /// </summary>
    public static void Check(int rc, nint card, string operation)
    {
        if (rc >= NxpscError.Ok)
            return;
        throw Failure(rc, card, operation);
    }

    public static NxpscException Failure(int rc, nint card, string operation)
    {
        var code = Enum.IsDefined(typeof(NxpscErrorCode), rc) ? (NxpscErrorCode)rc : NxpscErrorCode.Param;

        byte? status = null;
        string? statusText = null;
        var sessionLost = false;
        if (card != 0)
        {
            if (rc == NxpscError.Card)
            {
                status = NxpscNative.nxpsc_last_status(card);
                statusText = Marshal.PtrToStringAnsi(NxpscNative.nxpsc_status_str(status.Value));
            }
            sessionLost = NxpscNative.nxpsc_session_lost(card);
        }
        return new NxpscException(operation, code, NxpscLibrary.ErrorText(rc), status, statusText, sessionLost);
    }

    // ---- keys --------------------------------------------------------------------

    public static void Load(NxpscKey key, ref NativeKey native)
    {
        native.Type = (int)key.Type;
        native.Version = key.Version;
        fixed (byte* d = native.Data)
            key.Bytes.CopyTo(new Span<byte>(d, NxpscLimits.MaxKeySize));
    }

    public static void Wipe(ref NativeKey native)
    {
        fixed (NativeKey* p = &native)
            CryptographicOperations.ZeroMemory(new Span<byte>(p, sizeof(NativeKey)));
    }

    // ---- structs -------------------------------------------------------------------

    public static NativeAccess ToNative(NxpscAccessRights a) => new()
    {
        Read = a.Read,
        Write = a.Write,
        ReadWrite = a.ReadWrite,
        Change = a.Change,
    };

    public static NxpscAccessRights FromNative(NativeAccess a) => new(a.Read, a.Write, a.ReadWrite, a.Change);

    public static CardVersion FromNative(NativeVersion v) => new(
        v.HwVendor, v.HwType, v.HwSubtype, v.HwMajor, v.HwMinor, v.HwStorage, v.HwProtocol,
        v.SwVendor, v.SwType, v.SwSubtype, v.SwMajor, v.SwMinor, v.SwStorage, v.SwProtocol,
        new ReadOnlySpan<byte>(v.Uid, 7).ToArray(),
        new ReadOnlySpan<byte>(v.Batch, 5).ToArray(),
        v.Week, v.Year, v.HasBatchExtra != 0);

    public static NxpscFileSettings FromNative(in NativeFileSettings f) => new(
        (NxpscFileType)f.Type, f.Options, (NxpscCommMode)f.Comm, FromNative(f.Access),
        f.Size, f.LowerLimit, f.UpperLimit, f.Value, f.LimitedCredit != 0,
        f.RecordSize, f.MaxRecords, f.CurRecords, f.SdmEnabled != 0, f.SdmOptions);

    public static NxpscApplication FromNative(NativeApp a) => new(
        a.Aid, a.IsoFid, new ReadOnlySpan<byte>(a.DfName, Math.Min((int)a.DfNameLen, 16)).ToArray(),
        a.KeySettings, a.NumKeys, (NxpscKeyType)a.KeyType, a.IsoFidEnabled != 0);

    public static NxpscDelegateInfo FromNative(in NativeDelegateInfo d) =>
        new(d.DamSlotVersion, d.QuotaLimit, d.FreeBlocks, d.Aid);

    public static NativePiccConfig ToNative(NxpscPiccConfig c) => new()
    {
        DisableFormat = B(c.DisableFormat),
        RandomUid = B(c.RandomUid),
        PcMandatory = B(c.PcMandatory),
        AuthVcMandatory = B(c.AuthVcMandatory),
    };

    public static NativeSdmSettings ToNative(NxpscSdmSettings s) => new()
    {
        Enabled = B(s.Enabled),
        UidMirror = B(s.UidMirror),
        CounterMirror = B(s.CounterMirror),
        ReadCounterLimit = B(s.ReadCounterLimit),
        EncFileData = B(s.EncFileData),
        MetaReadKey = s.MetaReadKey,
        FileReadKey = s.FileReadKey,
        CounterRetKey = s.CounterRetKey,
        UidOffset = s.UidOffset,
        CounterOffset = s.CounterOffset,
        PiccDataOffset = s.PiccDataOffset,
        MacInputOffset = s.MacInputOffset,
        EncOffset = s.EncOffset,
        EncLength = s.EncLength,
        MacOffset = s.MacOffset,
        ReadCounterLimitValue = s.ReadCounterLimitValue,
    };

    /// <summary>The app config minus the DF name pointer, which the caller pins and sets.</summary>
    public static NativeAppConfig ToNative(NxpscApplicationConfig c) => new()
    {
        KeySettings = c.KeySettings,
        NumKeys = c.NumKeys,
        KeyType = (int)c.KeyType,
        IsoFidEnabled = B(c.IsoFidEnabled),
        IsoFid = c.IsoFid,
        NumKeySets = c.NumKeySets,
        KeySetVersion = c.KeySetVersion,
        MaxKeySize = c.MaxKeySize,
        KeySetSettings = c.KeySetSettings,
        SpecificVcKeys = B(c.SpecificVcKeys),
        SpecificCapabilityData = B(c.SpecificCapabilityData),
    };

    private static byte B(bool value) => value ? (byte)1 : (byte)0;
}
