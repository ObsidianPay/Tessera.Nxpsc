using System.Runtime.InteropServices;

namespace Tessera.Nxpsc.Native;

// Blittable mirrors of libnxpsc's public structs. Field order, types and
// therefore offsets follow nxpsc.h exactly; C `bool` is one byte and every
// enum is an int. The test suite checks every size and offset here against
// native/layout_probe.c, compiled by the same toolchain as the library.

/// <summary>nxpsc_key_t (40 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeKey
{
    public int Type;
    public fixed byte Data[32];
    public byte Version;
}

/// <summary>nxpsc_transport_t (4 pointers).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeTransport
{
    public nint Ctx;
    public delegate* unmanaged[Cdecl]<nint, byte*, nuint, byte*, nuint, nuint*, int> Transceive;
    public delegate* unmanaged[Cdecl]<nint, byte*, nuint, nuint*, int> GetUid;
    public delegate* unmanaged[Cdecl]<nint, int> Reselect;
}

/// <summary>nxpsc_version_t (29 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeVersion
{
    public byte HwVendor, HwType, HwSubtype, HwMajor, HwMinor, HwStorage, HwProtocol;
    public byte SwVendor, SwType, SwSubtype, SwMajor, SwMinor, SwStorage, SwProtocol;
    public fixed byte Uid[7];
    public fixed byte Batch[5];
    public byte Week;
    public byte Year;
    public byte HasBatchExtra;
}

/// <summary>nxpsc_access_t (4 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeAccess
{
    public byte Read;
    public byte Write;
    public byte ReadWrite;
    public byte Change;
}

/// <summary>nxpsc_file_settings_t (56 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeFileSettings
{
    public int Type;
    public byte Options;
    public int Comm;
    public NativeAccess Access;
    public uint Size;
    public int LowerLimit;
    public int UpperLimit;
    public int Value;
    public byte LimitedCredit;
    public uint RecordSize;
    public uint MaxRecords;
    public uint CurRecords;
    public byte SdmEnabled;
    public uint SdmOptions;
}

/// <summary>nxpsc_app_t (36 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeApp
{
    public uint Aid;
    public ushort IsoFid;
    public fixed byte DfName[17];
    public byte DfNameLen;
    public byte KeySettings;
    public byte NumKeys;
    public int KeyType;
    public byte IsoFidEnabled;
}

/// <summary>nxpsc_app_config_t (40 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeAppConfig
{
    public byte KeySettings;
    public byte NumKeys;
    public int KeyType;
    public byte IsoFidEnabled;
    public ushort IsoFid;
    public byte* DfName;
    public nuint DfNameLen;
    public byte NumKeySets;
    public byte KeySetVersion;
    public byte MaxKeySize;
    public byte KeySetSettings;
    public byte SpecificVcKeys;
    public byte SpecificCapabilityData;
}

/// <summary>nxpsc_delegate_info_t (12 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeDelegateInfo
{
    public byte DamSlotVersion;
    public ushort QuotaLimit;
    public ushort FreeBlocks;
    public uint Aid;
}

/// <summary>nxpsc_picc_config_t (4 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativePiccConfig
{
    public byte DisableFormat;
    public byte RandomUid;
    public byte PcMandatory;
    public byte AuthVcMandatory;
}

/// <summary>nxpsc_sdm_settings_t (40 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeSdmSettings
{
    public byte Enabled;
    public byte UidMirror;
    public byte CounterMirror;
    public byte ReadCounterLimit;
    public byte EncFileData;
    public byte MetaReadKey;
    public byte FileReadKey;
    public byte CounterRetKey;
    public uint UidOffset;
    public uint CounterOffset;
    public uint PiccDataOffset;
    public uint MacInputOffset;
    public uint EncOffset;
    public uint EncLength;
    public uint MacOffset;
    public uint ReadCounterLimitValue;
}
