namespace Tessera.Nxpsc;

/// <summary>Card families, values as libnxpsc's nxpsc_cardtype_t.</summary>
public enum NxpscCardType
{
    Unknown = 0,
    DesfireMf3icd40,
    DesfireEv1,
    DesfireEv2,
    DesfireEv2Xl,
    DesfireEv3,
    DesfireLight,
    PlusEv1,
    PlusEv2,
    Ntag413Dna,
    Ntag424,
    Duox,
}

/// <summary>Key types, values as nxpsc_keytype_t.</summary>
public enum NxpscKeyType
{
    Des = 0,
    TwoKey3Des = 1,
    ThreeKey3Des = 2,
    Aes128 = 3,
    /// <summary>DESFire Light / EV2 originality only.</summary>
    Aes256 = 4,
}

/// <summary>Secure channel / authentication variant, values as nxpsc_channel_t.</summary>
public enum NxpscChannel
{
    /// <summary>Pick from the card type and key type.</summary>
    Auto = 0,
    /// <summary>Legacy native authenticate (0x0A / 0x1A).</summary>
    D40,
    /// <summary>AuthenticateISO / AuthenticateAES (0x1A / 0xAA).</summary>
    Ev1,
    /// <summary>AuthenticateEV2First / NonFirst (0x71 / 0x77).</summary>
    Ev2,
    /// <summary>Leakage resilient primitive (DESFire Light, EV2 and later).</summary>
    Lrp,
}

/// <summary>Per command communication mode, values as nxpsc_commmode_t.</summary>
public enum NxpscCommMode
{
    Plain = 0,
    Mac,
    /// <summary>Fully enciphered.</summary>
    Full,
}

/// <summary>Command set on the wire, values as nxpsc_cmdset_t.</summary>
public enum NxpscCmdSet
{
    /// <summary>Raw native frames.</summary>
    Native = 0,
    /// <summary>Native commands wrapped in ISO 7816-4 APDUs (CLA 0x90). What PC/SC needs.</summary>
    NativeIso,
    /// <summary>Real ISO 7816-4 commands.</summary>
    Iso,
}

/// <summary>File types, values as nxpsc_filetype_t.</summary>
public enum NxpscFileType
{
    Standard = 0x00,
    Backup = 0x01,
    Value = 0x02,
    LinearRecord = 0x03,
    CyclicRecord = 0x04,
    TransactionMac = 0x05,
}

/// <summary>Failure classes, values as nxpsc_error_t.</summary>
public enum NxpscErrorCode
{
    /// <summary>Bad argument from the caller.</summary>
    Param = -1,
    /// <summary>Reader or transport failed.</summary>
    Transport = -2,
    /// <summary>The card answered with an error status; see <see cref="NxpscException.CardStatus"/>.</summary>
    Card = -3,
    /// <summary>A local crypto operation failed.</summary>
    Crypto = -4,
    /// <summary>Authentication failed, or the command needs one.</summary>
    Auth = -5,
    /// <summary>Response length not as expected, or a buffer too small.</summary>
    Length = -6,
    /// <summary>Not supported by this card, or not implemented.</summary>
    Unsupported = -7,
    Memory = -8,
}

/// <summary>Limits of the library, as the NXPSC_MAX_* constants.</summary>
public static class NxpscLimits
{
    public const int MaxKeySize = 32;
    public const int MaxApdu = 264;
    /// <summary>Biggest reassembled response; reads above this are chunked by the caller.</summary>
    public const int MaxResponse = 4096;
    public const int MaxFiles = 32;
    public const int MaxApplications = 64;
    public const int MaxKeys = 16;
}

/// <summary>DESFire status bytes worth branching on. <see cref="NxpscLibrary.StatusText"/> names any of them.</summary>
public static class DesfireStatus
{
    public const byte OperationOk = 0x00;
    public const byte NoChanges = 0x0C;
    public const byte OutOfEepromError = 0x0E;
    public const byte IllegalCommandCode = 0x1C;
    public const byte IntegrityError = 0x1E;
    public const byte NoSuchKey = 0x40;
    public const byte LengthError = 0x7E;
    public const byte PermissionDenied = 0x9D;
    public const byte ParameterError = 0x9E;
    public const byte ApplicationNotFound = 0xA0;
    public const byte AuthenticationError = 0xAE;
    public const byte AdditionalFrame = 0xAF;
    public const byte BoundaryError = 0xBE;
    public const byte CommandAborted = 0xCA;
    public const byte DuplicateError = 0xDE;
    public const byte FileNotFound = 0xF0;
}

/// <summary>What GetVersion reported (nxpsc_version_t).</summary>
public sealed record CardVersion(
    byte HwVendor,
    byte HwType,
    byte HwSubtype,
    byte HwMajor,
    byte HwMinor,
    byte HwStorage,
    byte HwProtocol,
    byte SwVendor,
    byte SwType,
    byte SwSubtype,
    byte SwMajor,
    byte SwMinor,
    byte SwStorage,
    byte SwProtocol,
    byte[] Uid,
    byte[] Batch,
    byte ProductionWeek,
    byte ProductionYear,
    bool HasBatchExtra);

/// <summary>
/// File access rights (nxpsc_access_t): a key number per right, 0x0E for free
/// access, 0x0F for denied.
/// </summary>
public readonly record struct NxpscAccessRights(byte Read, byte Write, byte ReadWrite, byte Change)
{
    public const byte Free = 0x0E;
    public const byte Denied = 0x0F;

    /// <summary>The 16-bit form the card uses: read &lt;&lt; 12 | write &lt;&lt; 8 | read_write &lt;&lt; 4 | change.</summary>
    public ushort Pack() => NxpscLibrary.PackAccess(this);

    public static NxpscAccessRights Unpack(ushort raw) => NxpscLibrary.UnpackAccess(raw);
}

/// <summary>Key settings of the selected application or PICC.</summary>
public sealed record NxpscKeySettings(byte Settings, byte NumKeys, NxpscKeyType KeyType);

/// <summary>A file's settings (nxpsc_file_settings_t). Fields that do not apply to the file type are zero.</summary>
public sealed record NxpscFileSettings(
    NxpscFileType Type,
    byte Options,
    NxpscCommMode CommMode,
    NxpscAccessRights Access,
    uint Size,
    int LowerLimit,
    int UpperLimit,
    int Value,
    bool LimitedCredit,
    uint RecordSize,
    uint MaxRecords,
    uint CurrentRecords,
    bool SdmEnabled,
    uint SdmOptions);

/// <summary>An application as GetDFNames reports it (nxpsc_app_t).</summary>
public sealed record NxpscApplication(
    uint Aid,
    ushort IsoFid,
    byte[] DfName,
    byte KeySettings,
    byte NumKeys,
    NxpscKeyType KeyType,
    bool IsoFidEnabled);

/// <summary>
/// The full CreateApplication payload (nxpsc_app_config_t). Key sets (EV2 and
/// later) are only available when <see cref="NumKeySets"/> is 2 or more.
/// </summary>
public sealed record NxpscApplicationConfig
{
    /// <summary>KeySettings1.</summary>
    public byte KeySettings { get; init; }

    /// <summary>1 to 14.</summary>
    public byte NumKeys { get; init; }

    public NxpscKeyType KeyType { get; init; }

    public bool IsoFidEnabled { get; init; }
    public ushort IsoFid { get; init; }

    /// <summary>Up to 16 bytes, or null.</summary>
    public byte[]? DfName { get; init; }

    /// <summary>2 to 16, or 0 for an application without key sets.</summary>
    public byte NumKeySets { get; init; }

    /// <summary>AKSVersion, the active set's version.</summary>
    public byte KeySetVersion { get; init; }

    /// <summary>16 or 24.</summary>
    public byte MaxKeySize { get; init; }

    /// <summary>AppKeySetSett: the key allowed to roll key sets, 0 to 7.</summary>
    public byte KeySetSettings { get; init; }

    /// <summary>The application carries its own virtual card keys (the proximity check MACs with key 0x21).</summary>
    public bool SpecificVcKeys { get; init; }

    public bool SpecificCapabilityData { get; init; }
}

/// <summary>Delegated application slot information (nxpsc_delegate_info_t).</summary>
public sealed record NxpscDelegateInfo(byte DamSlotVersion, ushort QuotaLimit, ushort FreeBlocks, uint Aid);

/// <summary>
/// SetConfiguration option 0x00 flags (nxpsc_picc_config_t). All four are
/// written at once. Disabling format and enabling random UID are one-way on
/// most cards.
/// </summary>
public sealed record NxpscPiccConfig(bool DisableFormat, bool RandomUid, bool PcMandatory, bool AuthVcMandatory);

/// <summary>NTAG 4xx DNA secure dynamic messaging settings (nxpsc_sdm_settings_t).</summary>
public sealed record NxpscSdmSettings
{
    public bool Enabled { get; init; }
    public bool UidMirror { get; init; }
    public bool CounterMirror { get; init; }
    public bool ReadCounterLimit { get; init; }
    public bool EncFileData { get; init; }

    /// <summary>0x0E plain mirroring, 0x0F no mirroring.</summary>
    public byte MetaReadKey { get; init; } = 0x0F;

    /// <summary>The key used for the CMAC / enc mirror, 0x0F none.</summary>
    public byte FileReadKey { get; init; } = 0x0F;

    public byte CounterRetKey { get; init; } = 0x0F;

    public uint UidOffset { get; init; }
    public uint CounterOffset { get; init; }
    public uint PiccDataOffset { get; init; }
    public uint MacInputOffset { get; init; }
    public uint EncOffset { get; init; }
    public uint EncLength { get; init; }
    public uint MacOffset { get; init; }
    public uint ReadCounterLimitValue { get; init; }
}
