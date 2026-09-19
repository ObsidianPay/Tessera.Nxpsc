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

/// <summary>Key types, values as libnxpsc's nxpsc_keytype_t.</summary>
public enum NxpscKeyType
{
    Des = 0,
    TwoKey3Des = 1,
    ThreeKey3Des = 2,
    Aes128 = 3,
    Aes256 = 4,
}

/// <summary>Secure channels, values as libnxpsc's nxpsc_channel_t.</summary>
public enum NxpscChannel
{
    Auto = 0,
    D40,
    Ev1,
    Ev2,
    Lrp,
}

/// <summary>Failure classes, values as libnxpsc's nxpsc_error_t.</summary>
public enum NxpscErrorCode
{
    Param = -1,
    Transport = -2,
    Card = -3,
    Crypto = -4,
    Auth = -5,
    Length = -6,
    Unsupported = -7,
    Memory = -8,
}

/// <summary>What GetVersion reported. Nothing here is secret.</summary>
public sealed record CardVersion(
    byte HwVendor,
    byte HwType,
    byte HwMajor,
    byte HwMinor,
    byte HwStorage,
    byte SwMajor,
    byte SwMinor,
    byte[] Uid,
    byte ProductionWeek,
    byte ProductionYear);

/// <summary>DESFire status bytes the personaliser branches on.</summary>
public static class DesfireStatus
{
    public const byte NoSuchKey = 0x40;
    public const byte PermissionDenied = 0x9D;
    public const byte AuthenticationError = 0xAE;
    public const byte ApplicationNotFound = 0xA0;
    public const byte DuplicateError = 0xDE;
}
