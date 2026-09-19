using System.Security.Cryptography;

namespace Tessera.Nxpsc;

/// <summary>
/// Key material handed to libnxpsc. The bytes live in a pinned array (so the GC
/// never leaves a stray copy behind when it compacts) and are zeroed on
/// dispose. There is deliberately no ToString, no hex accessor, and no way to
/// read the bytes back out: nothing that could end up in a log.
/// </summary>
public sealed class NxpscKey : IDisposable
{
    private readonly byte[] _data;
    private bool _disposed;

    public NxpscKey(NxpscKeyType type, ReadOnlySpan<byte> data, byte version = 0)
    {
        var size = SizeOf(type);
        if (data.Length != size)
            throw new ArgumentException($"A {type} key is {size} bytes, not {data.Length}.", nameof(data));

        Type = type;
        Version = version;
        _data = GC.AllocateUninitializedArray<byte>(size, pinned: true);
        data.CopyTo(_data);
    }

    public NxpscKeyType Type { get; }

    /// <summary>
    /// For AES keys, the key version byte ChangeKey loads alongside the key. For
    /// (2K3)DES keys libnxpsc carries it in the parity bits instead.
    /// </summary>
    public byte Version { get; }

    /// <summary>The DESFire factory PICC master key: 2K3DES, all zero.</summary>
    public static NxpscKey FactoryPiccMasterKey() => new(NxpscKeyType.TwoKey3Des, new byte[16]);

    /// <summary>The key a freshly created AES application carries: all zero.</summary>
    public static NxpscKey FactoryAesApplicationKey() => new(NxpscKeyType.Aes128, new byte[16]);

    public static int SizeOf(NxpscKeyType type) => type switch
    {
        NxpscKeyType.Des => 8,
        NxpscKeyType.TwoKey3Des => 16,
        NxpscKeyType.ThreeKey3Des => 24,
        NxpscKeyType.Aes128 => 16,
        NxpscKeyType.Aes256 => 32,
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    internal ReadOnlySpan<byte> Bytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _data;
        }
    }

    /// <summary>An independent copy (its own pinned buffer, its own lifetime).</summary>
    public NxpscKey Copy() => new(Type, Bytes, Version);

    public override string ToString() => $"{Type} key (version {Version})";

    public void Dispose()
    {
        if (_disposed)
            return;
        CryptographicOperations.ZeroMemory(_data);
        _disposed = true;
    }
}
