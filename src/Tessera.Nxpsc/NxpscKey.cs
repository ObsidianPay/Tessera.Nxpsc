using System.Security.Cryptography;

namespace Tessera.Nxpsc;

/// <summary>
/// Key material handed to libnxpsc. The bytes live in a pinned array (so the GC
/// never leaves a stray copy behind when it compacts) and are zeroed on
/// dispose. There is deliberately no ToString and no hex accessor: nothing that
/// could end up in a log. The one way to read the bytes back out is
/// <see cref="ExportTo"/>, into a buffer the caller owns.
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

    /// <summary>
    /// Same type and same bytes, compared in constant time. The version is not
    /// part of the key material and is not compared.
    /// </summary>
    public bool FixedTimeEquals(NxpscKey other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return Type == other.Type && CryptographicOperations.FixedTimeEquals(Bytes, other.Bytes);
    }

    /// <summary>An independent copy (its own pinned buffer, its own lifetime).</summary>
    public NxpscKey Copy() => new(Type, Bytes, Version);

    /// <summary>
    /// Copies the key bytes into <paramref name="destination"/>, which must hold
    /// at least <see cref="SizeOf"/> bytes. This exists for a key server that
    /// derives one card's key and hands it to the one party entitled to it,
    /// over an authenticated channel — the shape a SAM has in derivation mode.
    /// The copy is the caller's: send it, then zero it with
    /// <c>CryptographicOperations.ZeroMemory</c>, and never format it into a
    /// string that could reach a log.
    /// </summary>
    public void ExportTo(Span<byte> destination)
    {
        var bytes = Bytes;
        if (destination.Length < bytes.Length)
            throw new ArgumentException($"A {Type} key needs {bytes.Length} bytes.", nameof(destination));
        bytes.CopyTo(destination);
    }

    public override string ToString() => $"{Type} key (version {Version})";

    public void Dispose()
    {
        if (_disposed)
            return;
        CryptographicOperations.ZeroMemory(_data);
        _disposed = true;
    }
}
