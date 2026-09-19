namespace Tessera.Nxpsc;

/// <summary>
/// Moves one ISO 14443-4 payload to the card and back. The contract is the one
/// the Tessera and Crucible hardware suites use:
/// <list type="bullet">
/// <item>Return false ONLY for a genuine transport failure — card removed, no
/// answer, reader gone. libnxpsc sees NXPSC_E_TRANSPORT.</item>
/// <item>A card answering with an error status is NOT a transport failure:
/// return true with the answer untouched, and let libnxpsc decode it.</item>
/// </list>
/// Implementations must never log the frames: they carry challenges and
/// enciphered key material.
/// </summary>
public interface ICardTransport : IDisposable
{
    /// <summary>A human label for output, e.g. the reader name.</summary>
    string Description { get; }

    bool TryTransceive(ReadOnlySpan<byte> command, Span<byte> response, out int responseLength);

    /// <summary>True only for the libnxpsc mock card. Real transports keep the default.</summary>
    bool IsMock => false;
}
