namespace Tessera.Nxpsc;

/// <summary>
/// Moves one ISO 14443-4 payload (the INF field: no framing, no CRC) to the card
/// and back. This is libnxpsc's transceive callback:
/// <list type="bullet">
/// <item>Return false ONLY for a genuine transport failure: card removed, no
/// answer, reader gone. libnxpsc sees NXPSC_E_TRANSPORT.</item>
/// <item>A card answering with an error status is NOT a transport failure:
/// return true with the answer untouched, and let libnxpsc decode it.</item>
/// </list>
/// Implementations must never log the frames: they carry challenges and
/// enciphered key material. They are called on the thread that called into
/// <see cref="NxpscCard"/>, and must not throw (an exception is treated as a
/// transport failure).
/// </summary>
public interface ICardTransport : IDisposable
{
    /// <summary>A human label, e.g. the reader name.</summary>
    string Description { get; }

    bool TryTransceive(ReadOnlySpan<byte> command, Span<byte> response, out int responseLength);

    /// <summary>True only for a mock card. Real transports keep the default.</summary>
    bool IsMock => false;
}

/// <summary>
/// Optional: the UID of the selected card, as the reader saw it at anticollision.
/// libnxpsc asks once, when the card is opened, and uses it as the answer of
/// <see cref="NxpscCard.GetCardUid"/> when there is no session.
/// </summary>
public interface IUidTransport
{
    bool TryGetUid(Span<byte> uid, out int length);
}

/// <summary>
/// Optional: put the card back into a known, freshly selected state. Part of
/// libnxpsc's transport contract for ISO flows; the current library does not
/// call it.
/// </summary>
public interface IReselectTransport
{
    bool TryReselect();
}
