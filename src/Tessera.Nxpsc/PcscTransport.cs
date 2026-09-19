using System.Security.Cryptography;
using PCSC;
using PCSC.Exceptions;

namespace Tessera.Nxpsc;

/// <summary>
/// PC/SC transport over the PCSC package: SCardTransmit with SCARD_PCI_T1.
/// PC/SC readers only carry APDUs, so open the card with
/// <see cref="NxpscCmdSet.NativeIso"/> (the default). Frames are never logged.
/// </summary>
public sealed class PcscTransport : ICardTransport, IUidTransport
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(250);

    // PC/SC part 3 GET DATA: the UID the reader saw at anticollision
    private static readonly byte[] GetUidApdu = [0xFF, 0xCA, 0x00, 0x00, 0x00];

    private readonly ISCardContext _context;
    private readonly ICardReader _reader;

    private PcscTransport(ISCardContext context, ICardReader reader, string readerName)
    {
        _context = context;
        _reader = reader;
        Description = readerName;
    }

    public string Description { get; }

    /// <summary>The readers PC/SC knows about; empty when there are none or no PC/SC service.</summary>
    public static IReadOnlyList<string> ListReaders()
    {
        try
        {
            using var context = ContextFactory.Instance.Establish(SCardScope.System);
            return context.GetReaders() ?? [];
        }
        catch (PCSCException)
        {
            return [];
        }
    }

    /// <summary>
    /// Picks a reader: the first whose name contains <paramref name="preferred"/>
    /// when given; otherwise the contactless interface (the one with "PICC" in its
    /// name, as combined contact/contactless readers name it), else the only
    /// reader. Null when that is ambiguous or there are none.
    /// </summary>
    public static string? ChooseReader(IReadOnlyList<string> readers, string? preferred = null)
    {
        if (!string.IsNullOrWhiteSpace(preferred))
            return readers.FirstOrDefault(r => r.Contains(preferred, StringComparison.OrdinalIgnoreCase));

        var contactless = readers.Where(r => r.Contains("PICC", StringComparison.OrdinalIgnoreCase)).ToList();
        if (contactless.Count == 1)
            return contactless[0];
        return readers.Count == 1 ? readers[0] : null;
    }

    /// <summary>Connects to a card already on <paramref name="readerName"/> (T=1).</summary>
    public static PcscTransport Connect(string readerName)
    {
        var context = ContextFactory.Instance.Establish(SCardScope.System);
        try
        {
            var reader = context.ConnectReader(readerName, SCardShareMode.Shared, SCardProtocol.T1);
            return new PcscTransport(context, reader, readerName);
        }
        catch
        {
            context.Dispose();
            throw;
        }
    }

    /// <summary>Waits until a card is on <paramref name="readerName"/> and connects to it (T=1).</summary>
    public static PcscTransport WaitForCard(string readerName, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var context = ContextFactory.Instance.Establish(SCardScope.System);
        var deadline = DateTime.UtcNow + timeout;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var reader = context.ConnectReader(readerName, SCardShareMode.Shared, SCardProtocol.T1);
                    return new PcscTransport(context, reader, readerName);
                }
                catch (PCSCException ex) when (IsNoCardYet(ex.SCardError))
                {
                    if (DateTime.UtcNow >= deadline)
                        throw new TimeoutException($"No card was presented to {readerName} within {timeout.TotalSeconds:0} s.");
                    cancellationToken.WaitHandle.WaitOne(PollInterval);
                }
            }
        }
        catch
        {
            context.Dispose();
            throw;
        }
    }

    /// <summary>Waits until the reader is empty again (or the timeout passes).</summary>
    public static void WaitForRemoval(string readerName, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        using var context = ContextFactory.Instance.Establish(SCardScope.System);
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            var state = context.GetReaderStatus(readerName);
            if ((state.EventState & SCRState.Present) == 0)
                return;
            cancellationToken.WaitHandle.WaitOne(PollInterval);
        }
    }

    public bool TryTransceive(ReadOnlySpan<byte> command, Span<byte> response, out int responseLength)
    {
        responseLength = 0;
        var send = command.ToArray();
        var receive = new byte[response.Length];
        try
        {
            var received = _reader.Transmit(SCardPCI.T1, send, send.Length, receive, receive.Length);
            if (received < 0 || received > response.Length)
                return false;
            receive.AsSpan(0, received).CopyTo(response);
            responseLength = received;
            return true;
        }
        catch (PCSCException)
        {
            // card removed, no answer, reader gone: a genuine transport failure
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(send);
            CryptographicOperations.ZeroMemory(receive);
        }
    }

    /// <summary>The anticollision UID, through the reader's GET DATA pseudo-APDU.</summary>
    public bool TryGetUid(Span<byte> uid, out int length)
    {
        length = 0;
        var receive = new byte[32];
        try
        {
            var received = _reader.Transmit(SCardPCI.T1, GetUidApdu, GetUidApdu.Length, receive, receive.Length);
            if (received < 2 || receive[received - 2] != 0x90 || receive[received - 1] != 0x00)
                return false;
            var uidLength = received - 2;
            if (uidLength > uid.Length)
                return false;
            receive.AsSpan(0, uidLength).CopyTo(uid);
            length = uidLength;
            return true;
        }
        catch (PCSCException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        try
        {
            // leave the card powered; nothing on it needs a reset
            _reader.Disconnect(SCardReaderDisposition.Leave);
        }
        catch (PCSCException)
        {
            // already gone
        }
        _reader.Dispose();
        _context.Dispose();
    }

    private static bool IsNoCardYet(SCardError error) => error is
        SCardError.NoSmartcard or SCardError.RemovedCard or SCardError.UnpoweredCard or
        SCardError.UnresponsiveCard or SCardError.ResetCard or SCardError.SharingViolation or
        SCardError.ProtocolMismatch or SCardError.Timeout;
}
