using System.Security.Cryptography;
using PCSC;
using PCSC.Exceptions;

namespace Tessera.Nxpsc;

/// <summary>
/// PC/SC transport over the PCSC package: SCardTransmit with SCARD_PCI_T1, as in
/// the hardware suites. Frames are never logged.
/// </summary>
public sealed class PcscTransport : ICardTransport
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(250);

    private readonly ISCardContext _context;
    private readonly ICardReader _reader;

    private PcscTransport(ISCardContext context, ICardReader reader, string readerName)
    {
        _context = context;
        _reader = reader;
        Description = readerName;
    }

    public string Description { get; }

    /// <summary>The readers PC/SC knows about; empty when there are none or no service.</summary>
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
    /// Picks a reader: the one whose name contains <paramref name="preferred"/>
    /// when given, else an ACR1552 contactless (PICC) interface, else any PICC
    /// interface, else the only reader. Null when that is ambiguous or empty.
    /// </summary>
    public static string? ChooseReader(IReadOnlyList<string> readers, string? preferred)
    {
        if (!string.IsNullOrWhiteSpace(preferred))
            return readers.FirstOrDefault(r => r.Contains(preferred, StringComparison.OrdinalIgnoreCase));

        return readers.FirstOrDefault(r => r.Contains("ACR1552", StringComparison.OrdinalIgnoreCase)
                                        && r.Contains("PICC", StringComparison.OrdinalIgnoreCase))
            ?? readers.FirstOrDefault(r => r.Contains("PICC", StringComparison.OrdinalIgnoreCase))
            ?? (readers.Count == 1 ? readers[0] : null);
    }

    /// <summary>Waits until a card is on <paramref name="readerName"/> and connects to it (T=1).</summary>
    public static PcscTransport WaitForCard(string readerName, TimeSpan timeout, CancellationToken cancellationToken)
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

    /// <summary>Waits until the reader is empty again, so the next run cannot pick up the same card.</summary>
    public static void WaitForRemoval(string readerName, TimeSpan timeout, CancellationToken cancellationToken)
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

    public void Dispose()
    {
        try
        {
            // leave the card powered as the suites do; nothing on it needs a reset
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
