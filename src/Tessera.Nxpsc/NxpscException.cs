namespace Tessera.Nxpsc;

/// <summary>
/// A libnxpsc call returned a negative code. <see cref="CardStatus"/> is the
/// status byte of the card's answer (nxpsc_last_status) and only meaningful when
/// <see cref="Code"/> is <see cref="NxpscErrorCode.Card"/>.
/// <para>
/// <see cref="SessionLost"/> is nxpsc_session_lost() sampled right after the
/// failure: when true the PICC has dropped secure messaging and every further
/// in-session command will fail until a fresh authentication.
/// </para>
/// </summary>
public sealed class NxpscException : Exception
{
    public NxpscException(string operation, NxpscErrorCode code, string codeText,
        byte? cardStatus, string? cardStatusText, bool sessionLost)
        : base(Describe(operation, codeText, cardStatus, cardStatusText))
    {
        Operation = operation;
        Code = code;
        CardStatus = cardStatus;
        SessionLost = sessionLost;
    }

    public string Operation { get; }
    public NxpscErrorCode Code { get; }
    public byte? CardStatus { get; }
    public bool SessionLost { get; }

    public bool IsTransport => Code == NxpscErrorCode.Transport;

    public bool IsCardStatus(byte status) => Code == NxpscErrorCode.Card && CardStatus == status;

    private static string Describe(string operation, string codeText, byte? status, string? statusText) =>
        status is { } s
            ? $"{operation}: {codeText} (card status 0x{s:X2}: {statusText})"
            : $"{operation}: {codeText}";
}
