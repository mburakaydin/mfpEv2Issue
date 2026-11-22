using PCSC;
using PCSC.Utils;

namespace MfpEv2Issue;

/// <summary>ISO 7816 wrapped native commands and unmodified PC/SC APDUs.</summary>
public sealed class PcscMifarePlusChannel : IMifarePlusChannel, IDisposable
{
    private readonly ISCardContext context;
    private readonly SCardReader reader;
    public Action<string>? Logger { get; set; }
    public bool LogKeyBytes { get; set; } = true;

    public PcscMifarePlusChannel(string readerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(readerName);
        context = ContextFactory.Instance.Establish(SCardScope.System);
        reader = new SCardReader(context);
        try
        {
            Check(reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any));
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public void ReconnectCard()
    {
        Logger?.Invoke("PC/SC reconnect/reset requested");
        Check(reader.Reconnect(SCardShareMode.Shared, SCardProtocol.Any, SCardReaderDisposition.Reset));
        Logger?.Invoke("PC/SC reconnect/reset OK");
    }

    public byte[] TransceiveRaw(byte[] apdu)
    {
        ArgumentNullException.ThrowIfNull(apdu);
        if (apdu.Length == 0) throw new ArgumentException("APDU is empty.", nameof(apdu));
        byte[] response = new byte[4096];
        Logger?.Invoke(ApduTrace.Format(apdu, outgoing: true, maskKeys: !LogKeyBytes));
        var result = reader.Transmit(SCardPCI.GetPci(reader.ActiveProtocol), apdu, ref response);
        if (result != SCardError.Success)
        {
            Logger?.Invoke($"PC/SC transmit failed: {SCardHelper.StringifyError(result)}");
            Check(result);
        }
        Logger?.Invoke(ApduTrace.Format(response, outgoing: false));
        // PCSC returns the actual response length. Zero bytes are meaningful data.
        return response;
    }

    public byte[] Transceive(byte[] command)
    {
        byte[] response = TransceiveRaw(WrapNativeCommand(command));
        if (response.Length < 2) throw new InvalidResponseStatusException(0);
        if (response[^2] != 0x91)
            throw new InvalidResponseStatusException(response[^2], response[^1]);
        // Normalize native status to byte zero, matching the controller contract.
        byte[] native = new byte[response.Length - 1];
        native[0] = response[^1];
        response.AsSpan(0, response.Length - 2).CopyTo(native.AsSpan(1));
        return native;
    }

    /// <summary>
    /// Wraps a native command as a short APDU. No parameters: header + Le (case 2S).
    /// With parameters: header + Lc + data + Le (case 4S). Never emits an empty Lc.
    /// </summary>
    public static byte[] WrapNativeCommand(byte[] command)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Length is < 1 or > 256)
            throw new ArgumentException("Expected a command with up to 255 parameter bytes.", nameof(command));
        if (command.Length == 1)
            return new byte[] { 0x90, command[0], 0x00, 0x00, 0x00 };
        byte[] apdu = new byte[command.Length + 5];
        apdu[0] = 0x90;
        apdu[1] = command[0];
        apdu[4] = (byte)(command.Length - 1);
        command.AsSpan(1).CopyTo(apdu.AsSpan(5));
        return apdu;
    }

    private static void Check(SCardError result)
    {
        if (result != SCardError.Success)
            throw new IOException($"PC/SC: {SCardHelper.StringifyError(result)}");
    }

    public void Dispose()
    {
        reader.Dispose();
        context.Dispose();
    }
}
