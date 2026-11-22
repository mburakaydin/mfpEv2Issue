namespace MfpEv2Issue;

/// <summary>Wire-level APDU logs; keys are visible by default, with optional masking.</summary>
public static class ApduTrace
{
    public static string Format(byte[] bytes, bool outgoing, bool maskKeys = false)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        int keyOffset = -1;
        if (outgoing && maskKeys)
        {
            // Raw A8 | address LE | key, or wrapped 90 A8 00 00 Lc | address LE | key | Le.
            int addressOffset = bytes.Length >= 19 && bytes[0] == 0xA8 ? 1
                : bytes.Length >= 23 && bytes[0] == 0x90 && bytes[1] == 0xA8 ? 5 : -1;
            if (addressOffset >= 0)
            {
                int address = bytes[addressOffset] | (bytes[addressOffset + 1] << 8);
                if (address is >= 0x4000 and <= 0x406F or >= 0x9000 and <= 0x90FF)
                    keyOffset = addressOffset + 2;
            }
        }
        string hex = bytes.Length == 0 ? "(empty)" : string.Join(" ", bytes.Select((b, i) =>
            keyOffset >= 0 && i >= keyOffset && i < keyOffset + 16 ? "**" : b.ToString("X2")));
        return $"APDU {(outgoing ? "OUT" : "IN ")} [{bytes.Length} bytes]: {hex}" +
            (keyOffset >= 0 ? " (key masked)" : "");
    }
}
