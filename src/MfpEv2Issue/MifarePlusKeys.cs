namespace MfpEv2Issue;

/// <summary>SL0 personalization keys. Sector entries supply both AES Key A and Key B.</summary>
public static class MifarePlusKeys
{
    private static readonly (string Name, ushort Address)[] ControlKeys =
    {
        ("MASTER", 0x9000),
        ("CONF", 0x9001),
        ("L3SWITCH", 0x9003),
        ("L3SECTORSWITCH", 0x9006),
        ("MIXSECTORSWITCH", 0x9007)
    };

    /// <summary>Creates independent, zero-filled AES-128 keys for development personalization.</summary>
    public static Dictionary<string, byte[]> CreateDefaultKeySet(int sectorCount = 32)
    {
        ValidateSectorCount(sectorCount);
        return Enumerable.Range(0, sectorCount).Select(i => $"SECTOR{i}")
            .Concat(ControlKeys.Select(k => k.Name))
            .ToDictionary(name => name, _ => new byte[16]);
    }

    /// <summary>
    /// Builds a uniform AES sector-key profile and a separate 9007 key from UI hex input.
    /// Accepts 32 hex digits, optional leading 0x, and whitespace. Other control keys stay zero.
    /// </summary>
    public static Dictionary<string, byte[]> CreateUniformKeySet(
        string sectorKeyHex, string mixSwitchKeyHex, int sectorCount = 32,
        IReadOnlyDictionary<int, string>? sectorOverrides = null)
    {
        var sectorKey = ParseKey(sectorKeyHex, "Sector AES key");
        var switchKey = ParseKey(mixSwitchKeyHex, "9007 switch key");
        var keys = CreateDefaultKeySet(sectorCount);
        for (int sector = 0; sector < sectorCount; sector++)
            keys[$"SECTOR{sector}"] = (byte[])sectorKey.Clone();
        keys["MIXSECTORSWITCH"] = switchKey;
        if (sectorOverrides is not null)
            foreach (var (sector, hex) in sectorOverrides)
            {
                if (sector < 0 || sector >= sectorCount)
                    throw new ArgumentException($"Override sector must be between 0 and {sectorCount - 1}.", nameof(sectorOverrides));
                keys[$"SECTOR{sector}"] = ParseKey(hex, $"Sector {sector:D2} override");
            }
        return keys;
    }

    private static byte[] ParseKey(string? value, string label)
        => Convert.FromHexString(NormalizeAesKeyHex(value, label));

    /// <summary>Normalizes up to 16 whole hex bytes, padding missing trailing bytes with zero.</summary>
    public static string NormalizeAesKeyHex(string? value, string label = "AES key")
    {
        string hex = new((value ?? "").Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
        if (hex.Length > 32 || hex.Length % 2 != 0 || hex.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException($"{label} must contain up to 32 hexadecimal digits in complete byte pairs.");
        return hex.ToUpperInvariant().PadRight(32, '0');
    }

    /// <summary>Builds a 32-sector UI profile with explicit inputs for all five issuing control keys.</summary>
    public static Dictionary<string, byte[]> CreateKeySet(
        string defaultSectorKeyHex,
        IReadOnlyDictionary<string, string> controlKeys,
        IReadOnlyDictionary<int, string>? sectorOverrides = null)
    {
        ArgumentNullException.ThrowIfNull(controlKeys);
        foreach (var (name, address) in ControlKeys)
            if (!controlKeys.ContainsKey(name))
                throw new ArgumentException($"Supply the {address:X4} {name} key field.", nameof(controlKeys));
        var keys = CreateUniformKeySet(defaultSectorKeyHex,
            controlKeys.GetValueOrDefault("MIXSECTORSWITCH", ""), sectorOverrides: sectorOverrides);
        foreach (var (name, address) in ControlKeys)
            keys[name] = ParseKey(controlKeys.GetValueOrDefault(name, ""), $"{address:X4} {name} key");
        return keys;
    }

    /// <summary>Writes AES sector keys and the five control keys using WritePerso; does not commit.</summary>
    public static void WriteKeys(
        MifarePlusController ctrl,
        IDictionary<string, byte[]> keySet,
        Action<string>? log = null,
        int sectorCount = 32)
    {
        ArgumentNullException.ThrowIfNull(ctrl);
        ArgumentNullException.ThrowIfNull(keySet);
        ValidateSectorCount(sectorCount);
        var required = Enumerable.Range(0, sectorCount).Select(i => $"SECTOR{i}")
            .Concat(ControlKeys.Select(k => k.Name));
        foreach (var name in required)
        {
            if (!keySet.TryGetValue(name, out var key) || key is null || key.Length != 16)
                throw new ArgumentException($"Supply a 16-byte key for {name}.", nameof(keySet));
        }

        for (int sector = 0; sector < sectorCount; sector++)
        {
            Write((ushort)(0x4000 + 2 * sector), keySet[$"SECTOR{sector}"]);
            Write((ushort)(0x4001 + 2 * sector), keySet[$"SECTOR{sector}"]);
        }
        foreach (var (name, address) in ControlKeys)
            Write(address, keySet[name]);

        void Write(ushort address, byte[] key)
        {
            log?.Invoke($"WritePerso bNr=0x{address:X4}");
            ctrl.WritePerso(address, key);
        }
    }

    private static void ValidateSectorCount(int sectorCount)
    {
        if (sectorCount < 1 || sectorCount > 56)
            throw new ArgumentOutOfRangeException(nameof(sectorCount), "Select 1 through 56 sectors supported by the target card.");
    }
}
