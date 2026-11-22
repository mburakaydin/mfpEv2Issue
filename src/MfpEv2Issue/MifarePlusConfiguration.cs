namespace MfpEv2Issue;

public static class MifarePlusConfiguration
{
    public const ushort BlockAddress = 0xB000;

    /// <summary>
    /// Builds the SL0 mixed-mode configuration with SL1 activation parameters and ISO-4 enabled.
    /// With a base block, preserves all bytes except bytes 3 through 6.
    /// Without a base block, uses 00 0F 00 AA AA 01 55 followed by nine zero bytes.
    /// Zero activation override bytes preserve the card's existing ATQA and SAK (Table 79).
    /// A full RF power cycle is required for activation parameter changes to take effect.
    /// This permits sector switching; it does not switch individual sectors.
    /// </summary>
    public static byte[] CreateSL1SL3MixBlock(byte[]? baseBlock = null)
    {
        if (baseBlock is not null && baseBlock.Length != 16)
            throw new ArgumentException("Configuration block must be exactly 16 bytes.", nameof(baseBlock));
        var block = baseBlock is null ? new byte[16] : (byte[])baseBlock.Clone();
        if (baseBlock is null)
            block[1] = 0x0F; // DefaultPlainAC; MaxUMRead remains 00.
        block[3] = 0xAA; // KeySystemDataWrite: write enabled.
        block[4] = 0xAA; // SectorSwitch: sector switching allowed.
        block[5] = 0x01; // ISOParamUse: SL1 (Classic-compatible) activation parameters.
        block[6] = 0x55; // ISOL4Disabled: ISO 14443-4 activation enabled for AES access.
        return block;
    }

    /// <summary>Writes a complete B000 block in SL0; does not commit.</summary>
    public static void WriteConfigurationBlock(
        MifarePlusController ctrl, byte[]? configurationBlock = null, Action<string>? log = null)
    {
        ArgumentNullException.ThrowIfNull(ctrl);
        var block = configurationBlock ?? CreateSL1SL3MixBlock();
        if (block.Length != 16)
            throw new ArgumentException("Configuration block must be exactly 16 bytes.", nameof(configurationBlock));
        log?.Invoke("WritePerso bNr=0xB000");
        ctrl.WritePerso(BlockAddress, block);
    }
}
