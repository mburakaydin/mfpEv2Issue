using System.Security.Cryptography;

namespace MfpEv2Issue;

public enum SectorSwitchTarget : ushort
{
    SL3 = 0x9006,
    SL1SL3Mix = 0x9007
}

public sealed record SectorKeyB(int Sector, byte[] Key);

public sealed class SectorSwitchResponseException(byte command, byte status) : InvalidResponseStatusException(status)
{
    public byte Command { get; } = command;
    public override string Message => $"AuthenticateSectorSwitch 0x{Command:X2} ({(Command == 0x7A ? "initial challenge" : "continuation")}): response 0x{Status:X2}";
}

public partial class MifarePlusController
{
    /// <summary>
    /// Switches selected sectors from SL1 using the datasheet Tables 34/35 key order.
    /// Requires ISO 14443-4 activation and SectorSwitch enabled. Does not establish
    /// a normal FirstAuth secure messaging session. At most 31 sectors per 2KB command
    /// or 39 per 4KB command; the mixed-mode helper processes 2KB sectors one at a time.
    /// useRaw bypasses native APDU wrapping, matching the reference reader's post-activation
    /// mode. That mode must return native status first, followed by challenge bytes.
    /// </summary>
    public void AuthenticateSectorSwitch(
        SectorSwitchTarget target,
        byte[] switchingKey,
        IReadOnlyList<SectorKeyB> sectors,
        int cardSectorCount = 32,
        bool useRaw = false)
    {
        if (target != SectorSwitchTarget.SL1SL3Mix && target != SectorSwitchTarget.SL3)
            throw new ArgumentOutOfRangeException(nameof(target));
        if (cardSectorCount != 32 && cardSectorCount != 40)
            throw new ArgumentOutOfRangeException(nameof(cardSectorCount), "Select a 32-sector 2KB or 40-sector 4KB card.");
        ArgumentNullException.ThrowIfNull(sectors);
        if (switchingKey is null || switchingKey.Length != 16)
            throw new ArgumentException("Switching key must be 16 bytes.", nameof(switchingKey));
        if (sectors.Count < 1 || sectors.Count > cardSectorCount - 1)
            throw new ArgumentException($"Select 1 through {cardSectorCount - 1} sectors per command.", nameof(sectors));

        var keys = new List<byte[]> { (byte[])switchingKey.Clone() };
        var seen = new HashSet<int>();
        var command = new byte[4 + 2 * sectors.Count];
        command[0] = 0x7A;
        command[1] = (byte)((ushort)target & 0xFF);
        command[2] = (byte)((ushort)target >> 8);
        command[3] = (byte)sectors.Count;
        for (int i = 0; i < sectors.Count; i++)
        {
            var entry = sectors[i];
            if (entry is null || entry.Sector < 0 || entry.Sector >= cardSectorCount || !seen.Add(entry.Sector))
                throw new ArgumentException("Sectors must be distinct and within the target card.", nameof(sectors));
            if (entry.Key is null || entry.Key.Length != 16)
                throw new ArgumentException("Every sector Key B must be 16 bytes.", nameof(sectors));
            ushort address = (ushort)(0x4001 + 2 * entry.Sector);
            command[4 + 2 * i] = (byte)(address & 0xFF);
            command[5 + 2 * i] = (byte)(address >> 8);
            keys.Add((byte[])entry.Key.Clone());
        }

        // Sector switching invalidates any earlier secure messaging session.
        _session = new FirstAuthResult();
        var rndB = DecryptLayers(ExchangeChallenge(command, useRaw), keys);
        var rndA = RandomNumberGenerator.GetBytes(16);
        var plain = new byte[32];
        rndA.CopyTo(plain, 0);
        RotateLeftByte(rndB).CopyTo(plain, 16);
        // Datasheet Table 35: switching key first, then Key Bs in request order.
        var encrypted = EncryptLayers(plain, keys);
        var continuation = new byte[33];
        continuation[0] = 0x72;
        encrypted.CopyTo(continuation, 1);
        var returnedRndA = DecryptLayers(ExchangeChallenge(continuation, useRaw), keys);
        if (!CryptographicOperations.FixedTimeEquals(returnedRndA, RotateLeftByte(rndA)))
            throw new CryptoErrorException("AuthenticateSectorSwitch: returned RndA does not match.");
    }

    /// <summary>Resets card authentication without reconnecting or changing sector security levels.</summary>
    public void ResetAuthentication(bool useRaw = false)
    {
        _session = new FirstAuthResult();
        var command = new byte[] { 0x78 };
        var response = useRaw ? _channel.TransceiveRaw(command) : Transceive(command);
        if (response is null || response.Length == 0)
            throw new LengthMismatchException(1, response?.Length ?? 0);
        if (response[0] != 0x90)
            throw new InvalidResponseStatusException(response[0]);
        if (response.Length != 1)
            throw new LengthMismatchException(1, response.Length);
    }

    private byte[] ExchangeChallenge(byte[] command, bool useRaw)
    {
        var response = useRaw ? _channel.TransceiveRaw(command) : Transceive(command);
        if (response is null || response.Length == 0)
            throw new LengthMismatchException(17, response?.Length ?? 0);
        if (response[0] != 0x90)
            throw new SectorSwitchResponseException(command[0], response[0]);
        if (response.Length != 17)
            throw new LengthMismatchException(17, response.Length);
        return response[1..];
    }

    private static byte[] EncryptLayers(byte[] data, IReadOnlyList<byte[]> keys)
    {
        foreach (var key in keys)
            data = AesCbcEncrypt(key, new byte[16], data);
        return data;
    }

    private static byte[] DecryptLayers(byte[] data, IReadOnlyList<byte[]> keys)
    {
        for (int i = keys.Count - 1; i >= 0; i--)
            data = AesCbcDecrypt(keys[i], new byte[16], data);
        return data;
    }

    private static byte[] RotateLeftByte(byte[] data)
    {
        var rotated = new byte[data.Length];
        Array.Copy(data, 1, rotated, 0, data.Length - 1);
        rotated[^1] = data[0];
        return rotated;
    }
}
