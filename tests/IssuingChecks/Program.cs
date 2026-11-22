using MfpEv2Issue;

static Dictionary<string, byte[]> Keys() => Enumerable.Range(0, 16)
    .Select(i => $"SECTOR{i}").Concat(new[] { "MASTER", "CONF", "L3SWITCH" })
    .ToDictionary(name => name, _ => new byte[16]); // Synthetic test data only.

static void Require(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

var channel = new FakeChannel();
CardPerso.SL0Operations(new MifarePlusController(channel), Keys(), null);
Require(channel.Commands.Count == 36, "Expected 35 writes followed by commit.");
for (int i = 0; i < 32; i++)
{
    var command = channel.Commands[i];
    Require(command.Length == 19 && command[0] == 0xA8 &&
        command[1] == i && command[2] == 0x40, "Sector key address mismatch.");
}
Require(channel.Commands[32][1] == 0 && channel.Commands[32][2] == 0x90, "Master key address mismatch.");
Require(channel.Commands[33][1] == 1 && channel.Commands[34][1] == 3, "Control key address mismatch.");
Require(channel.Commands[^1].SequenceEqual(new byte[] { 0xAA }), "Commit must be last.");

foreach (bool missing in new[] { true, false })
{
    channel = new FakeChannel();
    var keys = Keys();
    if (missing) keys.Remove("SECTOR15");
    else keys["MASTER"] = new byte[15];
    try
    {
        CardPerso.SL0Operations(new MifarePlusController(channel), keys, null);
        throw new Exception("Invalid profile was accepted.");
    }
    catch (ArgumentException) { }
    Require(channel.Commands.Count == 0, "Invalid profile must not write anything.");
}

channel = new FakeChannel { FailAt = 4 };
try
{
    CardPerso.SL0Operations(new MifarePlusController(channel), Keys(), null);
    throw new Exception("Failed write was accepted.");
}
catch (InvalidResponseStatusException) { }
Require(channel.Commands.Count == 4 && channel.Commands.All(c => c[0] != 0xAA),
    "Failure must stop writes and prevent commit.");
Console.WriteLine("Passed: personalization layout, preflight validation, and failed-write handling.");

sealed class FakeChannel : IMifarePlusChannel
{
    public List<byte[]> Commands { get; } = new();
    public int FailAt { get; init; } = -1;
    public byte[] Transceive(byte[] command)
    {
        Commands.Add((byte[])command.Clone());
        return new byte[] { Commands.Count == FailAt ? (byte)0x06 : (byte)0x90 };
    }
    public byte[] TransceiveRaw(byte[] apdu) => throw new Exception("Unexpected raw APDU during personalization.");
    public void ReconnectCard() { }
}
