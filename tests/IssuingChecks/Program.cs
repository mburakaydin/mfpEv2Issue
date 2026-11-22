using MfpEv2Issue;

static Dictionary<string, byte[]> Keys() => MifarePlusKeys.CreateDefaultKeySet(16);

static void Require(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

var channel = new FakeChannel();
CardPerso.SL0Operations(new MifarePlusController(channel), Keys(), null, sectorCount: 16);
Require(channel.Commands.Count == 39, "Expected 37 key writes, B000, then commit.");
for (int i = 0; i < 32; i++)
{
    var command = channel.Commands[i];
    Require(command.Length == 19 && command[0] == 0xA8 &&
        command[1] == i && command[2] == 0x40, "Sector key address mismatch.");
}
Require(channel.Commands[32][1] == 0 && channel.Commands[32][2] == 0x90, "Master key address mismatch.");
Require(channel.Commands[33][1] == 1 && channel.Commands[34][1] == 3, "Control key address mismatch.");
Require(channel.Commands[35][1] == 6 && channel.Commands[35][2] == 0x90 &&
    channel.Commands[36][1] == 7 && channel.Commands[36][2] == 0x90, "Sector switch key address mismatch.");
Require(channel.Commands.Take(37).All(c => c.Skip(3).All(b => b == 0)), "Default keys must be zero-filled.");
Require(channel.Commands[37].SequenceEqual(Convert.FromHexString("A800B0000F00AAAA0055000000000000000000")),
    "B000 must enable mixed-mode switching and ISO-4 while leaving ISOParamUse unchanged.");
Require(channel.Commands[^1].SequenceEqual(new byte[] { 0xAA }), "CommitPerso must follow all personalization writes.");

foreach (string invalid in new[] { "SECTOR15", "MASTER", "L3SECTORSWITCH", "MIXSECTORSWITCH" })
{
    channel = new FakeChannel();
    var keys = Keys();
    if (invalid == "MASTER") keys[invalid] = new byte[15];
    else keys.Remove(invalid);
    try
    {
        CardPerso.SL0Operations(new MifarePlusController(channel), keys, null, sectorCount: 16);
        throw new Exception("Invalid profile was accepted.");
    }
    catch (ArgumentException) { }
    Require(channel.Commands.Count == 0, "Invalid profile must not write anything.");
}

foreach (int failAt in new[] { 4, 36, 37, 38 })
{
channel = new FakeChannel { FailAt = failAt };
try
{
    CardPerso.SL0Operations(new MifarePlusController(channel), Keys(), null, sectorCount: 16);
    throw new Exception("Failed write was accepted.");
}
catch (InvalidResponseStatusException) { }
Require(channel.Commands.Count == failAt && channel.Commands.All(c => c[0] != 0xAA),
    "Failure must stop writes and prevent commit.");
}

channel = new FakeChannel();
try
{
    CardPerso.SL0Operations(new MifarePlusController(channel), Keys(), null, new byte[15]);
    throw new Exception("Invalid configuration was accepted.");
}
catch (ArgumentException) { }
Require(channel.Commands.Count == 0, "Invalid configuration must fail before any key write.");

var baseBlock = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
var mixedBlock = MifarePlusConfiguration.CreateSL1SL3MixBlock(baseBlock);
Require(baseBlock[3] == 3 && baseBlock[4] == 4, "Configuration builder must not modify its input.");
Require(mixedBlock[3] == 0xAA && mixedBlock[4] == 0xAA && mixedBlock[5] == 0x00 && mixedBlock[6] == 0x55,
    "Mixed-mode builder must emit ISOParamUse no-change and enable ISO-4 even with a base block.");
Require(mixedBlock.Where((_, i) => i < 3 || i > 6)
    .SequenceEqual(baseBlock.Where((_, i) => i < 3 || i > 6)), "Unrelated configuration bytes must be preserved.");
Require(MifarePlusConfiguration.CreateSL1SL3MixBlock().Skip(7).All(b => b == 0),
    "Default profile must preserve the card's existing ATQA and SAK rather than overriding them.");

channel = new FakeChannel();
CardPerso.SL0Operations(new MifarePlusController(channel));
Require(channel.Commands.Count == 71, "Default overload must write all 32 sectors, five control keys, B000, then commit.");

channel = new FakeChannel();
MifarePlusKeys.WriteKeys(new MifarePlusController(channel), MifarePlusKeys.CreateDefaultKeySet(56), sectorCount: 56);
Require(channel.Commands.Count == 117 && channel.Commands[111][1] == 0x6F && channel.Commands[111][2] == 0x40,
    "Explicit extended profile must end sector keys at 406F and must not commit.");
SectorSwitchChecks.Run();
FirstAuthChecks.Run();
SectorSwitchTraceChecks.Run();
ApduTraceChecks.Run();
Console.WriteLine("Passed: personalization and sector switching checks.");

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
