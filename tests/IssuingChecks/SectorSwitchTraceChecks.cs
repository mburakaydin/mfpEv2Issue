using System.Reflection;
using System.Security.Cryptography;
using MfpEv2Issue;

static class SectorSwitchTraceChecks
{
    private static byte[] Hex(string text) => Convert.FromHexString(text);
    private static byte[] Rotate(byte[] bytes) => bytes.Skip(1).Append(bytes[0]).ToArray();
    private static readonly byte[] SwitchKey = new byte[16];
    private static readonly byte[] SectorKey = Enumerable.Repeat((byte)0xFF, 16).ToArray();

    // Both complete successful exchanges from the supplied RFIDDiscover trace.
    // Wire Key B addresses 401F and 4021 correspond to zero-based sectors 15 and 16.
    private static readonly Trace[] Vectors =
    {
        new(15, "8567D16DCE8F3DEE68A42AB2A9B6D429", "BD8686B6A56E48056BCC8954B2BFBBFF",
            "AE9F5187EC0F73333D9C889177DAAE6C", "F3F2CC1DBFC3F3B1F262BC14730D68F5",
            "FEE8411530BEF4BE2F70F6C6512C344558A96B0E5FC335EB8F4B4AC032926D0F",
            "476DA406BAEA901A97256AE9151E1E099D817F5402C6F1E02A3BC80198E1DE72",
            "C7947B5F0F85706FD53D54D41E11B24F", "3ABC6167DEF1087DF3C69794B694523F"),
        new(16, "3D39F78C69C5707A8043AB74E6444FFE", "47D8C1E1B6A82A8CCA808FF45D0B4A58",
            "179E06F39CE5A43CEB833CED74AAA32D", "CECABBC7281342AF3CC5E1D2A4AF1F61",
            "87F6EB552D69660CD705CDE15E0C8D8E7C50C17783B28642C3E229059064E84F",
            "7DD6F0C0703A6F7EF66B6B91F78C15609C75CFB17672F1ADEDD0689E2B4B94D0",
            "F24C997E2A103B641764E50FADD91FAD", "073CCA4CBE049F4528479867DE9E768B")
    };

    public static void Run()
    {
        var layers = new[] { SwitchKey, SectorKey };
        foreach (var vector in Vectors)
        {
            using var aes = Aes.Create();
            aes.Key = SectorKey;
            Match(aes.DecryptCbc(Hex(vector.Challenge), new byte[16], PaddingMode.None),
                Hex(vector.IntermediateB), "challenge outer FF-key decryption");
            Match(Call("DecryptLayers", Hex(vector.Challenge), layers), Hex(vector.RndB), "production challenge decryption");

            var plain = Hex(vector.RndA).Concat(Rotate(Hex(vector.RndB))).ToArray();
            Match(Call("EncryptLayers", plain, new[] { SwitchKey }), Hex(vector.IntermediateRequest), "zero-key first encryption");
            Match(Call("EncryptLayers", plain, layers), Hex(vector.Request), "production 32-byte continuation encryption");
            Check(!Call("EncryptLayers", plain, layers.Reverse().ToArray()).SequenceEqual(Hex(vector.Request)),
                "Distinct-key vector must distinguish the reversed application-note order.");

            Match(aes.DecryptCbc(Hex(vector.Proof), new byte[16], PaddingMode.None),
                Hex(vector.IntermediateProof), "final proof outer FF-key decryption");
            Match(Call("DecryptLayers", Hex(vector.Proof), layers), Rotate(Hex(vector.RndA)), "production final proof decryption");

            foreach (bool raw in new[] { false, true })
            {
                var channel = new TraceCard(vector, raw);
                new MifarePlusController(channel).AuthenticateSectorSwitch(SectorSwitchTarget.SL1SL3Mix,
                    SwitchKey, new[] { new SectorKeyB(vector.Sector, SectorKey) }, useRaw: raw);
                Check(channel.Count == 2, "Public authentication must complete with the captured challenge and distinct keys.");
            }
        }
    }

    // Keep fixed test nonces out of the public authentication API.
    private static byte[] Call(string method, byte[] data, byte[][] keys) => (byte[])typeof(MifarePlusController)
        .GetMethod(method, BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, new object[] { data, keys })!;
    private static void Match(byte[] actual, byte[] expected, string step) => Check(actual.SequenceEqual(expected), $"RFIDDiscover mismatch: {step}.");
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private sealed record Trace(int Sector, string Challenge, string IntermediateB, string RndB,
        string RndA, string IntermediateRequest, string Request, string Proof, string IntermediateProof);

    // Uses the captured challenge, then verifies production's fresh random RndA continuation.
    private sealed class TraceCard(Trace vector, bool raw) : IMifarePlusChannel
    {
        public int Count { get; private set; }
        public byte[] Transceive(byte[] command)
        {
            Check(!raw, "Unexpected wrapped exchange.");
            return Exchange(command);
        }
        public byte[] TransceiveRaw(byte[] command)
        {
            Check(raw, "Unexpected raw exchange.");
            return Exchange(command);
        }
        private byte[] Exchange(byte[] command)
        {
            Count++;
            if (Count == 1)
            {
                int address = 0x4001 + 2 * vector.Sector;
                Match(command, new byte[] { 0x7A, 0x07, 0x90, 0x01, (byte)(address & 0xFF), 0x40 }, "request address");
                return new byte[] { 0x90 }.Concat(Hex(vector.Challenge)).ToArray();
            }
            Check(Count == 2 && command.Length == 33 && command[0] == 0x72, "Invalid continuation frame.");
            using var aes = Aes.Create();
            aes.Key = SectorKey;
            var inner = aes.DecryptCbc(command[1..], new byte[16], PaddingMode.None);
            aes.Key = SwitchKey;
            var plain = aes.DecryptCbc(inner, new byte[16], PaddingMode.None);
            Match(plain[16..], Rotate(Hex(vector.RndB)), "public continuation rotated RndB");
            var proof = aes.EncryptCbc(Rotate(plain[..16]), new byte[16], PaddingMode.None);
            aes.Key = SectorKey;
            proof = aes.EncryptCbc(proof, new byte[16], PaddingMode.None);
            return new byte[] { 0x90 }.Concat(proof).ToArray();
        }
        public void ReconnectCard() => throw new Exception("Unexpected reset within an exchange.");
    }
}
