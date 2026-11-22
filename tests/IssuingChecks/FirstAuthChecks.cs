using System.Reflection;
using System.Security.Cryptography;
using MfpEv2Issue;

static class FirstAuthChecks
{
    private static byte[] Hex(string value) => Convert.FromHexString(value);
    private static readonly byte[] RndA = Hex("52A2AE87324B041C57B4350C22C41F54");
    private static readonly byte[] RndB = Hex("4DE0B5FD4A340CA3437C9B6DF050B75C");
    private static readonly byte[] EncryptedB = Hex("90E9BA8AC11F26450DC2500C1B8654A5");
    private static readonly byte[] FinalProof = Hex("EA3576BBB594A5344EEEBBF5768945348B57042E11A0B42F98EA5ED0779BCD31");

    public static void Run()
    {
        // Fixed values from the successful RFIDDiscover 9000 authentication trace.
        using var aes = Aes.Create();
        aes.Key = new byte[16];
        Check(aes.DecryptCbc(EncryptedB, new byte[16], PaddingMode.None).SequenceEqual(RndB), "Trace RndB mismatch.");
        var plain = RndA.Concat(Rotate(RndB)).ToArray();
        Check(aes.EncryptCbc(plain, new byte[16], PaddingMode.None).SequenceEqual(
            Hex("6E6D60759A99C333737DCF3CCAB0C6CD01A284D4AA5054D657317E9CEECD6B31")),
            "Trace continuation requires CBC chaining across both 16-byte blocks.");

        // Exercise production proof verification and derivation with the exact captured nonces.
        // Reflection keeps deterministic test nonces out of the public authentication API.
        var ctrl = new MifarePlusController(new AuthCard(false));
        var verify = typeof(MifarePlusController).GetMethod("FirstAuth2", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var result = (byte[])verify.Invoke(ctrl, new object[] { new byte[16], RndA, RndB, FinalProof })!;
        Check(result.SequenceEqual(Hex("39E28CC8CD8E67922A865DF5A632C7148E7A17164F4A4BFE44E0FDAC0CCFDD4BFDEAB8A3")),
            "TI, session ENC key, or session MAC key differs from the RFIDDiscover trace.");
        var badProof = (byte[])FinalProof.Clone();
        badProof[0] ^= 1;
        try
        {
            verify.Invoke(ctrl, new object[] { new byte[16], RndA, RndB, badProof });
            throw new Exception("Corrupted master-key proof accepted.");
        }
        catch (TargetInvocationException ex) when (ex.InnerException is InvalidInputException) { }

        // Exercise public authentication with fresh random RndA in both transport/capability modes.
        foreach (bool raw in new[] { false, true })
        foreach (bool omit in new[] { false, true })
        {
            var card = new AuthCard(raw) { OmitCapabilities = omit };
            var session = new MifarePlusController(card).FirstAuth(new byte[16], 0x9000, raw,
                omit ? Array.Empty<byte>() : null);
            Check(card.Count == 2 && session.Ti.SequenceEqual(Hex("39E28CC8")) && session.WCtr == 0 && session.RCtr == 0,
                "Master-key authentication did not complete and initialize the session.");
        }
    }

    private static byte[] Rotate(byte[] value) => value.Skip(1).Append(value[0]).ToArray();
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private sealed class AuthCard(bool raw) : IMifarePlusChannel
    {
        public bool OmitCapabilities { get; init; }
        public int Count { get; private set; }
        public byte[] Transceive(byte[] command)
        {
            Check(!raw, "Expected raw master authentication.");
            return Exchange(command);
        }
        public byte[] TransceiveRaw(byte[] command)
        {
            Check(raw, "Expected wrapped master authentication.");
            return Exchange(command);
        }
        private byte[] Exchange(byte[] command)
        {
            Count++;
            if (Count == 1)
            {
                Check(command.SequenceEqual(Hex(OmitCapabilities ? "70009000" : "70009006000000000000")),
                    "Incorrect master-key AuthenticateFirst request.");
                return new byte[] { 0x90 }.Concat(EncryptedB).ToArray();
            }
            Check(Count == 2 && command.Length == 33 && command[0] == 0x72, "Incorrect AuthenticateContinue request.");
            using var aes = Aes.Create();
            aes.Key = new byte[16];
            var plain = aes.DecryptCbc(command[1..], new byte[16], PaddingMode.None);
            Check(plain[16..].SequenceEqual(Rotate(RndB)), "Production continuation failed RndB verification.");
            var response = Hex("39E28CC8").Concat(Rotate(plain[..16])).Concat(new byte[12]).ToArray();
            return new byte[] { 0x90 }.Concat(aes.EncryptCbc(response, new byte[16], PaddingMode.None)).ToArray();
        }
        public void ReconnectCard() => throw new Exception("Unexpected reset during authentication.");
    }
}
