using MfpEv2Issue;

static class ApduTraceChecks
{
    public static void Run()
    {
        Check(PcscMifarePlusChannel.WrapNativeCommand(new byte[] { 0xAA })
            .SequenceEqual(Convert.FromHexString("90AA000000")), "CommitPerso must use five-byte case-2 APDU, without empty Lc.");
        Check(PcscMifarePlusChannel.WrapNativeCommand(new byte[] { 0x78 })
            .SequenceEqual(Convert.FromHexString("9078000000")), "Wrapped ResetAuthentication must also omit empty Lc.");
        var write = new byte[] { 0xA8, 0x00, 0x40 }.Concat(new byte[16]).ToArray();
        var wrappedWrite = PcscMifarePlusChannel.WrapNativeCommand(write);
        Check(wrappedWrite.Length == 24 && wrappedWrite[..5].SequenceEqual(Convert.FromHexString("90A8000012")) &&
            wrappedWrite[5..^1].SequenceEqual(write[1..]) && wrappedWrite[^1] == 0,
            "WritePerso must retain the working Lc/data/Le framing from the hardware trace.");
        Check(PcscMifarePlusChannel.WrapNativeCommand(Convert.FromHexString("7A0790010140"))
            .SequenceEqual(Convert.FromHexString("907A000005079001014000")), "Parameterized authentication framing must retain Lc and Le.");
        foreach (int invalidLength in new[] { 0, 257 })
        {
            try
            {
                PcscMifarePlusChannel.WrapNativeCommand(new byte[invalidLength]);
                throw new Exception("Invalid native command length accepted.");
            }
            catch (ArgumentException) { }
        }
        foreach (int address in new[] { 0x4000, 0x403F, 0x406F, 0x9000, 0x9007 })
        foreach (bool wrapped in new[] { false, true })
        {
            byte[] prefix = wrapped ? new byte[] { 0x90, 0xA8, 0, 0, 0x12 } : new byte[] { 0xA8 };
            var command = prefix.Concat(new[] { (byte)(address & 0xFF), (byte)(address >> 8) })
                .Concat(Enumerable.Repeat((byte)0xAB, 16)).Concat(wrapped ? new byte[1] : Array.Empty<byte>()).ToArray();
            var original = (byte[])command.Clone();
            string log = ApduTrace.Format(command, outgoing: true, maskKeys: true);
            Check(log.StartsWith($"APDU OUT [{command.Length} bytes]:") && !log.Contains("AB") &&
                log.Split(' ').Count(word => word == "**") == 16 && log.EndsWith("(key masked)"), "WritePerso key material must be masked with accurate length.");
            Check(command.SequenceEqual(original), "Logging must not alter transmitted bytes.");
            string fullLog = ApduTrace.Format(command, outgoing: true);
            Check(!fullLog.Contains("**") && !fullLog.Contains("masked") && fullLog.Split(' ').Count(word => word == "AB") == 16,
                "Explicit full-key logging must show the exact 16 key bytes in raw and wrapped frames.");
            Check(command.SequenceEqual(original), "Full-key logging must not alter transmitted bytes.");
        }
        var config = Convert.FromHexString("A800B0000F00AAAA0155000000000000000000");
        Check(!ApduTrace.Format(config, true).Contains("**"), "Configuration data should remain visible.");
        Check(ApduTrace.Format(new byte[] { 0x09 }, false) == "APDU IN  [1 bytes]: 09", "Native status must be logged unchanged.");
        Check(ApduTrace.Format(new byte[] { 0x90, 0x00 }, false).EndsWith("90 00"), "Trailing response zero must be preserved.");
        Check(ApduTrace.Format(Array.Empty<byte>(), false).Contains("[0 bytes]: (empty)"), "Empty responses must be explicit.");
        var request = Convert.FromHexString("7A0790010140");
        Check(ApduTrace.Format(request, true).EndsWith("7A 07 90 01 01 40"), "Raw authentication request should be visible.");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }
}
