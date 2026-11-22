using System.Security.Cryptography;
using MfpEv2Issue;

static class SectorSwitchChecks
{
    public static void Run()
    {
        var keys = MifarePlusKeys.CreateDefaultKeySet();
        keys["MIXSECTORSWITCH"] = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        for (int i = 0; i < 32; i++)
            keys[$"SECTOR{i}"] = Enumerable.Range(0, 16).Select(b => (byte)(32 + i + b)).ToArray();

        // Distinct keys ensure reversed layer order cannot accidentally pass.
        var card = new SwitchCard(keys);
        CardPerso.SwitchSectorsToSL1SL3Mix(new MifarePlusController(card), new[] { 7, 0, 31 }, keys);
        Check(card.Commands[0].SequenceEqual(Convert.FromHexString("7A0790010F40")) &&
            card.Commands[3].SequenceEqual(Convert.FromHexString("7A0790010140")) &&
            card.Commands[6].SequenceEqual(Convert.FromHexString("7A0790013F40")),
            "Selected sector order or little-endian addresses incorrect.");
        Check(card.Verified == 3 && card.Commands.Count == 8, "Selected exchanges were not individually verified.");

        card = new SwitchCard(keys);
        new MifarePlusController(card).AuthenticateSectorSwitch(SectorSwitchTarget.SL1SL3Mix,
            keys["MIXSECTORSWITCH"], new[] { 7, 0, 31 }.Select(s => new SectorKeyB(s, keys[$"SECTOR{s}"])).ToArray());
        Check(card.Commands[0].SequenceEqual(Convert.FromHexString("7A0790030F4001403F40")) && card.Verified == 1,
            "Low-level command must retain distinct-key multi-sector authentication support.");

        card = new SwitchCard(keys);
        CardPerso.SwitchAll2KbSectorsToSL1SL3Mix(new MifarePlusController(card), keys);
        Check(card.Commands.Select(c => c[0].ToString("X2")).SequenceEqual(SwitchSequence(32)),
            "All sectors must use individual authentication with reset between sectors.");
        Check(card.Commands.Where(c => c[0] == 0x7A).Select((c, i) => c[3] == 1 && c[4] == 1 + 2 * i && c[5] == 0x40).All(ok => ok),
            "Individual requests must cover sectors 0 through 31.");
        Check(card.Commands.Where(c => c[0] == 0x7A).All(c => c[1] == 7 && c[2] == 0x90),
            "Mixed-mode helper must never select SL3.");
        Check(card.Verified == 32, "Every sector must verify RndA.");

        var zeroKeys = MifarePlusKeys.CreateDefaultKeySet();
        var uiKeys = MifarePlusKeys.CreateUniformKeySet("0x" + string.Join(" ", Enumerable.Repeat("ff", 16)), new string('0', 32));
        Check(Enumerable.Range(0, 32).All(s => uiKeys[$"SECTOR{s}"].Length == 16 && uiKeys[$"SECTOR{s}"].All(b => b == 0xFF)) &&
            uiKeys["MIXSECTORSWITCH"].All(b => b == 0) && uiKeys["MASTER"].All(b => b == 0),
            "UI key profile must apply FF sector keys and a separate zero switching key.");
        Check(!ReferenceEquals(uiKeys["SECTOR0"], uiKeys["SECTOR1"]), "Sector keys must have independent buffers.");
        var overrides = Enumerable.Range(0, 3).ToDictionary(s => s, _ => new string('0', 32));
        var mixedUiKeys = MifarePlusKeys.CreateUniformKeySet(new string('F', 32), new string('0', 32), sectorOverrides: overrides);
        Check(Enumerable.Range(0, 32).All(s => mixedUiKeys[$"SECTOR{s}"].All(b => b == (s < 3 ? 0x00 : 0xFF))),
            "Mixed UI profile must use zero keys for sectors 0-2 and FF for 3-31.");
        var sl0Channel = new FakeChannel();
        CardPerso.SL0Operations(new MifarePlusController(sl0Channel), mixedUiKeys, null);
        Check(sl0Channel.Commands.Take(64).Select((c, index) =>
            c.Skip(3).SequenceEqual(mixedUiKeys[$"SECTOR{index / 2}"])).All(ok => ok),
            "SL0 must write the resolved UI default and overrides to both AES sector keys.");
        Check(sl0Channel.Commands[68].SequenceEqual(new byte[] { 0xA8, 0x07, 0x90 }.Concat(mixedUiKeys["MIXSECTORSWITCH"])),
            "SL0 must write the separate UI switching key to 9007.");
        var controlNames = new[] { "MASTER", "CONF", "L3SWITCH", "L3SECTORSWITCH", "MIXSECTORSWITCH" };
        var controlHex = controlNames.Select((name, i) => (name, hex: Convert.ToHexString(Enumerable.Repeat((byte)(i + 1), 16).ToArray())))
            .ToDictionary(pair => pair.name, pair => pair.hex);
        var configuredKeys = MifarePlusKeys.CreateKeySet(new string('F', 32), controlHex, overrides);
        var configuredChannel = new FakeChannel();
        CardPerso.SL0Operations(new MifarePlusController(configuredChannel), configuredKeys, null);
        var expectedControlAddresses = new byte[] { 0x00, 0x01, 0x03, 0x06, 0x07 };
        for (int i = 0; i < 5; i++)
        {
            var command = configuredChannel.Commands[64 + i];
            Check(command[1] == expectedControlAddresses[i] && command[2] == 0x90 &&
                command[3..].SequenceEqual(Convert.FromHexString(controlHex[controlNames[i]])),
                "Each 90xx field must reach the matching SL0 key address.");
        }
        Check(configuredKeys["SECTOR0"].All(b => b == 0) && configuredKeys["SECTOR3"].All(b => b == 0xFF),
            "Explicit control keys must preserve default sector keys and overrides.");
        foreach (var name in controlNames)
        {
            var invalidControls = new Dictionary<string, string>(controlHex);
            invalidControls.Remove(name);
            try
            {
                MifarePlusKeys.CreateKeySet(new string('F', 32), invalidControls, overrides);
                throw new Exception("Missing control-key field accepted.");
            }
            catch (ArgumentException) { }
        }
        var explicitControlCard = new IssuingCard(configuredKeys) { InitialSak = 0x18 };
        CardPerso.Continue2KbSL1ToSL1SL3Mix(new MifarePlusController(explicitControlCard), configuredKeys);
        Check(explicitControlCard.Events.SequenceEqual(new[] { "reconnect", "activate" }.Concat(SwitchSequence(32))),
            "SL1 flow must use entered 9007 and sector keys without writing other control keys.");
        foreach (bool rawMixed in new[] { false, true })
        {
            var mixedCard = new SwitchCard(mixedUiKeys) { AllowRaw = rawMixed };
            mixedCard.AlreadySwitched.UnionWith(new[] { 0, 1, 2 });
            var mixedLogs = new List<string>();
            CardPerso.SwitchAll2KbSectorsToSL1SL3Mix(new MifarePlusController(mixedCard), mixedUiKeys, mixedLogs.Add, rawMixed);
            Check(mixedCard.Verified == 29 && mixedLogs.Count(m => m.Contains(": already switched (0x09)")) == 3,
                "Mixed-key card must skip 0-2 and verify sectors 3-31.");
        }
        foreach (var invalidOverride in new[] { new Dictionary<int, string> { [-1] = new string('0', 32) },
            new Dictionary<int, string> { [32] = new string('0', 32) }, new Dictionary<int, string> { [2] = "bad" } })
        {
            try
            {
                MifarePlusKeys.CreateUniformKeySet(new string('F', 32), new string('0', 32), sectorOverrides: invalidOverride);
                throw new Exception("Invalid per-sector override accepted.");
            }
            catch (ArgumentException) { }
        }
        Check(MifarePlusKeys.NormalizeAesKeyHex("A1") == "A1" + new string('0', 30) &&
            MifarePlusKeys.NormalizeAesKeyHex("0x a1 b2") == "A1B2" + new string('0', 28) &&
            MifarePlusKeys.NormalizeAesKeyHex("") == new string('0', 32),
            "Short key values must be padded with zero bytes on the right.");
        var paddedKeys = MifarePlusKeys.CreateKeySet("FF", controlHex.ToDictionary(p => p.Key, _ => "A1B2"),
            new Dictionary<int, string> { [0] = "01" });
        Check(paddedKeys["SECTOR3"].SequenceEqual(new byte[] { 0xFF }.Concat(new byte[15])) &&
            paddedKeys["SECTOR0"].SequenceEqual(new byte[] { 0x01 }.Concat(new byte[15])) &&
            paddedKeys["MASTER"].SequenceEqual(new byte[] { 0xA1, 0xB2 }.Concat(new byte[14])),
            "Sector, override, and control keys must all use the same byte padding.");
        foreach (string invalid in new[] { "F", new string('F', 31), new string('F', 33), new string('F', 34), new string('G', 32) })
        foreach (bool invalidSector in new[] { false, true })
        {
            try
            {
                MifarePlusKeys.CreateUniformKeySet(invalidSector ? invalid : new string('F', 32), invalidSector ? new string('0', 32) : invalid);
                throw new Exception("Malformed UI key accepted.");
            }
            catch (ArgumentException ex)
            {
                Check(ex.Message.StartsWith(invalidSector ? "Sector AES key" : "9007 switch key"), "Validation must name the incorrect field without echoing its value.");
            }
        }
        foreach (bool rawUi in new[] { false, true })
        {
            var uiCard = new IssuingCard(uiKeys) { InitialSak = 0x18, ExpectRawSwitching = rawUi };
            var messages = new List<string>();
            CardPerso.Continue2KbSL1ToSL1SL3Mix(new MifarePlusController(uiCard), uiKeys, messages.Add, rawUi);
            Check(uiCard.Events.SequenceEqual(new[] { "reconnect", "activate" }.Concat(SwitchSequence(32))),
                "SL1 flow must use the entered keys for all sectors without personalization.");
            Check(messages.All(m => !m.Contains(new string('F', 32)) && !m.Contains(new string('0', 32))), "Logs must not contain entered key values.");
        }
        card = new SwitchCard(zeroKeys);
        CardPerso.SwitchAll2KbSectorsToSL1SL3Mix(new MifarePlusController(card));
        Check(card.Verified == 32, "Zero-default keys must work for all 32 sectors.");

        foreach (bool early09 in new[] { false, true })
        foreach (bool raw09 in new[] { false, true })
        {
            card = new SwitchCard(keys) { Return09AtStart = early09, AllowRaw = raw09 };
            card.AlreadySwitched.UnionWith(new[] { 0, 7, 31 });
            var messages = new List<string>();
            CardPerso.SwitchAll2KbSectorsToSL1SL3Mix(new MifarePlusController(card), keys, messages.Add, raw09);
            Check(card.Verified == 29, "09 sectors must be skipped; remaining sectors must verify their proof.");
            Check(card.Commands.Count(c => c[0] == 0x7A) == 32 && card.Commands.Count(c => c[0] == 0x78) == 31,
                "09 at either authentication step must continue with a reset before the next sector.");
            Check(messages.Count(m => m.Contains(": already switched (0x09)")) == 3 &&
                messages.Count(m => m.Contains(": switched to SL1SL3Mix; challenge verified")) == 29,
                "Every sector must have its own accurate result log.");
            Check(messages[^1] == "Sector results: 29 switched and verified, 3 already switched (0x09), 32 processed",
                "Summary must distinguish skipped sectors from verified sectors.");
        }
        card = new SwitchCard(keys);
        card.AlreadySwitched.UnionWith(Enumerable.Range(0, 32));
        var alreadyLogs = new List<string>();
        CardPerso.SwitchAll2KbSectorsToSL1SL3Mix(new MifarePlusController(card), keys, alreadyLogs.Add);
        Check(card.Verified == 0 && alreadyLogs.Count(m => m.Contains(": already switched (0x09)")) == 32,
            "Repeating a fully switched card must process all sectors without claiming new proofs.");

        // Generic command supports explicitly requested SL3, but no issuing helper selects it.
        card = new SwitchCard(keys);
        new MifarePlusController(card).AuthenticateSectorSwitch(SectorSwitchTarget.SL3,
            keys["L3SECTORSWITCH"], new[] { new SectorKeyB(3, keys["SECTOR3"]) });
        Check(card.Commands[0][1] == 6 && card.Verified == 1, "Explicit SL3 target must use 9006.");

        foreach (var fault in new[] { "bad-proof", "first-status", "last-status", "short-first", "short-last", "reset", "reset09" })
        {
            card = new SwitchCard(keys) { Fault = fault };
            try
            {
                CardPerso.SwitchAll2KbSectorsToSL1SL3Mix(new MifarePlusController(card), keys);
                throw new Exception($"Accepted fault: {fault}");
            }
            catch (MifarePlusException ex)
            {
                if (fault is "first-status" or "last-status")
                {
                    Check(ex is SectorSwitchResponseException response && response.Command == (fault == "first-status" ? 0x7A : 0x72),
                        "Status error must identify the failing authentication command.");
                    Check(ex.Message.Contains(fault == "first-status" ? "initial challenge" : "continuation"),
                        "UI diagnostic must identify the authentication phase.");
                }
            }
            Check(card.Commands.Count <= (fault.StartsWith("reset") ? 3 : 2), "Failed exchange must stop before next sector.");
        }

        foreach (var sectors in new[] { Array.Empty<int>(), new[] { 0, 0 }, new[] { -1 }, new[] { 32 } })
        {
            card = new SwitchCard(keys);
            try
            {
                CardPerso.SwitchSectorsToSL1SL3Mix(new MifarePlusController(card), sectors, keys);
                throw new Exception("Invalid sector selection accepted.");
            }
            catch (ArgumentException) { }
            Check(card.Commands.Count == 0, "Invalid input must fail before I/O.");
        }
        var invalidKeys = new Dictionary<string, byte[]>(keys) { ["SECTOR31"] = new byte[15] };
        card = new SwitchCard(keys);
        try
        {
            CardPerso.SwitchAll2KbSectorsToSL1SL3Mix(new MifarePlusController(card), invalidKeys);
            throw new Exception("Invalid second-batch key accepted.");
        }
        catch (ArgumentException) { }
        Check(card.Commands.Count == 0, "All keys must be validated before the first batch.");

        card = new SwitchCard(keys);
        try
        {
            new MifarePlusController(card).AuthenticateSectorSwitch(SectorSwitchTarget.SL1SL3Mix,
                keys["MIXSECTORSWITCH"], Enumerable.Range(0, 32).Select(s => new SectorKeyB(s, keys[$"SECTOR{s}"])).ToArray());
            throw new Exception("32 sectors accepted in one 2KB command.");
        }
        catch (ArgumentException) { }
        Check(card.Commands.Count == 0, "Per-command limit must be checked before I/O.");

        foreach (var (useDefaults, useRaw) in new[] { (false, true), (true, true), (false, false) })
        {
            var issuing = new IssuingCard(useDefaults ? zeroKeys : keys) { ExpectRawSwitching = useRaw };
            CardPerso.Issue2KbSL1SL3Mix(new MifarePlusController(issuing), useDefaults ? null : keys, useRaw: useRaw);
            Check(issuing.Events.Count(e => e == "write") == 70, "Issuing must write 64 sector keys, five control keys, and B000.");
            Check(issuing.Events.Skip(70).SequenceEqual(new[] { "commit", "reconnect", "activate" }.Concat(SwitchSequence(32))),
                "Issuing must commit, reconnect, activate ISO-4, and switch all sectors individually.");
        }
        foreach (var fault in new[] { "write", "commit", "reconnect", "activate" })
        {
            var issuing = new IssuingCard(keys) { Fault = fault };
            try
            {
                CardPerso.Issue2KbSL1SL3Mix(new MifarePlusController(issuing), keys);
                throw new Exception($"Issuing accepted {fault} failure.");
            }
            catch (MifarePlusException) { }
            Check(issuing.Events[^1] == fault, "Issuing must stop at the failed stage.");
        }

        foreach (byte sak in new byte[] { 0x08, 0x18, 0x20 })
        {
            var issuing = new IssuingCard(zeroKeys) { InitialSak = sak };
            CardPerso.Issue2KbSL1SL3MixFromCurrentState(new MifarePlusController(issuing));
            Check(issuing.Events[0] == "detect", "Auto flow must inspect activation before mutating the card.");
            if (sak == 0x20)
                Check(issuing.Events.Skip(71).SequenceEqual(new[] { "commit", "reconnect", "activate" }.Concat(SwitchSequence(32))),
                    "Auto SL0 flow must commit and complete sector switching after detection and writes.");
            else
                Check(issuing.Events.SequenceEqual(new[] { "detect", "reconnect", "activate" }.Concat(SwitchSequence(32))),
                    "Auto SL1 flow must continue without rewriting keys or committing.");
        }
        var unsupported = new IssuingCard(zeroKeys) { InitialSak = 0x00 };
        try
        {
            CardPerso.Issue2KbSL1SL3MixFromCurrentState(new MifarePlusController(unsupported));
            throw new Exception("Unsupported card accepted.");
        }
        catch (MifarePlusException) { }
        Check(unsupported.Events.SequenceEqual(new[] { "detect" }), "Unsupported card must not be modified.");

        var sl3Candidate = new IssuingCard(zeroKeys) { InitialSak = 0x20, Fault = "write" };
        try
        {
            CardPerso.Issue2KbSL1SL3MixFromCurrentState(new MifarePlusController(sl3Candidate));
            throw new Exception("Rejected SL0 command treated as success.");
        }
        catch (InvalidResponseStatusException) { }
        Check(sl3Candidate.Events.SequenceEqual(new[] { "detect", "write" }), "A failed SL0 probe must not commit or switch sectors.");

        foreach (bool legacy in new[] { false, true })
        {
            var reader = new IssuingCard(zeroKeys) { InitialSak = 0x18, LegacyStatus = legacy };
            var picc = new MifarePlusController(reader).GetPiccInformation();
            Check(picc.Sak == 0x18 && picc.Uid!.SequenceEqual(Convert.FromHexString("04010203040500")),
                "PICC parser must accept both status formats without losing a zero UID byte.");
        }
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static IEnumerable<string> SwitchSequence(int count) => Enumerable.Range(0, count)
        .SelectMany(i => i == 0 ? new[] { "7A", "72" } : new[] { "78", "7A", "72" });

    private sealed class IssuingCard(IDictionary<string, byte[]> keys) : IMifarePlusChannel
    {
        private readonly SwitchCard card = new(keys);
        public List<string> Events { get; } = new();
        public string? Fault { get; init; }
        public bool ExpectRawSwitching { get; init; } = true;
        public byte? InitialSak { get; init; }
        public bool LegacyStatus { get; init; }
        private bool activated;

        public byte[] Transceive(byte[] command)
        {
            if (command[0] is 0xA8 or 0xAA)
            {
                string stage = command[0] == 0xA8 ? "write" : "commit";
                Check(!activated && !Events.Contains("reconnect"), "Personalization must precede reconnect.");
                if (stage == "commit")
                    Check(Events.Count(e => e == "write") == 70, "Commit must follow all personalization writes.");
                Events.Add(stage);
                return new byte[] { Fault == stage ? (stage == "write" ? (byte)0x0B : (byte)0x06) : (byte)0x90 };
            }
            Check(activated, "Sector switching must follow successful activation.");
            Check(!ExpectRawSwitching, "Expected raw sector switching after activation.");
            Events.Add(command[0].ToString("X2"));
            return card.Transceive(command);
        }

        public void ReconnectCard()
        {
            Check(Events.LastOrDefault() == "commit" ||
                (InitialSak is 0x08 or 0x18 && (Events.Count == 0 || Events.SequenceEqual(new[] { "detect" }))),
                "Reconnect must follow commit or SL1 detection.");
            Events.Add("reconnect");
            if (Fault == "reconnect") throw new MifarePlusException("Simulated reconnect failure.");
        }

        public byte[] TransceiveRaw(byte[] apdu)
        {
            if (apdu.SequenceEqual(Convert.FromHexString("FFCA000200")))
            {
                Check(InitialSak.HasValue && Events.Count == 0, "Unexpected PICC inspection.");
                Events.Add("detect");
                return Convert.FromHexString("040004010203040500")
                    .Concat(new byte[] { InitialSak!.Value })
                    .Concat(LegacyStatus ? new byte[] { 0x90 } : new byte[] { 0x90, 0x00 }).ToArray();
            }
            if (apdu[0] is 0x7A or 0x72 or 0x78)
            {
                Check(activated && ExpectRawSwitching, "Unexpected raw native command before activation or in wrapped mode.");
                Events.Add(apdu[0].ToString("X2"));
                return card.Transceive(apdu);
            }
            Check(Events[^1] == "reconnect", "Activation must follow reconnect.");
            Check(apdu.SequenceEqual(Convert.FromHexString("FFC20002048F02000400")), "Incorrect activation APDU.");
            Events.Add("activate");
            activated = Fault != "activate";
            return Convert.FromHexString(activated ? "C0030090009000" : "C003006A819000");
        }
    }

    // Independent PICC simulator: only BCL crypto, no production encryption helpers.
    private sealed class SwitchCard(IDictionary<string, byte[]> keySet) : IMifarePlusChannel
    {
        public List<byte[]> Commands { get; } = new();
        public string? Fault { get; init; }
        public int Verified { get; private set; }
        public HashSet<int> AlreadySwitched { get; } = new();
        public bool Return09AtStart { get; init; }
        public bool AllowRaw { get; init; }
        private int currentSector;
        private byte[][]? activeKeys;
        private readonly byte[] rndB = Convert.FromHexString("027BF96807E9AD960D41828A94F8CA72");

        public byte[] Transceive(byte[] command)
        {
            Commands.Add((byte[])command.Clone());
            if (command[0] == 0x78)
            {
                activeKeys = null;
                return new byte[] { Fault == "reset" ? (byte)0x0B : Fault == "reset09" ? (byte)0x09 : (byte)0x90 };
            }
            if (command[0] == 0x7A)
            {
                Check(activeKeys is null, "Next batch requires authentication reset.");
                if (Fault == "first-status") return new byte[] { 0x0B };
                if (Fault == "short-first") return new byte[] { 0x90, 0x00 };
                int count = command[3];
                Check(command.Length == 4 + 2 * count && count is >= 1 and <= 31, "Invalid request frame.");
                currentSector = ((command[4] | (command[5] << 8)) - 0x4001) / 2;
                if (Return09AtStart && AlreadySwitched.Contains(currentSector))
                    return new byte[] { 0x09 };
                var names = new List<string> { command[1] == 7 ? "MIXSECTORSWITCH" : "L3SECTORSWITCH" };
                for (int i = 0; i < count; i++)
                {
                    int address = command[4 + 2 * i] | (command[5 + 2 * i] << 8);
                    Check(address is >= 0x4001 and <= 0x403F && (address & 1) == 1, "Invalid Key B address.");
                    names.Add($"SECTOR{(address - 0x4001) / 2}");
                }
                activeKeys = names.Select(n => keySet[n]).ToArray();
                return Reply(Encrypt(rndB, activeKeys));
            }
            Check(command[0] == 0x72 && command.Length == 33 && activeKeys is not null, "Invalid continuation.");
            if (Fault == "last-status") return new byte[] { 0x06 };
            if (Fault == "short-last") return new byte[] { 0x90 };
            var plain = command[1..];
            foreach (var key in activeKeys!.Reverse())
            {
                using var aes = Aes.Create();
                aes.Key = key;
                plain = aes.DecryptCbc(plain, new byte[16], PaddingMode.None);
            }
            var rotatedB = rndB.Skip(1).Append(rndB[0]).ToArray();
            Check(plain[16..].SequenceEqual(rotatedB), "Datasheet continuation encryption order or RndB rotation incorrect.");
            if (AlreadySwitched.Contains(currentSector)) return new byte[] { 0x09 };
            var rotatedA = plain.Skip(1).Take(15).Append(plain[0]).ToArray();
            if (Fault == "bad-proof") rotatedA[0] ^= 1;
            Verified++;
            AlreadySwitched.Add(currentSector);
            return Reply(Encrypt(rotatedA, activeKeys!));
        }

        private static byte[] Encrypt(byte[] data, byte[][] keys)
        {
            foreach (var key in keys)
            {
                using var aes = Aes.Create();
                aes.Key = key;
                data = aes.EncryptCbc(data, new byte[16], PaddingMode.None);
            }
            return data;
        }

        private static byte[] Reply(byte[] data) => new byte[] { 0x90 }.Concat(data).ToArray();
        public byte[] TransceiveRaw(byte[] apdu) => AllowRaw ? Transceive(apdu) : throw new Exception("Unexpected raw I/O.");
        public void ReconnectCard() => throw new Exception("Unexpected reconnect.");
    }
}
