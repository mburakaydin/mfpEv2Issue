using System;
using System.Collections.Generic;

namespace MfpEv2Issue
{
    public static class CardPerso
    {
        public static void SL0Operations(
            MifarePlusController ctrl,
            IDictionary<string, byte[]> keySet,
            Action<string>? log)
        {
            ArgumentNullException.ThrowIfNull(ctrl);
            ArgumentNullException.ThrowIfNull(keySet);
            var required = Enumerable.Range(0, 16).Select(i => $"SECTOR{i}")
                .Concat(new[] { "MASTER", "CONF", "L3SWITCH" });
            foreach (var name in required)
            {
                if (!keySet.TryGetValue(name, out var key) || key is null || key.Length != 16)
                    throw new ArgumentException($"Supply a 16-byte key for {name}.", nameof(keySet));
            }
            var writes = new List<(ushort bnr, byte[] key)>();

            void AddSector(string name, ushort b0, ushort b1)
            {
                if (keySet.TryGetValue(name, out var key))
                {
                    writes.Add((b0, key));
                    writes.Add((b1, key));
                }
            }

            AddSector("SECTOR0", 0x4000, 0x4001);
            AddSector("SECTOR1", 0x4002, 0x4003);
            AddSector("SECTOR2", 0x4004, 0x4005);
            AddSector("SECTOR3", 0x4006, 0x4007);
            AddSector("SECTOR4", 0x4008, 0x4009);
            AddSector("SECTOR5", 0x400A, 0x400B);
            AddSector("SECTOR6", 0x400C, 0x400D);
            AddSector("SECTOR7", 0x400E, 0x400F);
            AddSector("SECTOR8", 0x4010, 0x4011);
            AddSector("SECTOR9", 0x4012, 0x4013);
            AddSector("SECTOR10", 0x4014, 0x4015);
            AddSector("SECTOR11", 0x4016, 0x4017);
            AddSector("SECTOR12", 0x4018, 0x4019);
            AddSector("SECTOR13", 0x401A, 0x401B);
            AddSector("SECTOR14", 0x401C, 0x401D);
            AddSector("SECTOR15", 0x401E, 0x401F);

            if (keySet.TryGetValue("MASTER", out var m))
                writes.Add((0x9000, m));
            if (keySet.TryGetValue("CONF", out var c))
                writes.Add((0x9001, c));
            if (keySet.TryGetValue("L3SWITCH", out var l3))
                writes.Add((0x9003, l3));

            foreach (var (bnr, key) in writes)
            {
                log?.Invoke($"WritePerso bNr=0x{bnr:X4}");
                ctrl.WritePerso(bnr, key);
            }

            ctrl.CommitPerso();
            log?.Invoke("CommitPerso OK");
        }

        public static void SL1toSL3(
            MifarePlusController ctrl,
            byte[] l3SwitchKey,
            Action<string>? log)
        {
            ctrl.ResetCard();
            log?.Invoke("Card reset OK");

            var activation = ctrl.Iso14443_4A_Active();
            if (!activation.IsOk)
                throw new MifarePlusException("ISO 14443-4A activation failed.");
            ctrl.FirstAuth(l3SwitchKey, 0x9003);
        }
    }
}
