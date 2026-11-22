using System;
using System.Collections.Generic;

namespace MfpEv2Issue
{
    public static class CardPerso
    {
        /// <summary>
        /// Issues a 2KB card presented in SL0: WritePerso keys and B000, CommitPerso,
        /// reconnect/reset, activate ISO 14443-4A, then switch all sectors to mixed mode.
        /// Uses zero keys unless a complete 32-sector key set is supplied.
        /// By default sends sector-switch/reset commands raw after activation, matching pcMfpIssue.
        /// Set useRaw=false for readers requiring wrapped native commands instead.
        /// Reader must support the activation APDU and perform the required RF reset.
        /// Stops on the first failure; completed card changes cannot be rolled back.
        /// </summary>
        public static void Issue2KbSL1SL3Mix(
            MifarePlusController ctrl,
            IDictionary<string, byte[]>? keySet = null,
            Action<string>? log = null,
            bool useRaw = true)
        {
            ArgumentNullException.ThrowIfNull(ctrl);
            keySet ??= MifarePlusKeys.CreateDefaultKeySet();
            SL0Operations(ctrl, keySet, log, sectorCount: 32);

            Continue2KbSL1ToSL1SL3Mix(ctrl, keySet, log, useRaw);
        }

        /// <summary>
        /// Uses reader ATQA/UID/SAK data to choose the reference application's flow.
        /// 08/18 are SL1-compatible hints: skip SL0 writes. 20 is ambiguous (SL0 or SL3,
        /// or customized SL1): attempt SL0 personalization, whose command status is authoritative.
        /// SAK alone does not prove card type or security level. Errors are never treated as success.
        /// </summary>
        public static void Issue2KbSL1SL3MixFromCurrentState(
            MifarePlusController ctrl,
            IDictionary<string, byte[]>? keySet = null,
            Action<string>? log = null,
            bool useRaw = true)
        {
            ArgumentNullException.ThrowIfNull(ctrl);
            var card = ctrl.GetPiccInformation();
            if (!card.IsTypeA || card.Uid is null || card.Sak is null)
                throw new MifarePlusException("Expected an ISO 14443 Type A card with UID and SAK.");
            log?.Invoke($"UID={Convert.ToHexString(card.Uid)} ATQA={Convert.ToHexString(card.Atqa!)} SAK={card.Sak:X2}");
            if (card.Sak is 0x08 or 0x18)
            {
                log?.Invoke("SL1-compatible activation detected; skipping SL0 key/configuration writes and CommitPerso.");
                Continue2KbSL1ToSL1SL3Mix(ctrl, keySet, log, useRaw);
            }
            else if (card.Sak == 0x20)
            {
                log?.Invoke("ISO-4 activation detected (SAK 20); attempting SL0 personalization. Unsupported state will stop the flow.");
                Issue2KbSL1SL3Mix(ctrl, keySet, log, useRaw);
            }
            else
                throw new MifarePlusException($"Unsupported activation SAK {card.Sak:X2}; no personalization attempted.");
        }

        /// <summary>Continues an existing SL1 card without rewriting keys/configuration or committing.</summary>
        public static void Continue2KbSL1ToSL1SL3Mix(
            MifarePlusController ctrl,
            IDictionary<string, byte[]>? keySet = null,
            Action<string>? log = null,
            bool useRaw = true)
        {
            ArgumentNullException.ThrowIfNull(ctrl);
            keySet ??= MifarePlusKeys.CreateDefaultKeySet();
            // Preflight before reconnect or activation; existing cards must already have these keys.
            foreach (var name in Enumerable.Range(0, 32).Select(s => $"SECTOR{s}").Append("MIXSECTORSWITCH"))
                if (!keySet.TryGetValue(name, out var key) || key is null || key.Length != 16)
                    throw new ArgumentException($"Supply a 16-byte key for {name}.", nameof(keySet));

            ctrl.ResetCard();
            log?.Invoke("Card reconnected/reset in SL1 flow");
            var activation = ctrl.Iso14443_4A_Active();
            if (!activation.IsOk)
                throw new MifarePlusException("ISO 14443-4A activation failed in SL1 flow.");
            log?.Invoke("ISO 14443-4A activation OK");

            SwitchAll2KbSectorsToSL1SL3Mix(ctrl, keySet, log, useRaw);
            log?.Invoke("2KB SL1SL3Mix issuing complete");
        }

        /// <summary>Writes a zero-key mixed-mode profile in SL0, then commits personalization.</summary>
        public static void SL0Operations(
            MifarePlusController ctrl,
            Action<string>? log = null,
            int sectorCount = 32)
        {
            SL0Operations(ctrl, MifarePlusKeys.CreateDefaultKeySet(sectorCount), log,
                sectorCount: sectorCount);
        }

        /// <summary>Writes all keys and B000 in SL0, then commits. Stops at the first failed write.</summary>
        public static void SL0Operations(
            MifarePlusController ctrl,
            IDictionary<string, byte[]> keySet,
            Action<string>? log,
            byte[]? configurationBlock = null,
            int sectorCount = 32)
        {
            ArgumentNullException.ThrowIfNull(ctrl);
            ArgumentNullException.ThrowIfNull(keySet);
            var block = configurationBlock is null
                ? MifarePlusConfiguration.CreateSL1SL3MixBlock()
                : (byte[])configurationBlock.Clone();
            if (block.Length != 16)
                throw new ArgumentException("Configuration block must be exactly 16 bytes.", nameof(configurationBlock));

            MifarePlusKeys.WriteKeys(ctrl, keySet, log, sectorCount);
            MifarePlusConfiguration.WriteConfigurationBlock(ctrl, block, log);
            ctrl.CommitPerso();
            log?.Invoke("CommitPerso OK");
        }
        /// <summary>
        /// Switches all 32 sectors of a 2KB card to mixed mode with zero default keys.
        /// Card must already be in SL1, activated to ISO 14443-4, with SectorSwitch enabled.
        /// This changes sector levels; use FirstAuth afterward for normal AES access.
        /// </summary>
        public static void SwitchAll2KbSectorsToSL1SL3Mix(
            MifarePlusController ctrl,
            IDictionary<string, byte[]>? keySet = null,
            Action<string>? log = null,
            bool useRaw = false)
            => SwitchSectorsToSL1SL3Mix(ctrl, Enumerable.Range(0, 32), keySet, log, useRaw);

        /// <summary>
        /// Switches selected 2KB sectors individually; never selects the SL3 switch key.
        /// For the tested issuing workflow, native 09 is treated as already switched and skipped.
        /// Other failures stop the flow. Skipped sectors have not supplied a verified final proof.
        /// </summary>
        public static void SwitchSectorsToSL1SL3Mix(
            MifarePlusController ctrl,
            IEnumerable<int> sectors,
            IDictionary<string, byte[]>? keySet = null,
            Action<string>? log = null,
            bool useRaw = false)
        {
            ArgumentNullException.ThrowIfNull(ctrl);
            ArgumentNullException.ThrowIfNull(sectors);
            var selected = sectors.ToArray();
            if (selected.Length < 1 || selected.Length > 32 || selected.Distinct().Count() != selected.Length ||
                selected.Any(s => s < 0 || s >= 32))
                throw new ArgumentException("Select distinct sectors from 0 through 31.", nameof(sectors));
            keySet ??= MifarePlusKeys.CreateDefaultKeySet();
            byte[] GetKey(string name)
            {
                if (!keySet.TryGetValue(name, out var key) || key is null || key.Length != 16)
                    throw new ArgumentException($"Supply a 16-byte key for {name}.", nameof(keySet));
                return (byte[])key.Clone();
            }
            // Validate every key before sending anything.
            var switchKey = GetKey("MIXSECTORSWITCH");
            var entries = selected.Select(s => new SectorKeyB(s, GetKey($"SECTOR{s}"))).ToArray();
            int switched = 0;
            int alreadySwitched = 0;
            for (int index = 0; index < entries.Length; index++)
            {
                var entry = entries[index];
                try
                {
                    // Reset even after 09, so the next request starts with clean authentication state.
                    if (index > 0)
                        ctrl.ResetAuthentication(useRaw);
                    log?.Invoke($"Sector {entry.Sector:D2}: switching to SL1SL3Mix (Key B 0x{0x4001 + 2 * entry.Sector:X4})");
                    try
                    {
                        ctrl.AuthenticateSectorSwitch(SectorSwitchTarget.SL1SL3Mix, switchKey,
                            new[] { entry }, useRaw: useRaw);
                        switched++;
                        log?.Invoke($"Sector {entry.Sector:D2}: switched to SL1SL3Mix; challenge verified");
                    }
                    catch (InvalidResponseStatusException ex) when (ex.Status == 0x09 && ex.Status2 is null)
                    {
                        alreadySwitched++;
                        log?.Invoke($"Sector {entry.Sector:D2}: already switched (0x09); continuing");
                    }
                }
                catch (Exception ex)
                {
                    log?.Invoke($"Sector {entry.Sector:D2}: FAILED — {ex.Message}");
                    throw;
                }
            }
            log?.Invoke($"Sector results: {switched} switched and verified, {alreadySwitched} already switched (0x09), {entries.Length} processed");
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
