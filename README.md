# mfpEv2Issue

Independent C# starting point for a MIFARE Plus EV2 issuing application. Includes a reusable controller, PC/SC transport, and a personalization helper. Requires the .NET 10 SDK and a compatible PC/SC reader and driver.

## Build and reader discovery

```sh
dotnet build MfpEv2Issue.slnx
dotnet run --project tests/IssuingChecks
dotnet run --project examples/ReaderInfo
```

The example only lists readers. It does not write to cards.

## Windows issuing UI

In Visual Studio, open `MfpEv2Issue.slnx`, then right-click **IssueUi** in Solution Explorer and choose **Set as Startup Project**. Press F5. `ReaderInfo` and `IssuingChecks` are console programs, so selecting either launches a console. A shared `Issue UI` profile is supplied in `MfpEv2Issue.slnLaunch` for Visual Studio versions supporting solution launch profiles; existing user startup selections may still need changing. The UI project is configured as `WinExe` with Windows Forms.

```sh
dotnet run --project examples/IssueUi
```

Select the contactless reader (the UI prefers a name containing `PICC` when available), place a MIFARE Plus EV2 2KB card on it, then click **Issue card**. The UI runs reader operations in the background, displays timestamped progress and errors, and offers **Refresh**, **Clear logs**, and **Save logs**. Its profile uses all 32 sectors and the mixed-mode configuration. The default sector-key field and per-sector overrides configure sector AES keys. Separate inputs configure `9000` (Master), `9001` (Configuration), `9003` (SL3 Switch), `9006` (SL3 Sector Switch), and `9007` (Mixed-mode Sector Switch). The default sector key initially contains 16 bytes of FF; the five control-key fields initially contain zero keys. Preset buttons have been removed; key values are edited directly. Each key accepts up to 16 bytes (32 hex digits), in whole byte pairs. Short values are padded on the right with zero bytes: `A1B2` becomes `A1B2` followed by 28 zero digits. Blank main key fields become zero keys; blank override rows still inherit the default sector key. The main edit boxes accept only hex input and limit it to 32 digits, normalize when focus leaves, and reject oversized pastes. Whitespace and an optional `0x` prefix are accepted when pasting or constructing a key profile. Validation happens before opening the reader. Inputs are disabled while issuing, and key values are not written to logs or saved as settings. It does not start issuing automatically or log key payloads.

The default **Auto (activation SAK)** flow mirrors the reference application's activation hints. SAK `08` or `18` skips SL0 key/configuration writes and CommitPerso, then reconnects, activates ISO 14443-4, and switches all sectors to mixed mode. SAK `20` is ambiguous: it attempts the SL0 flow, and any rejected WritePerso stops the operation as an error. SAK is not proof of chip model, capacity, or security level; SL3 and customized SL1 cards can also advertise `20`. Unknown SAKs and Type B cards stop without personalization. A `0B` status is never treated as successful issuing.

Choose **Start from SL0** or **Continue from SL1** explicitly when the reader cannot return ATQA/UID/SAK through the reference `FF CA 00 02 00` command, or when activation parameters have been customized. An existing SL1 card must already have `SectorSwitch` enabled, ISO-4 activation enabled, and switching/sector keys matching the inputs; the SL1 path does not overwrite them. The **Raw commands after activation** option defaults on to match pcMfpIssue; uncheck it for wrapped transport. In SL1 the sector input supplies AES Key B for every sector. In SL0 it is written to both AES Key A and Key B, and the switch input is written to `9007`; all five control keys are written from their corresponding fields.

## Integrating issuing

The UI displays the card UID below the reader selector and logs it before card changes, in every flow. It reads the UID using `FF CA 00 00 00` and checks for a 4, 7, or 10-byte value. The display resets when refreshing or changing readers; a failed UID read stops issuing before personalization.

The UI also supports **Per-sector overrides**: blank rows use the default sector-key field, while entered keys (padded to 16 bytes if short) take precedence for that sector. Both SL0 personalization (AES Key A and B) and SL1 authentication (AES Key B) use the resolved profile. Logs list overridden sector numbers without key values. Authentication status errors now identify whether `7A` (initial challenge) or `72` (continuation) failed.

For a 2KB card placed on the reader in SL0, use the complete issuing flow:

```csharp
CardPerso.Issue2KbSL1SL3Mix(controller); // Zero default keys.
// Or: CardPerso.Issue2KbSL1SL3Mix(controller, keys, log);
```

This writes all 32 sectors' AES keys, the five control keys, and `B000` with `WritePerso` (`A8`), then calls `CommitPerso` (`AA`). It reconnects/resets the card, calls `Iso14443_4A_Active()`, checks activation success, and calls `SwitchAll2KbSectorsToSL1SL3Mix`. Any failure stops the sequence. It never uses the global SL3 switch. The reader must support the activation APDU, native command transport, and required RF reset; the current PC/SC reconnect requests a reset but does not prove that the reader performs a full RF power cycle.

The reference `mfpSystemIssue/pcMfpTest` application (`pcMfpIssue.csproj`) uses `FirstAuth(..., 0x9003, true)` after activation. This project's complete issuing flow instead uses AuthenticateSectorSwitch with `9007` and follows the same raw transport choice by default: `7A`, `72`, and the inter-sector `78` go directly through `TransceiveRaw`. This requires a reader mode returning native status first. Pass `useRaw: false` to `Issue2KbSL1SL3Mix` for wrapped native transport. Standalone sector-switch helpers retain wrapped transport by default; pass `useRaw: true` when invoking them directly on the reference reader's raw path. Changing the key number in FirstAuth alone is not equivalent to AuthenticateSectorSwitch.

Reference `src/MfpEv2Issue/MfpEv2Issue.csproj` from your application. Supply your own `IMifarePlusChannel`, or use `PcscMifarePlusChannel` if the reader supports the ISO 7816 native-command wrapping used here. Raw APDU methods return complete responses including status bytes; native methods return native status followed by payload.

`CardPerso.SL0Operations(controller)` writes the default 32-sector 2KB SL0 profile using zero-filled AES-128 keys, writes `B000`, then commits personalization. These keys are development defaults.

For custom keys, call `CardPerso.SL0Operations(controller, keys, log)`. Supply `SECTOR0` through `SECTOR31` (each used for both AES Key A and Key B), `MASTER` (`9000`), `CONF` (`9001`), `L3SWITCH` (`9003`), `L3SECTORSWITCH` (`9006`), and `MIXSECTORSWITCH` (`9007`). `MifarePlusKeys.CreateDefaultKeySet()` creates independent zero-filled keys. Required keys and configuration length are checked before the first write. Failed writes stop the sequence without rolling back earlier writes.

`MifarePlusKeys.WriteKeys(controller, keys)` and `MifarePlusConfiguration.WriteConfigurationBlock(controller)` are standalone SL0 writers that do not commit. The default `B000` payload is `00 0F 00 AA AA 01 55 00 00 00 00 00 00 00 00 00`, using the AN12784 mixed-mode setup and datasheet Rev. 3.4 Table 79 activation selectors. It enables KeySystemDataWrite (byte 3), SectorSwitch (byte 4), SL1 activation parameters (byte 5 = `01`), and ISO 14443-4 activation (byte 6 = `55`). The `00` selector value means no change, not an explicit SL1 or ISO-4 selection. To preserve other fields, pass your known 16-byte block to `CreateSL1SL3MixBlock(baseBlock)`, then pass the result as `configurationBlock` to `SL0Operations` or `WriteConfigurationBlock`. This prepares sector switching; it does not switch individual sectors into mixed mode.

The optional `sectorCount` selects contiguous AES sector keys starting at `4000`, two per sector. It defaults to 32 (`4000` through `403F`) and accepts up to 56 (`406F`); select a count supported by your target card. Use the same count when creating and writing a key set. Pass `sectorCount: 16` explicitly for the earlier 16-sector profile.

## Switching 2KB sectors to mixed mode

After SL0 personalization, the card must be in SL1 with `SectorSwitch = AA`. Activate ISO 14443-4 using the appropriate reader transport before calling:

```csharp
// All 32 sectors, using the zero default switching key and sector Key Bs:
CardPerso.SwitchAll2KbSectorsToSL1SL3Mix(controller);

// Alternatively, selected sectors using a supplied key set:
CardPerso.SwitchSectorsToSL1SL3Mix(controller, new[] { 0, 7, 31 }, keys);
```

These helpers always use `9007` and process sectors individually in the requested order. Each `7A` request contains exactly one sector. ResetAuthentication (`78`) is sent between sectors, including after a skipped sector. Native status `09` from either `7A` or `72` is logged as already switched and processing continues, following the observed repeat-switch behavior in the supplied RFIDDiscover trace. Other errors, malformed replies, failed proof verification, and reset failures stop the flow. The low-level AuthenticateSectorSwitch method still throws on `09`; this continuation policy belongs to the mixed-mode helper. All selected keys are validated before any exchange. Completed sector changes are not rolled back.

The low-level `controller.AuthenticateSectorSwitch(target, switchingKey, sectorKeyBs)` also accepts an explicit `SectorSwitchTarget.SL3` (`9006`) for separate callers. Each entry is `new SectorKeyB(sectorNumber, keyBBytes)`. Its default card size is 32 sectors; `cardSectorCount: 40` selects the 4KB limits. The implementation follows datasheet Rev. 3.4 Tables 34/35: encrypt with the switching key first and then sector Key Bs in request order, resetting the CBC IV to zero for each layer; decrypt in reverse key order. This intentionally follows the datasheet where the earlier application note differs.

AuthenticateSectorSwitch changes sector security levels and does not initialize the controller's normal secure messaging session. Authenticate with the appropriate sector AES key using `FirstAuth` before normal AES reads. Configuring mixed mode does not personalize Classic keys or sector access bits; those remain separate issuing steps. Byte 5 explicitly selects SL1 activation parameters for Classic-compatible discovery while byte 6 keeps ISO 14443-4 available for AES access. The zero ATQA/SAK override fields preserve the existing card parameters (including its factory SL1 SAK on an unmodified card); a supplied base block retains its custom ATQA/SAK fields. Perform a full RF power cycle after configuration changes before checking activation parameters. A PC/SC reconnect alone does not guarantee that power cycle.

Retrieve keys at runtime from your application's secure key provider. No master keys, UID diversification scheme, customer APIs, account data, or production profiles are included. Do not log APDU payloads containing key material. Choose a key management and diversification scheme for your deployment.

## Validation status

The supplied successful RFIDDiscover master-key (`9000`) trace is covered by fixed-vector checks for RndB decryption, CBC encryption of `RndA || RndB'`, final proof verification, TI, and both session keys. To match its short `70 00 90 00` request, call:

```csharp
var session = controller.FirstAuth(new byte[16], 0x9000,
    useRaw: true, pcdCapabilities: Array.Empty<byte>());
```

Omitting `pcdCapabilities` preserves the existing request containing six zero reader-capability bytes. Both modes and raw/wrapped transport selection are exercised with a simulated card. Master-key authentication remains separate from the `9007` sector-switch flow.

Two successful RFIDDiscover sector-switch traces with `9007 = 00…00` and sector Key B `FF…FF` are also fixed regression vectors. They cover Key B addresses `401F` and `4021` (zero-based sectors 15 and 16), both intermediate decryption/encryption layers, the complete 32-byte continuation, and the final rotated RndA proof. These distinct keys confirm switching-key-first encryption and reverse-order decryption. The library helpers retain zero-filled defaults; the UI initially selects FF sector keys and zero control keys.

This is an extracted development starting point, not a hardware-qualified issuing product. The controller includes inherited authentication, secure-read, and reader-specific transparent-exchange code. Reader firmware, native-command wrapping, card size, security level, and EV2 configuration must be validated with your hardware before issuing. The helper defaults to the 32-sector 2KB profile; other profiles require an explicit supported sector count. Personalization commit and security-level changes can permanently change a card's state.

Automated checks exercise personalization validation, command layout, and failure handling using a fake channel. A separate PICC simulator with distinct switching and sector keys checks layer order, challenge rotation, final proof rejection, selected-sector addressing, all-32-sector individual switching and already-switched retries, zero defaults, and malformed/error responses. They do not establish hardware interoperability or successful physical card issuing.

Per-sector results are streamed to the UI logs, followed by separate verified/skipped counts:

```text
Sector 00: switched to SL1SL3Mix; challenge verified
Sector 01: already switched (0x09); continuing
Sector results: 31 switched and verified, 1 already switched (0x09), 32 processed
```

A skipped `09` sector has not supplied a verified final challenge in this run. Treating `09` as already switched is the requested issuing policy for this card setup; the status can also represent other block/sector conditions according to the datasheet. The UI reports all sectors processed rather than claiming that skipped sectors were cryptographically verified.
