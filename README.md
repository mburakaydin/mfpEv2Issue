# mfpEv2Issue

Independent C# starting point for a MIFARE Plus EV2 issuing application. Includes a reusable controller, PC/SC transport, and a personalization helper. Requires the .NET 10 SDK and a compatible PC/SC reader and driver.

## Build and reader discovery

```sh
dotnet build MfpEv2Issue.slnx
dotnet run --project tests/IssuingChecks
dotnet run --project examples/ReaderInfo
```

The example only lists readers. It does not write to cards.

## Integrating issuing

Reference `src/MfpEv2Issue/MfpEv2Issue.csproj` from your application. Supply your own `IMifarePlusChannel`, or use `PcscMifarePlusChannel` if the reader supports the ISO 7816 native-command wrapping used here. Raw APDU methods return complete responses including status bytes; native methods return native status followed by payload.

`CardPerso.SL0Operations(controller, keys, log)` writes the 16-sector profile and commits personalization. Supply AES-128 key bytes under `SECTOR0` through `SECTOR15`, `MASTER`, `CONF`, and `L3SWITCH`. All keys are checked before the first write. The helper stops on a failed write; it does not roll back earlier writes.

Retrieve keys at runtime from your application's secure key provider. No master keys, UID diversification scheme, customer APIs, account data, or production profiles are included. Do not log APDU payloads containing key material. Choose a key management and diversification scheme for your deployment.

## Validation status

This is an extracted development starting point, not a hardware-qualified issuing product. The controller includes inherited authentication, secure-read, and reader-specific transparent-exchange code. Reader firmware, native-command wrapping, card size, security level, and EV2 configuration must be validated with your hardware before issuing. The bundled helper covers a 16-sector profile; other card layouts need an explicit profile implementation. Personalization commit and security-level changes can permanently change a card's state.

Automated checks exercise personalization validation, command layout, and failure handling using a fake channel. They do not establish cryptographic interoperability or successful physical card issuing.
