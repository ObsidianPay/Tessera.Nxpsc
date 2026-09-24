# Tessera.Nxpsc

.NET binding for [libnxpsc](https://github.com/ObsidianPay/libnxpsc), a C
library for programming NXP smartcards: MIFARE DESFire (EV1, EV2, EV3, Light),
NTAG 413 / 424 DNA and MIFARE Plus EV1 / EV2. Every public function of
libnxpsc's `nxpsc.h` is bound. libnxpsc does the command layer, secure
messaging, CMAC and AN10922 key diversification; this package adds a managed
API, key handling that zeroes key material, and a PC/SC transport.

| Package | What it is |
|---|---|
| `Tessera.Nxpsc` | The binding, the PC/SC transport, and libnxpsc's native library for `win-x64`, `linux-x64` and `osx-arm64` |
| `Tessera.Nxpsc.MockCard` | libnxpsc's mock card with state, for testing code without hardware. Test projects only (see below) |

## Install

The packages are published to GitHub Packages. GitHub's NuGet registry asks for
authentication even for public packages: a personal access token (classic) with
`read:packages`. Add a `nuget.config` next to your solution:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="github-obsidianpay" value="https://nuget.pkg.github.com/ObsidianPay/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org"><package pattern="*" /></packageSource>
    <packageSource key="github-obsidianpay"><package pattern="Tessera.Nxpsc*" /></packageSource>
  </packageSourceMapping>
</configuration>
```

and give it the token once, outside the repository:

```
dotnet nuget update source github-obsidianpay --username <github user> --password <token> --store-password-in-clear-text
```

(in GitHub Actions, `--password ${{ secrets.GITHUB_TOKEN }}` with `packages: read`). Then:

```
dotnet add package Tessera.Nxpsc
dotnet add package Tessera.Nxpsc.MockCard   # test projects only
```

Versions: a `vX.Y.Z` tag publishes `X.Y.Z`; every push to `master` publishes
`X.Y.Z-ci.<run>`.

## Use

```csharp
using Tessera.Nxpsc;

if (!NxpscLibrary.SelfTest())
    throw new InvalidOperationException("libnxpsc's crypto self test failed");

var reader = PcscTransport.ChooseReader(PcscTransport.ListReaders())
             ?? throw new InvalidOperationException("no contactless reader");
using var transport = PcscTransport.WaitForCard(reader, TimeSpan.FromSeconds(30));
using var card = NxpscCard.Open(transport);            // ISO-wrapped native commands, what PC/SC needs

Console.WriteLine(NxpscLibrary.CardTypeName(card.Identify()));

using var picc = NxpscKey.FactoryPiccMasterKey();
card.SelectApplication(0x000000);
card.Authenticate(0, picc);
foreach (var aid in card.GetApplicationIds())
    Console.WriteLine($"{aid:X6}");
```

- **Errors.** Every failure is an `NxpscException` with `Code` (libnxpsc's
  `nxpsc_error_t`), `CardStatus` (the DESFire status byte, for card errors) and
  `SessionLost`. The PICC drops secure messaging whenever it answers an
  in-session command with an error. Check `SessionLost` and authenticate again,
  rather than letting later commands fail in confusing ways.
- **Keys.** `NxpscKey` keeps key bytes in pinned memory, zeroes them on
  dispose, and never renders them. Native copies are wiped after every call.
- **Transports.** `ICardTransport` is libnxpsc's transceive callback. Return
  `false` only for a real transport failure, and pass card error statuses
  through untouched. `IUidTransport` and `IReselectTransport` are the optional
  callbacks. `PcscTransport` implements the transceive and UID parts over the
  `PCSC` package.
- **One-way operations** are marked in their docs: `SetPiccConfig` (format
  disable, random UID), `ChangeKeySettings` for some settings,
  `PlusCommitPerso`, `PlusPersonalizeUid`, `RestrictMfcUpdate`. Read the card
  manual before sending any of them to cards you want to keep.

## The mock card

`Tessera.Nxpsc.MockCard` wraps libnxpsc's own `tests/mockcard.c` in a small
stateful shim (`native/nxpsc_mockcard.c`). It remembers keys and applications,
and it runs real framing and real card-side crypto against the real host path.
Two things to know:

- libnxpsc's mock expects a fixed host challenge. Creating a `MockCard` sets
  libnxpsc's RNG to that fixed sequence **for the whole process**. From then on
  `NxpscCard.Open` refuses any transport that is not a mock. Keep it to test
  processes.
- It can't check what a `ChangeKey` cryptogram carried. Call
  `SetChangeKeyResult` to state what the changed key reads as. Proving a key
  change takes real hardware.

Error statuses are part of what the mock can get wrong. The ones libnxpsc's mock
returns are listed, with which a card has confirmed, in libnxpsc's
[hardware notes](https://github.com/ObsidianPay/libnxpsc/blob/master/docs/hardware-notes.md#statuses-the-mock-card-returns).
The shim adds four of its own:

| Status | When the shim returns it | Seen on a card? |
|---|---|---|
| `0xA0` application not found | SelectApplication of an AID the card does not hold | yes |
| `0x7E` length error | SelectApplication or CreateApplication too short to parse | yes, as the card's length error generally |
| `0x40` no such key | authentication with a key number the application does not have | not yet |
| `0xDE` duplicate | CreateApplication of an AID the card already holds | not yet |

When a hardware run passes through a "not yet" path, record what the card said.

## Build from source

```
git clone --recursive https://github.com/ObsidianPay/Tessera.Nxpsc
cd Tessera.Nxpsc
cmake -S native -B native/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/build --config Release
dotnet test
```

`native/` builds libnxpsc from the `external/libnxpsc` submodule, plus the mock
card and `layout_probe`, into `native/build/out`. The build copies them next to
the assemblies. `TESSERA_NXPSC_DIR` points the binding at libraries somewhere
else.

The tests also check the binding against the library it loads:

- every function in `nxpsc.h` is declared and exported by the loaded library;
- every struct mirror has the size and field offsets that `layout_probe`
  (compiled by the same C toolchain) reports;
- AN10922's published vectors and libnxpsc's own access-rights and NTAG 424 SDM
  vectors, through the managed API;
- whole flows against the mock card, with both the ISO-wrapped and the native
  command set.

CI runs all of this on Windows x64, Linux x64 and macOS arm64, packs both
packages with every platform's native library, and publishes to GitHub
Packages.

## Licence

GPL-3.0-or-later, the same as libnxpsc, whose native library these packages
contain. See [LICENSE](LICENSE).
