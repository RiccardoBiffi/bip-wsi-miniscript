# Wallet-Signer Interface with Miniscript

Wallet-Signer Interface (WSI) is a Bitcoin protocol proposal for capability discovery, public-key export, policy validation and approval, address confirmation, and PSBT signing. Its conformance tests check what the signer verifies, shows on its trusted display, and signs for an exact policy.

The active [BIP working draft](BIP.md) is version **0.2.1**, with protocol version **1**. BIP number assignment and submission are pending. Physical hardware conformance is unassessed in this repository.

## Specification and test suite

| File | Purpose |
| --- | --- |
| [BIP.md](BIP.md) | WSI encoding, operations, security requirements, profiles, and 64 CTS cases |
| [CTS manifest](cts/manifest.json) and [schema](cts/manifest.schema.json) | Machine-readable case applicability, scenarios, fixture references, and expected outcomes |
| [WSI fixtures](cts/fixtures/wsi.json), [Bitcoin fixtures](cts/fixtures/bitcoin.json), [Miniscript corpus](cts/fixtures/miniscript.json), [mutation recipes](cts/mutations.json) | Reproducible test inputs, transformations and reference outputs |
| [Hardware harness](docs/harness.md) | Execution contract for endpoint adapters, observations, and independent checks |
| [Technical conformance](docs/conformance.md) and [report schema](cts/report.schema.json) | Assessment procedure, evidence, and report format |
| [Version 0.2.0 BIP](archive/v0.2.0/bip-draft-wallet-signer-interface-v0.2.0.md) and [case matrix](archive/v0.2.0/wsi-conformance-cases-v0.2.0.json) | Original draft and test matrix preserved byte for byte |

The archive includes the two v0.2.0 artifacts supplied with the draft. The encoding examples and codec cited in that revision are historical references. The CTS verifier and fixtures in this repository are new work for v0.2.1.

## Verify the corpus locally

Run the verifier from the repository root with Python 3.10 or later.

```bash
python3 -m pip install -r requirements.txt
python3 tools/cts.py verify
python3 -m unittest discover -s tests
```

Run the Bitcoin checks with Bitcoin Core 30 `bitcoind` and `bitcoin-cli` on PATH. The command starts an isolated regtest node in a temporary directory and stops it on exit.

```bash
python3 tools/cts.py verify-regtest
```

The v0.2.1 corpus was checked with Bitcoin Core 30.0. The regtest run covered 25 PSBTv0 inputs and 25 independently reconstructed PSBTv2 inputs, 30 accepted and 34 rejected witnesses, six signed transactions before and after maturity, and 276 Miniscript descriptor derivations. Core consumed the version 2 transaction projection through its PSBTv0 decoder.

To rebuild the generated fixtures or validate a completed assessment report, use the matching commands below.

```bash
python3 tools/cts.py generate
python3 tools/cts.py verify-report path/to/report.json
```

Provision only disposable test devices with the published fixture keys and treat those keys as public. Use a private regtest chain for funding and transaction acceptance tests.

## Assess a hardware wallet

Pin the CTS revision and record the device model, firmware, adapter revision, configuration, carrier, and network. Run the scenarios selected by the actual capability declaration. Capture the required trusted-device observations and independent verification evidence, then record the outcome for each applicable scenario. Use the technical conformance instructions to scope and publish the resulting report. [Hardware harness](docs/harness.md) · [Technical conformance](docs/conformance.md)

The [WSI Miniscript runner](https://github.com/RiccardoBiffi/wsi-miniscript-runner) is the implementation repository for hardware orchestration and vendor adapters. Corpus verification provides software evidence. A hardware conformance report requires the actual endpoint and the evidence specified by the harness.
