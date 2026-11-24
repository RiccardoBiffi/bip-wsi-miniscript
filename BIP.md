```
  BIP: ?
  Layer: Applications
  Title: Wallet-Signer Interface with Miniscript
  Authors: Riccardo Biffi <TBD>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: CC0-1.0
  Version: 0.2.1
  Requires: 32, 174, 370, 371, 379, 380, 382, 386, 388, 389
```

**Author's working draft, revised 2026-11-24.** No BIP number has been assigned; this document has not been submitted, accepted, implemented, or endorsed by the BIP editors or any hardware wallet vendor. The author contact must be completed before submission. Protocol identifiers and numerical resource choices below are proposed, not existing allocations. This revision specifies a candidate application protocol and its security requirements. The CTS defines the experiments needed to assess production interoperability and hardware conformance.

## Abstract

This proposal specifies Wallet-Signer Interface version 1 (WSI), a vendor-neutral interface between software wallets and Bitcoin signing devices. It covers capability discovery, public-key export, exact policy validation, policy approval, address verification, and transaction signing. Portable account descriptions use existing output descriptors and BIP-388 wallet policies. Transactions use PSBT.

WSI separates application semantics from physical transport and permits both native device implementations and adapters to existing device protocols. Self-contained request and response objects support connected and offline signers. Explicit profiles distinguish basic signing, Miniscript in P2WSH, Miniscript in Tapscript, and complete support for the specified Miniscript lifecycle. A device's limitations are exposed before funds are received.

This proposal makes no consensus or transaction relay changes. It does not define a new script language, a new PSBT format, or a substitute for trusted device review.

## Copyright

This document and the original accompanying encoding examples are offered under CC0-1.0. Existing specifications, software, and their test vectors retain their respective licenses.

## Motivation

Wallet software must currently integrate different device APIs, registration models, transports, and subsets of script functionality. Sharing PSBT does not itself standardize public-key discovery, account registration, address confirmation, or the meaning of a claim such as “supports Miniscript.” BIP-388 standardizes a compact account representation, while intentionally leaving registration details to implementations.

HWI, async-hwi and BHWI already provide common host-side abstractions, including policy-related operations. WSI builds on that work: its proposed contribution is a stable protocol contract with explicit trust, conformance, and failure semantics, independently implementable by wallets, device vendors, and adapters. It does not claim that no common host API exists.

An interoperable interface must answer whether a particular policy is supported by the complete integration, not merely by a firmware marketing category. For example, Taproot key-path signing, Tapscript Miniscript, hashlocks, multiple keys controlled by one device, and fixed external public keys are independent capabilities. A wrapper cannot create missing device-side validation.

**Semantic interoperability is the primary standardization objective.** WSI does not standardize six method names merely to spare application developers from vendor APIs. For a claimed capability, distinct implementations must agree on (i) which exact policy and transaction bytes are approved, (ii) which conditions are checked independently by the signer, (iii) what is presented to the user on the trusted display, (iv) which signatures may be released, and (v) the meaning of any refusal or uncertainty. An adapter that offers matching method names but silently changes a descriptor, substitutes an easier signing path, accepts host-only verification as device enforcement, or overstates Miniscript coverage is not WSI conformant. HWI, async-hwi and BHWI may implement WSI; this specification does not replace their transport integrations or demand their adoption.

In particular, capability discovery is a *claim* about a concrete signer-plus-adapter endpoint, not an interoperability proof. The normative conformance matrix below ties each profile and advertised feature to positive, negative, independent-oracle and trusted-display tests. No user should fund a complex account based solely on a profile string.

## Terminology and scope

The capitalized words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

- **Host:** wallet/coordinator software, including its OS. It is untrusted by the signer.
- **Signer:** the component controlling private keys and the trusted user interface.
- **Endpoint:** a native WSI signer or a WSI adapter plus its underlying signer.
- **Adapter:** code translating WSI objects into a vendor protocol. It may run on the host and does not inherit the signer's trust.
- **Policy:** the exact portable account object defined below, including network and script/key descriptions.
- **Approval:** user authorization of an exact policy on the trusted device interface.
- **Registration:** a mechanism for remembering or proving a previous approval. It need not consume persistent device storage.
- **Signature target:** one specified input, signing public key, signature mode, and sighash; for Tapscript, also one leaf hash.
- **Complete Miniscript lifecycle:** validation, review/approval, address derivation and verification, safe signing, preservation of recovery data, and participation in host-side satisfaction/finalization.
- **Conformance claim:** a declaration that a specified endpoint configuration implements a profile or feature according to its normative observable requirements.
- **Conformance assessment:** test results for a particular device model, firmware, adapter, transport binding, network and declared capability set; not device identity attestation or a guarantee against malicious hardware.
- **Conformance test suite (CTS):** the positive, negative, stateful, trusted-display and independent-implementation tests mapped to capabilities in this proposal.

The host selects coins, constructs transactions, chooses possible satisfactions, obtains other signatures and preimages, finalizes witnesses, and broadcasts. The signer validates what it approves and signs. WSI does not require the signer to run a node or search every possible satisfaction.

Seed generation, recovery, PIN entry, firmware installation, device attestation, message signing, transaction packages, covenant extensions, and MuSig2 round management are outside WSI v1. A device MAY offer them through separately specified extensions, but MUST NOT imply their support from a Miniscript profile. This protocol never asks for private keys or seed material.

## Specification

### 1. Encoding and portable messages

The normative encoding is CBOR using RFC 8949 section 4.2.1 core deterministic encoding. WSI uses only unsigned integers, byte strings, UTF-8 text strings, arrays, maps with text-string keys, booleans, and null where explicitly permitted. Integers use their shortest encoding; lengths are definite; map keys are sorted by their encoded bytes. Tags, floating-point numbers, indefinite lengths, duplicate map keys, trailing data, and invalid UTF-8 MUST be rejected. Protocol integers are bounded by the field definitions below; otherwise their maximum is 2^32-1. CBOR nesting is limited to 64 levels, counting the top-level record as level 1; implementations MUST enforce bounds while parsing, not after unbounded allocation or recursion.

No unspecified field is permitted in a core record. An unknown field, method, or required feature MUST produce an error instead of being silently ignored. This rule concerns WSI records; unknown non-conflicting PSBT fields are preserved under section 8.

Record notation in this document is a schema, not JSON wire encoding. `bytesN` means a byte string of exactly N bytes, `bytes` a variable-length byte string, `text` a text string, `u32` an unsigned 32-bit integer, and `[T]` an array of T. A trailing `?` marks an optional field. All other fields are required. All maps are closed. Arrays described as sets MUST contain no duplicates; their order has no semantic meaning, but their serialized order is committed by the request hash.

```
Request = {
  "v": 1,
  "type": "request",
  "id": bytes16,
  "method": text,
  "required_features": [text],
  "params": method-specific record
}

Response = {
  "v": 1,
  "type": "response",
  "id": bytes16,
  "request_hash": bytes32,
  exactly one of:
    "result": method-specific record
    "error": Error
}

Error = {
  "code": text,
  "message": text,
  "location"?: [text or u32],
  "limit"?: u32,
  "actual"?: u32
}
```

`location` identifies a field/index in the decoded request; it is not executable. `message` is diagnostic text, not a machine-readable authorization decision. Error details MUST NOT contain secrets. An endpoint MUST have receive capacity for at least 4,096 bytes of the WSI container, including its four-byte magic and excluding any stream length prefix. This minimum leaves the closed `capabilities` request schema intact. An endpoint MUST accept a valid `capabilities` request using the encoding and fields defined here and MUST reject unused fields, trailing bytes, and padding. Endpoints MAY impose advertised smaller limits on individual fields. The absolute WSI container limit is 16,777,216 bytes; actual endpoint limits are normally lower and MUST be checked before allocation.

The host generates a fresh unpredictable request ID for each new operation. The response copies that ID and contains:

```
request_hash = SHA256(ASCII("WSI/request/v1") || 0x00 || CBOR(Request))
```

An endpoint MUST reject an ID reused with different request bytes while it retains that ID. An identical retry MAY return a cached complete response or require a new device approval. Offline or restarted signers need not maintain a durable replay database; in that case retries are treated as new operations requiring the same authorization. The host MUST check both ID and request hash and MUST NOT merge conflicting responses. These hashes correlate data; they are not device attestation or proof of user consent.

A malformed/non-deterministic container is rejected before dispatch, without a WSI response: a stream binding closes the affected stream; a file binding reports an import error locally. No dummy request ID or commitment is invented. Once deterministic CBOR and the envelope's correlation fields (`v`, `type`, `id`) have been decoded with the prescribed types, semantic errors can use a Response. Its commitment hashes the exact received CBOR bytes, even when a method or parameter is invalid. For valid requests, those bytes equal `CBOR(Request)` above. Pre-envelope failures may be called `INVALID_ENCODING` by a local carrier API, but that label is not an uncorrelated WSI response.

`required_features` is a set of capability feature strings. Every listed feature MUST be available for that operation. The endpoint MUST also enforce all requirements inherent in the requested data, whether or not the host lists them. No fallback to a different script, network, signature mode, or sighash is permitted.

### 2. Transport-independent carriers

The common binary container is four bytes `57 53 49 01` followed by one encoded Request or Response. A file carrier uses these bytes directly, with suggested extension `.wsi`. A byte-stream carrier prefixes the entire container with its length encoded as an unsigned 32-bit big-endian integer. A length below five or above the applicable limit is invalid. An incomplete frame MUST NOT be executed.

USB, serial, BLE, QR, removable media, and interprocess implementations MAY carry the container. Transport segmentation MUST reconstruct the identical container before operation dispatch, or authenticate every streamed part against an immutable commitment with equivalent semantics. This draft does not allocate USB identifiers, BLE services, or new UR/BBQr type identifiers. Existing QR encodings may carry opaque binary data where their specifications permit it; a concrete mapping requires a separately identified transport binding.

An endpoint MUST implement at least one of the file or stream carriers and advertise it. Offline requests include the complete policy and transaction data needed for the operation; they MUST NOT require an online callback. A native adapter MAY use vendor-specific streaming internally, including Merkle-proof requests, but the policy and transaction being reviewed MUST remain immutable.

Transport encryption, authenticated pairing, device discovery, unlock flows, and OS permissions remain binding-specific. They do not replace device approval. Public-key export and other privacy-sensitive data MUST NOT be automatically exposed to an arbitrary network or browser origin. This proposal does not require a listening HTTP service.

### 3. Network and key representations

`Network` is one of `bitcoin`, `testnet3`, `testnet4`, `signet`, or `regtest`, referring to the corresponding standard Bitcoin network parameters. `signet` here means the default signet challenge. Custom signets and chains require a future explicit network extension; they MUST NOT silently reuse a standard name. Network is part of policy identity even when address encodings coincide.

A derivation path is an array of u32 BIP-32 child numbers. Hardened steps have bit 31 set. A master fingerprint is the four bytes specified by BIP-32, not proof of identity. The signer MUST derive and compare the complete expected public key or extended public key to establish ownership; matching a fingerprint alone is insufficient.

Public keys are compressed SEC1 keys of 33 bytes in SegWit-v0 contexts and x-only keys of 32 bytes where BIP-386/342 require them. Extended keys use standard BIP-32 public serialization for the network. Private extended keys, private scalar keys, WIF, and secret entropy are forbidden in all policy/export requests.

### 4. Portable policy objects

Two formats are defined. All endpoints implement `bip388-v1`; `descriptor-pair-v1` is an additional capability and is required by the Full profile.

```
Bip388Policy = {
  "format": "bip388-v1",
  "network": Network,
  "template": text,
  "keys": [text]
}

DescriptorPairPolicy = {
  "format": "descriptor-pair-v1",
  "network": Network,
  "receive": text,
  "change"?: text
}
```

#### 4.1 BIP-388 representation

`template` and ordered `keys` carry the BIP-388 wallet descriptor template and key information vector, using BIP-379 for Miniscript. All BIP-388 key/range validity rules apply. BIP-388 version 1.1's `musig()` placeholders are recognized as requiring a separate signing extension and are rejected by core WSI v1 with `UNSUPPORTED_FEATURE`.

The host MUST NOT change key ordering, derivation ranges, script ordering, or Taproot tree structure during registration or signing. Optional vendor-specific derivation patterns do not become portable merely because a vendor accepts them. Only the core BIP-388 derivations are covered by this format identifier.

#### 4.2 Descriptor-pair representation

This representation carries explicit BIP-380 descriptors with valid checksums. It permits fixed external public keys and ordinary BIP-32 public expressions without inventing a synthetic xpub for a static key. Its supported wrappers are `wpkh()`, `wsh()`, and `tr()`. The latter two use BIP-379 script expressions in their appropriate contexts. Private keys, `raw()`, `addr()`, `combo()`, arbitrary Bitcoin Script, and `musig()` are outside this format in v1.

Each descriptor has at most one terminal, unhardened `/*` per extended-key expression. All wildcards in one descriptor use the same address index. Multipath expressions MUST first be expanded according to BIP-389 into explicit receive and change descriptors; the expansion MUST preserve the resulting scripts. General higher-cardinality multipath account management is not defined in this revision.

If `change` is present, both descriptors are approved as one account. Their ASTs, including hash/timelock constants, thresholds, key-expression positions, and Taproot tree structure, MUST be identical after ignoring differences in unhardened suffix derivation steps. Corresponding key expressions MUST have the same base public key or xpub and origin. Wildcard presence and suffix length MUST match at corresponding positions. A fixed key MUST remain identical. This allows distinct receive/change branches while preventing a different spending policy from being hidden as change. A pair not meeting these conditions is rejected, not rewritten.

An unranged descriptor requires address index zero. With no change descriptor, branch one is unavailable. Fixed keys reused across addresses MUST generate a device warning about linkability; this is different from repeating a key inside one Miniscript.

Device-controlled key expressions MUST include their real origins so that ownership can be checked. A fixed external key may omit an origin. The signer MUST NOT infer ownership merely because the host names a key “mine.” External keys and locally controlled keys must be distinguished during review. Originless internal Taproot keys MUST NOT be described as unspendable unless the signer verifies a recognized NUMS construction; otherwise the key path is displayed as a possible external spending authority.

#### 4.3 Identity, exactness and labels

```
policy_id = SHA256(ASCII("WSI/policy/v1") || 0x00 || CBOR(Policy))
```

This is an exact-data identifier. Deterministic CBOR does not canonicalize descriptor semantics. Different equivalent descriptor spellings, origins, or tree encodings can intentionally have different IDs. No implicit normalization is performed during hashing. A wallet MAY explicitly transform a policy before approval, but MUST verify the script equivalence where it claims equivalence and treat the transformed object as a separate policy for registration.

The policy ID is independent of a vendor's wallet ID and is not an address, signature, or ownership proof. Names are metadata, outside policy identity. A label is 1-32 printable ASCII bytes with no leading/trailing spaces. A signer may advertise a lower maximum. A registration authorization MUST bind the exact label as well as the exact policy and active seed/passphrase context. A label change requires new approval or an equivalent independently reviewed rename, which is outside v1.

### 5. Capability discovery

`capabilities` takes an empty parameter map and returns:

```
Capabilities = {
  "protocol_versions": [u32],
  "implementation": {"name": text, "version": text},
  "mode": "native" or "adapter",
  "signer": {"model": text, "firmware": text},
  "profiles": [text],
  "features": [text],
  "networks": [Network],
  "carriers": ["file" or "stream"],
  "policy_formats": ["bip388-v1" or "descriptor-pair-v1"],
  "psbt_versions": [0 or 2],
  "transaction_versions": [u32],
  "registration_modes": ["stored" or "token" or "per-operation"],
  "ecdsa_sighashes": [u32],
  "schnorr_sighashes": [u32],
  "miniscript": {
    "wsh": ContextSupport,
    "tapscript": ContextSupport
  },
  "enforcement": {
    "policy_validation": Enforcement,
    "policy_review": Enforcement,
    "address_display": Enforcement,
    "change_verification": Enforcement,
    "signature_scope": Enforcement
  },
  "limits": Limits
}

ContextSupport = {
  "coverage": "none" or "subset" or "full-v1",
  "fragments": [text],
  "restrictions": [text]
}
Enforcement = "device" or "host-only" or "unavailable"
```

All list fields above are sets. Model/firmware strings are informational and MAY say `unknown`; they MUST NOT be used to infer a capability that is absent. No serial number, fingerprint, or xpub is included in discovery. For `full-v1`, `fragments` lists the applicable BIP-379 fragment and wrapper names; for `subset`, it lists only supported names. A list of names alone never implies all compositions are accepted. `restrictions` provides diagnostic explanations, while `check_policy` is the machine decision for an exact object.

`Limits` is a closed map containing the following u32 fields, each with the units stated: `container_bytes`, `psbt_bytes`, `policy_bytes` (encoded CBOR), `template_bytes` (UTF-8 bytes), `descriptor_bytes` (per descriptor), `keys` (key expressions after expansion), `owned_keys` (distinct key expressions controlled by this signer), `ast_nodes` (per Miniscript), `ast_depth` (per Miniscript, root depth 1), `tap_leaves`, `tap_depth` (root leaf depth 0), `inputs`, `outputs`, `targets`, `policies_per_sign`, and `label_bytes`. Zero means unsupported, not unlimited. An unused limit, such as `tap_leaves` on a WSH-only endpoint, is zero. The endpoint MUST disclose additional composition restrictions through `check_policy`; it MUST NOT disguise an unsupported fragment as a resource limit.

Feature strings defined by this version are `policy-bip388`, `descriptor-pair`, `miniscript-wsh`, `miniscript-tapscript`, `hashlocks`, `cltv-height`, `cltv-time`, `csv-blocks`, `csv-time`, `raw-external-keys`, `multiple-owned-keys`, `taproot-keypath`, `taproot-scriptpath`, `exact-signature-scope`, and `fee-unverified-opt-in`. PSBT versions, transaction versions, and sighashes use their explicit fields instead of implied version comparisons. Cross-context feature strings such as `hashlocks`, `cltv-height`, `cltv-time`, `csv-blocks`, `csv-time`, and `multiple-owned-keys` refer to every Miniscript context for which this endpoint claims the corresponding feature; an endpoint MUST NOT use an unqualified feature string to imply support in a context that rejects it. The `miniscript.wsh` and `miniscript.tapscript` objects scope fragment coverage; a subset implementation may omit a global feature when it can support that primitive in only one context. A named feature without any applicable supported context is not a valid claim. The definitive decision for an exact policy remains `check_policy`.

An adapter reports the **effective intersection** of device, adapter, and carrier capabilities. For example, native Tapscript support blocked by an adapter is unavailable at that endpoint. `device` means the relevant property is enforced inside the signer, including when reached through an adapter. Filtering excessive signatures or displaying a policy on the host cannot be advertised as device enforcement. Capability responses are claims, not cryptographic attestation; conformance requires testing.

### 6. Policy lifecycle operations

#### 6.1 `get_key`

Parameters: `{"network": Network, "path": [u32]}`.

Result: `{"network": Network, "fingerprint": bytes4, "path": [u32], "xpub": text}`.

The signer obtains user consent for the export, displaying the network and path on its trusted interface. It returns the real origin and public extended key for the active seed/passphrase. Unsupported derivation paths produce `UNSUPPORTED_DERIVATION`, not another account's key. Host-side caching requires explicit user consent and is outside the signing protocol. Imported non-BIP32 signing secrets are outside this method in v1.

#### 6.2 `check_policy`

Parameters: `{"policy": Policy}`.

Result:

```
{
  "policy_id": bytes32,
  "validity": "valid" or "invalid" or "unknown",
  "support": "supported" or "unsupported" or "unknown",
  "validation": "device" or "host" or "none",
  "owned_key_count": u32 or null,
  "issues": [Error],
  "warnings": [text]
}
```

Malformed CBOR is handled before the envelope as described in section 1; invalid Policy record shapes fail with an error response. For a structurally valid Policy record, the result distinguishes language validity, endpoint support, and who performed validation. `validity=valid, support=unsupported` means the data is valid within the specified language but the endpoint cannot safely support it. `unknown` MUST be used when early resource rejection, an unsupported parser, or an unavailable device check prevents a definitive conclusion. Unknown ownership is null, not zero.

`validity=invalid` is reserved for proven language, context, type, key-encoding or checksum failure. A well-formed policy rejected for safety or a vendor restriction can remain `validity=valid`, with `support=unsupported` and the appropriate issue. No successful device validation or approval may be inferred from `validity` alone.

`support=supported` requires `validity=valid`, `validation=device`, at least one controlled key, and all applicable syntax, context, sanity, public-key, resource and ownership checks. A locked signer cannot yield this positive result. An adapter MAY perform a read-only host preflight and report `validation=host`; it MUST NOT claim device-established support from its own parser. When the native API validates only during an interactive registration/signing operation, the preflight returns `support=unknown` with `DEVICE_CHECK_REQUIRED` in `issues`. It MUST NOT trigger an undisclosed approval or registration as a side effect. Successful subsequent device approval and address verification can establish usable support even when the earlier preflight was unknown.

For every complete Miniscript profile, each complete WSH script or Tapscript leaf MUST have top-level type B, satisfy all applicable BIP-379 correctness requirements, have BIP-379 property `s` (every satisfaction requires a signature), satisfy the BIP-379 timelock-type-mixing rules, and meet the malleability table's requirements recursively at every node. This last condition requires the specified guarantee of non-malleable satisfaction, not merely finding one non-malleable witness in a sample. Duplicate derived public keys inside one Miniscript and policies outside resource bounds are rejected separately. An external-only Taproot leaf is permissible if it meets these conditions; an entire account without a key controlled by the signer is unsupported. Cross-leaf or internal-key reuse MUST be analyzed and disclosed; BIP-388 restrictions still apply to that format. Using one seed or xpub more than once with disjoint, valid derivation ranges is not itself forbidden.

Validation of ranged descriptors MUST include structural alias checks and per-address duplicate-key checks whenever a concrete address is derived. A finite spot-check MUST NOT be presented as proof about every possible BIP-32 child. If ranges cannot be accepted safely, the endpoint reports the restriction. Hashlock preimages are not required for policy approval.

The operation is a preflight, not approval, chain validation, or a guarantee that any future PSBT is signable. It neither derives a receive address for funding nor produces a signature. Firmware, adapter, active key context, and transaction details may affect subsequent support. Registration and signing MUST revalidate their inputs. Complete Miniscript profiles require definitive device validation for policies inside their supported domain; the Core profile permits an unknown preflight followed by real device validation during approval.

#### 6.3 `register_policy`

Parameters: `{"policy": Policy, "label": text}`.

Result: `{"policy_id": bytes32, "label": text, "mode": RegistrationMode, "handle"?: bytes}`.

The signer MUST independently validate the policy and obtain explicit approval on its trusted interface. Review MUST expose the actual spending conditions, keys/origins, network, hashlocks/timelocks, and key-path authority where applicable. A human-readable explanation is encouraged, but it MUST be derived by the signer and MUST NOT replace access to the exact template/descriptors and key details. The full policy commitment must be available for comparison with a trusted backup; a short label alone is insufficient.

Registration models:

- `stored`: the signer stores approved material; the returned opaque handle identifies that record.
- `token`: the host stores a signer-authenticated proof; the returned opaque handle carries it.
- `per-operation`: approval is repeated when an address or transaction is requested; no handle is returned.

For `stored` and `token`, the handle is 1-1,024 bytes. It MUST be validated against the exact policy, label, network and active signing-key context, not merely a master fingerprint. Handles are not portable between vendors, devices or key contexts unless that implementation explicitly authenticates such reuse. The portable policy remains the source of account recovery data.

A native registration hash is not automatically a WSI policy commitment. An adapter can use it only when the native commitment plus device checks authenticate every WSI-required field, including origins, network and label. A host-created wrapper hash cannot fill a missing device guarantee. If the native registration omits such material, the endpoint must obtain complete fresh device review at each operation or report the registration mode unsupported; firmware changes may be necessary. The device need not compute the WSI CBOR hash if it exposes an independently verifiable native commitment covering the same exact approved data, with an explicit lossless mapping. The host MUST NOT present a host-computed WSI hash as a hash displayed or authenticated by the signer.

No v1 operation promises registration revocation. Deleting a host-side token does not revoke copies of it; deleting a device record does not revoke Bitcoin signatures. Policy editing produces a new policy object and requires new approval. Host backups MUST retain exact descriptors/key origins, network and derivation structure; a seed alone may not reconstruct a complex account. The host can export those already-held public objects without a device-specific export operation.

#### 6.4 `display_address`

```
RegisteredPolicy = {
  "policy": Policy,
  "label": text,
  "registration"?: {"mode": "stored" or "token", "handle": bytes}
}

AddressRef = {"policy_id": bytes32, "branch": 0 or 1, "index": u32}
```

Parameters: `{"wallet": RegisteredPolicy, "branch": 0 or 1, "index": u32}`.

Result: `{"policy_id": bytes32, "branch": 0 or 1, "index": u32, "address": text, "script_pubkey": bytes, "confirmed": true}`.

Index MUST be less than 2^31. Branch means receive (0) or change (1), not an arbitrary raw BIP-32 child number. BIP-388 placeholders resolve their first/second branch choices accordingly. The endpoint validates the registration or obtains full per-operation policy approval. It then independently derives the address and displays it for confirmation. There is no no-display mode in this operation. User rejection is an error; success MUST NOT be emitted before confirmation. The host SHOULD independently derive and compare both address and script.

### 7. Transaction signing

#### 7.1 Request and result

```
SignParams = {
  "psbt": bytes,
  "wallets": [RegisteredPolicy],
  "input_bindings": [{"input": u32, "address": AddressRef}],
  "change_bindings": [{"output": u32, "address": AddressRef}],
  "targets": [SignatureTarget],
  "fee_mode": "verified-prevouts" or "allow-unverified"
}

SignatureTarget = {
  "input": u32,
  "mode": "ecdsa" or "tap-key" or "tap-script",
  "pubkey": bytes,
  "sighash": u32,
  "leaf_hash"?: bytes32
}

SignResult = {
  "psbt_hash": bytes32,
  "updates": [{"input": u32, "key": bytes, "value": bytes}],
  "targets": [{"target": u32, "status": "signed" or "already-present"}],
  "fee_status": "verified-prevouts" or "unverified"
}
```

Method: `sign_psbt`. `psbt_hash` is SHA256 of the exact original PSBT bytes. The surrounding response also binds the complete request, including every policy and signing restriction. Each target has exactly one corresponding result by zero-based target index. Duplicate targets, duplicate input bindings, duplicate output bindings and duplicate policy IDs in `wallets` are invalid. Unused wallet entries are invalid. Every target's input MUST have an input binding; its referenced policy must be present in `wallets`. Every binding resolves against the original PSBT input/output ordering.

`wallets`, `input_bindings` and `targets` MUST be nonempty. Every wallet MUST refer to the same exact Network, which the signer must support and use for its review. A request mixing network identities is invalid even when address prefixes or signature algorithms coincide. At least one target must belong to each supplied wallet; otherwise that wallet is unused for this operation.

For `ecdsa`, `pubkey` is the compressed public key and `leaf_hash` is absent. For `tap-key`, `pubkey` is the x-only internal key, `leaf_hash` is absent, and the signer validates the tweaked output key. A single-party key-path signing key must be controlled by this signer; aggregated signing requires a separate extension. For `tap-script`, `pubkey` is the x-only script key and `leaf_hash` is required. The requested key/leaf MUST be part of the approved instantiated policy. Signing a leaf does not authorize a key-path signature.

The target's sighash MUST agree with the PSBT's effective sighash; when the field is absent, ECDSA defaults to ALL (1) and Schnorr defaults to DEFAULT (0). Core supports ECDSA ALL, and Taproot profiles support Schnorr DEFAULT and ALL. Other sighashes require an explicit advertised value, an exact target request, and trusted user review of the weakened commitment. No silent ANYONECANPAY, NONE, SINGLE, or default-sighash substitution is allowed. For a weakened commitment, the device MUST identify which inputs/outputs can change and distinguish current proposed amounts/fees from values fixed by the signature. A verified current prevout total does not imply an immutable final fee under an incomplete commitment.

The device MUST enforce the exact target set before releasing any signatures. An adapter MUST return `SIGNATURE_SCOPE_UNSUPPORTED` if the underlying signer would produce unrequested signatures; discarding such signatures afterwards is not sufficient. A request can legitimately obtain only one participant's signatures for a multisignature transaction; completion of all transaction signatures is not required.

Before returning success, the endpoint validates the whole request and obtains the required policy and transaction approvals. A target that cannot be safely fulfilled causes an error; a complete success response does not silently omit it. If a valid signature is already present for a target, status is `already-present` and no duplicate update is added. A preexisting invalid or conflicting target signature is an error. This is response-level completeness, not a guarantee of transactional rollback after a disconnect.

#### 7.2 PSBT and transaction checks

The endpoint MUST validate the PSBT format, consistency and conversion. Duplicate PSBT keys, conflicting witness/non-witness UTXOs, inconsistent derivations, malformed scripts, invalid input/output counts, and disagreement between the policy and prevout script MUST fail. A finalized input cannot be a new signature target in v1. Existing data MUST NOT be overwritten to make a request acceptable. A signer receiving a structured vendor transaction need not parse raw PSBT bytes; it MUST independently enforce the corresponding transaction, policy, prevout, key, change and signature semantics. Host validation or translation does not discharge these device duties.

Every target's concrete witness script, redeem script where applicable, or Taproot commitment MUST match the descriptor-derived prevout. The signer independently checks controlled key origins and all derivation indices. Host-supplied ownership flags or fingerprints are insufficient.

For Taproot, the signer reconstructs the approved internal key, full script tree, Merkle root, and output-key tweak. It validates the selected leaf script, leaf version and control block against that commitment and the UTXO. v1 covers leaf version 0xc0 and BIP-379 Tapscript; unknown leaf versions, annex signing, and OP_CODESEPARATOR extensions are not covered. A matching leaf hash alone does not prove the UTXO belongs to the approved account.

Transaction version is negotiated independently from PSBT version. Supporting PSBTv2 does not imply supporting transaction nVersion=3. An unlisted transaction version MUST fail. The host MUST NOT change a transaction version, sequence, locktime, output, or fee merely to satisfy a device without producing a new request and new review.

#### 7.3 Change, outputs and fees

`change_bindings` are claims for the signer to verify. Each must resolve to branch one of an approved account actually bound to at least one target input, and the full output script MUST equal independent derivation at the specified index. A policy used only by an output cannot enable change classification and is not an eligible `wallets` entry. The mere presence of a key owned by the signer does not make an output change. A mismatching claim fails. Outputs not classified as verified change are displayed as external, including transfers to another policy controlled by the same seed. Missing metadata must never cause an unsafe change classification.

When signature targets span more than one policy, every output MUST be displayed with its amount, even when annotated as verified change; cross-account transfers cannot be hidden by introducing a small input from another account. The review MUST identify the affected accounts and their visible allocations. This conservative rule avoids treating arbitrary transfers among registered policies as invisible change.

The trusted transaction review displays external destinations and amounts, fees with their verification status, and the affected policy labels/identities. Receiving outputs may use address types the device does not sign; this does not by itself authorize hiding those outputs. Unknown script destinations require an unambiguous script/commitment review or rejection.

With `fee_mode=verified-prevouts`, **all** input values used in aggregate fee accounting, including external inputs, MUST be authenticated by complete previous transactions whose txids and output indices match the outpoints. Corresponding witness UTXOs must agree. PSBT `non_witness_utxo` can carry these transactions. If required data is missing, the signer returns `PREVOUT_DATA_REQUIRED`. This verifies the values committed by the transaction IDs, not confirmation, unspentness, or chain inclusion.

`allow-unverified` is available only with feature `fee-unverified-opt-in`. The signer must still validate its own input signing data and PSBT consistency. It must clearly warn on-device when aggregate fees depend on unauthenticated values and obtain explicit approval; the result then reports `unverified`. An adapter's fee calculation cannot upgrade this to `verified-prevouts`. This distinction is particularly relevant to SegWit-v0 signing, where the signer's signature does not commit to every other input amount.

#### 7.4 Timelocks, hashlocks and satisfaction

The signer validates script semantics and the actual transaction fields committed by each signature. It MUST distinguish CLTV height from time, CSV block delay from 512-second units, the sequence disable/type flags, transaction version, and effective nLockTime. Input sequence and locktime values are never silently repaired. For PSBTv2, effective locktime is derived under BIP-370 rules rather than reading the fallback alone.

`sign_psbt` v1 requests signatures, not proof that a particular complete witness exists. No branch-selection string is authoritative. A signer MUST reject a known impossible requested script context; it MUST NOT claim to have verified a particular satisfaction unless it has actually validated its complete conditions. An unsatisfied timelock in an unused alternative is not by itself proof that the script is impossible and MUST NOT be treated as a universal conjunct. The host remains responsible for selecting a feasible satisfaction and constructing and validating the final witness; this protocol does not require an on-device exhaustive satisfaction search.

Presigning a transaction before a timelock matures is permitted. An offline device generally cannot establish current chain maturity. Its UI and response MUST NOT confuse successful signing with present broadcastability. Similarly, policy validation does not imply knowledge of a hash preimage. Hash preimages supplied in PSBT must match the corresponding hash and BIP-379 length rules; absent preimages do not automatically prevent producing otherwise authorized signatures. The signer MUST NOT generate or export secrets to fill a missing preimage.

A P2WSH signature commits to the script and transaction according to its sighash, not to an abstract branch name. A Tapscript signature additionally commits to its leaf context, not necessarily to a unique branch within that leaf. WSI enforces requested keys and Taproot leaves; it cannot promise branch-exclusive authorization that Bitcoin's signature construction does not provide.

### 8. Signature patches and PSBT preservation

`updates` contains new input-map key/value entries using the exact PSBT key and value encoding, excluding the surrounding CompactSize key/value length prefixes. Only the following keys are allowed in core v1:

| Signature mode | PSBT key | Required key data |
|---|---|---|
| `ecdsa` | `PSBT_IN_PARTIAL_SIG` (0x02) | Corresponding compressed public key |
| `tap-key` | `PSBT_IN_TAP_KEY_SIG` (0x13) | Empty |
| `tap-script` | `PSBT_IN_TAP_SCRIPT_SIG` (0x14) | X-only public key followed by leaf hash |

Values follow BIP-174 or BIP-371, including their sighash encoding rules. There must be exactly one new entry for each `signed` target and none for an `already-present` target. All signatures must verify for the requested input, mode, key/leaf and sighash. In Taproot key-path mode verification uses the tweaked output key. No update may introduce a signature outside the target set.

The host validates the response commitment, signature validity and update scope before merging into its preserved original PSBT. Unknown/proprietary original PSBT fields remain unchanged. It MUST reject an update that conflicts with an existing key/value. It then performs any remaining signing, satisfaction and witness finalization independently. The patch deliberately permits devices that return a reduced PSBT or individual signatures without requiring them to round-trip unrelated fields.

An adapter translating between PSBTv0 and PSBTv2, or to a structured vendor transaction, MUST preserve the exact effective unsigned transaction and all signature semantics. It may keep unknown fields in the original host object, but MUST NOT strip a field whose unrecognized meaning is required for safe signing. BIP-370 transaction modifiability and locktime rules must be respected. A conversion that cannot preserve required semantics fails with `PSBT_CONVERSION_UNSAFE`. Signature deltas refer to the original PSBT ordering.

### 9. Errors, interruption and execution state

The following error codes are defined:

| Code | Meaning |
|---|---|
| `INVALID_ENCODING` | Invalid or non-deterministic CBOR/container |
| `INVALID_REQUEST` | Invalid record shape, duplicate index, or inconsistent parameters |
| `UNSUPPORTED_VERSION` | Unsupported WSI protocol version |
| `UNSUPPORTED_METHOD` | Unknown/unavailable operation |
| `UNSUPPORTED_FEATURE` | Required feature, policy format, or signing extension unavailable |
| `UNSUPPORTED_NETWORK` | Unsupported exact network |
| `UNSUPPORTED_DERIVATION` | Invalid or unsupported public-key derivation |
| `INVALID_POLICY` | Descriptor, key expression, Miniscript context/type, or checksum invalid |
| `UNSAFE_POLICY` | Policy fails the stated safety rules |
| `UNSUPPORTED_POLICY` | Valid policy exceeds functional constraints of this endpoint |
| `RESOURCE_LIMIT` | Named disclosed numerical limit exceeded |
| `KEY_NOT_OWNED` | No required matching controlled key in current key context |
| `REGISTRATION_REQUIRED` | Endpoint needs an approval/registration that is absent |
| `INVALID_REGISTRATION` | Handle/label/policy/key context mismatch |
| `DEVICE_LOCKED` | Device authentication or key-context selection needed |
| `DEVICE_CHECK_REQUIRED` | Read-only preflight cannot establish native support; interactive device validation is needed |
| `USER_REJECTED` | User rejected the operation on the trusted interface |
| `INVALID_PSBT` | Malformed, contradictory, or unsafe PSBT data |
| `POLICY_MISMATCH` | Input/output script or derivation does not match approved policy |
| `UNSUPPORTED_TX_VERSION` | Transaction version not supported |
| `UNSUPPORTED_SIGHASH` | Unsupported/request-mismatched sighash |
| `SIGNATURE_SCOPE_UNSUPPORTED` | Exact requested input/key/leaf scope cannot be enforced |
| `PREVOUT_DATA_REQUIRED` | Data needed for verified prevout accounting missing |
| `PSBT_CONVERSION_UNSAFE` | Adapter cannot preserve transaction/signing semantics |
| `REQUEST_ID_CONFLICT` | Retained request ID reused with different content |
| `BUSY` | Another interactive operation is in progress |
| `INTERNAL_ERROR` | Unclassified failure, with no implied safe retry |

No signatures appear in an error response. Before producing any signature, the signer must finish all applicable validation and approvals. Nonetheless, an error after a vendor operation, host crash, transport timeout, or user cancellation does not prove that no signature was produced or disclosed. The host records such an outcome as unknown, not unsigned. Once disclosed, a Bitcoin signature cannot be revoked by canceling WSI.

Core v1 has one final response per request and no resumable signing-session primitive. Connection closure does not imply rollback. If a backend exposes intermediate signatures, an adapter MUST treat them as potentially disclosed and must not promise atomicity. A fresh retry must be correlated to the original transaction and follow the same review rules. Multi-round nonce protocols require a separate specification and MUST NOT reuse these retry rules by assumption.

### 10. Conformance profiles and capability verification

WSI profiles define semantic and security *outcomes*, not a common source-code API. A backend's success on the correct `sign_psbt` call does not establish that it validates descriptor contents, displays policy terms, or rejects unsafe change. Compliance is scoped to the **complete endpoint**: signer hardware/software, firmware version, adapter version, relevant configuration, advertised carrier and the particular Bitcoin network. An adapter MUST claim only the effective intersection of all these layers. No adapter or host-side validator can certify `enforcement=device` for a check it performs itself.

| Profile | Requirements beyond the common encoding and operations |
|---|---|
| `wsi-core-v1` | Six core methods; BIP-388 `wpkh()` and `wsh(sortedmulti())`; at least PSBTv0 or v2; at least transaction version 2; ECDSA ALL; device-enforced policy review, address confirmation, change and exact target validation; verified-prevout fee mode |
| `wsi-miniscript-wsh-v1` | Core plus every BIP-379 fragment/wrapper applicable to P2WSH in safe, well-typed compositions within declared resource bounds; all four hashlocks; CLTV height/time; CSV block/time; multiple owned keys with distinct derivations |
| `wsi-miniscript-tapscript-v1` | Core plus every BIP-379 fragment/wrapper applicable to Tapscript in safe, well-typed compositions within declared resource bounds, BIP-371 data, complete Taproot policy validation, explicit key-path/script-path targets, Schnorr DEFAULT/ALL, all four hashlocks, CLTV height/time, CSV block/time, and multiple owned keys with distinct derivations |
| `wsi-miniscript-full-v1` | Both Miniscript profiles plus both policy formats, fixed external keys in their valid contexts, and the complete lifecycle in this proposal |

“Full” means complete coverage of the specified grammar and lifecycle within disclosed finite bounds and the stated safety domain. It does not mean arbitrary Script, unsafe policies, unlimited memory, custom networks, MuSig2, or every PSBT extension. A device excluding an applicable fragment or safe composition for a functional reason MUST claim `subset` rather than `full-v1` for that context. It MAY still advertise successfully tested narrower features. Every advertised `profiles`, `features`, `policy_formats`, `psbt_versions`, `transaction_versions`, `registration_modes`, supported sighash, carrier and `enforcement=device` value is a separate conformance claim.

#### 10.1 Normative test obligations

1. A WSI endpoint claiming any profile MUST pass all **CORE** cases of the WSI Conformance Test Specification (CTS), including each applicable positive and negative scenario. A WSH profile claim adds all `WSI-WSH-*` cases, and a Tapscript profile claim adds all `WSI-TR-*` cases. The Full profile adds both sets and all `WSI-DPA-*` cases. This includes cross-composition tests and end-to-end signing and witness checks. Every additional advertised feature, version, policy format, registration mode or carrier MUST pass all CTS cases assigned to that claim. Scenario applicability follows the manifest and this specification.
2. Tests MUST exercise the advertised endpoint, not a simulator in place of the signer. The same conformance claims MUST hold when requests are delivered through each advertised transport carrier. Implementations MAY perform additional direct-to-firmware tests. A black-box test of the host adapter alone cannot establish native signer enforcement: those claims additionally require trusted-display observation and device-side evidence or an independently inspectable firmware pathway.
3. A successful operation MUST match the independent expected output exactly where deterministic (policy ID, address, scriptPubKey, transaction, signature scope). A signature MUST verify against the independent digest, key, and sighash for its exact target. CTS does not require an identical signature nonce or signature byte sequence. Negative cases MUST be rejected or return the specified `unknown` state without making irreversible progress or leaking a signature. A refusal code MAY vary only where multiple outcomes are explicitly allowed by a CTS scenario. `UNSUPPORTED_POLICY`, `RESOURCE_LIMIT` and `DEVICE_CHECK_REQUIRED` MUST NOT be conflated.
4. The test harness MUST deliberately behave as a hostile host: lie about key origins and change, modify policies and PSBTs, reuse handles across seed/passphrase contexts, request wrong leaves and sighashes, and interrupt or reorder carrier data. Verifying host-rendered UI alone is insufficient.
5. Each positive mandatory CTS fixture establishes lower bounds on the resources it consumes. For every resource, the minimum for a claim is the greatest measured requirement among its applicable mandatory positive fixtures, with the explicit 4,096-byte container minimum also applied. A zero limit is permitted for an unused resource. A complete Miniscript profile MUST handle the published mandatory corpus, including at least two controlled derived key expressions, a third external cosigner, nontrivial nested AND/OR/threshold conditions and, for Tapscript, a three-leaf tree with depth two. Resource scenarios MUST test an otherwise valid input at the declared boundary and an otherwise valid input above it when those values can be represented. Where the protocol or language imposes a hard ceiling, use the largest representable valid input at or below the boundary and the corresponding encoding or semantic rejection beyond the hard ceiling. Record the resource, actual measurement, endpoint limit and observed outcome. A declared limit below the required corpus minimum makes the claim fail.
6. A claim is limited to the tested firmware, adapter, carrier and settings. A release or change that could alter parser behavior, policy review, key-context binding, signing, serialization, or secure display MUST rerun all affected tests before the prior claim is reused. If one mandatory test fails, the corresponding profile/feature claim MUST be removed or narrowed; a passing subset does not imply Full.
7. Because a finite suite does not prove all Miniscript compositions or resistance to malicious firmware, the CTS MUST combine fixed fixtures, type-directed generated valid/invalid policies, boundary testing, differential validation against independent Bitcoin Script/descriptor implementations, and device UI review. Exhaustive testing across arbitrary policies is not claimed.

#### 10.2 What conformance or certification means

A `capabilities` response is an unauthenticated statement by an endpoint. **This BIP does not create a certification authority, attestation root, vendor endorsement, security guarantee, or proof that an arbitrary physical device is running a particular firmware build.** Three distinct statements MUST NOT be conflated:

- **Declared support:** the endpoint advertises a feature. This is not test evidence.
- **Self-tested conformance:** the implementer publishes a reproducible CTS report for the exact tested endpoint and all claimed features.
- **Independently assessed conformance:** an identified independent evaluator repeats the applicable CTS and publishes its evidence and scope. The BIP does not authorize a particular evaluator or grant an official logo.

Test reports SHOULD include model, firmware build/hash (when available), adapter code revision, carrier binding, network, test suite version, test-case IDs, outcomes, negative-case evidence, independent validation software, observation of trusted-screen approvals, and any unresolved limitations. Reports MUST distinguish automatic test evidence from human-observed or source-reviewed signer behavior. A report hash or vendor signature only establishes integrity/attribution under separately established trust; it does not authenticate runtime firmware.

A software wallet MUST still call `check_policy`, obtain real device approval, and verify the address for the concrete policy prior to funding. Neither a published CTS report nor an attractive “Full” badge replaces those per-account checks.

### 11. Backup and recovery semantics

Before showing a complex account as ready for funding, the host SHOULD have completed a preflight without a known fatal issue, obtained actual device policy validation/approval, confirmed a receive address on the signer, and offered an exact portable policy backup. An unknown preflight is not enough: it must be resolved by the device's successful validation during approval and address derivation. These are separate steps. An opaque registration token is not a replacement for the policy backup.

Restoring the seed on a different signer does not transfer its previous registration handles or guarantee policy support. The new endpoint must validate and approve the same policy before it can derive or sign. If it cannot support that policy, it returns the incompatibility; it MUST NOT substitute a simpler script. Existing Bitcoin funds remain governed by their original script regardless of WSI version or vendor availability.

## Rationale

### Worked policy examples

The following templates illustrate script structure only; the key vectors, network and complete wire requests must also be supplied. The accompanying JSON vectors contain one complete encoding example using deliberately public test key material, never intended for deposits.

For an immediate key and a different recovery key after a relative delay of 144 blocks:

```
wsh(or_d(pk(@0/**),and_v(v:pk(@1/**),older(144))))
```

The signer validates the whole policy; the host chooses and constructs the witness. The delay is relative to the spent output's confirmation under CSV semantics, not to clicking a button or registering the wallet. Signing the recovery transaction early is distinct from it being mineable.

The same root xpub can supply two distinct roles using disjoint ranges:

```
wsh(or_d(pk(@0/<0;1>/*),and_v(v:pk(@0/<2;3>/*),older(144))))
```

At receive index `i`, the two keys are derived at `/0/i` and `/2/i`; at change index `i`, they are `/1/i` and `/3/i`. This does not make the two roles independent parties. It illustrates why “same seed,” “same xpub,” and “same derived public key” require different capability decisions.

For a Taproot key path plus two script leaves, one of which has an absolute height lock:

```
tr(@0/**,{pk(@1/**),and_v(v:pk(@2/**),after(1000000))})
```

A `tap-script` target for the second leaf must not silently become a `tap-key` target. The full tree and internal key are approved, while the requested signature identifies its exact leaf. No claim is made that a current device supports these examples until the precise object and integration have passed validation.

### Existing standards as the account and transaction model

Descriptors, BIP-388, BIP-379 and PSBT already separate key origins, spending conditions and transaction data. WSI references those semantics and adds operations, negotiation and security boundaries. A new script AST serialization or a new transaction container would duplicate mature work.

### Why explicit descriptors alongside BIP-388?

BIP-388 is a strong common basis for ranged accounts, but its portable core uses extended public keys and restricted derivations. Fixed external signing keys are legitimate descriptor inputs and may be supplied by HSM services. The descriptor-pair format makes their support explicit without reinterpreting BIP-388 or changing those keys. Existing xpub-only firmware can reject that format honestly.

### Why not one mandatory physical transport?

The inspected ecosystem includes APDU/Merkle exchanges, CBOR RPC, structured Protobuf signing, plaintext commands, files and QR workflows. Making USB or a persistent connection mandatory would exclude existing use cases. Stable application objects permit native firmware convergence and immediate adapters while retaining offline operation.

### Why signature deltas?

Some devices return individual signatures; others return a PSBT stripped of unrelated data. Returning narrowly scoped additions lets the host preserve the original PSBT and validate the exact result. It also separates signing from host-side finalization.

### Why opaque registration handles?

Device-held records, host-held authentication tokens and per-use approvals have different lifecycles. Their shared security property is approval of the same exact policy in the same signing-key context. Requiring one storage mechanism would reduce adoption without making policy review uniform.

### Why no generic spending-path authorization?

An arbitrary branch label does not appear in Bitcoin's signature preimage. The strongest general portable scope is the actual input, key, signature mode, sighash and, where applicable, Taproot leaf. A future satisfaction-plan extension may improve review but cannot change those cryptographic limits.

## Security and privacy considerations

The malicious-host model applies to all requests, including capability selection, policy names, origins, PSBT amounts, change hints and purported recovery branches. A firmware implementation must perform its own derivations and compile/validate the approved script. Host-rendered explanations are useful but are not trusted authorization.

Exact policy approval protects against script substitution and backup mismatch, not just theft in the immediate transaction. Equivalent lifted semantic policies can compile to different addresses. Device UI must make the exact registered object inspectable and keep its label bound to it.

The interface adds no device authentication or proof of correct firmware execution. An honest capability report and adapter conformance cannot be established solely by hashing their data. Supply-chain, firmware, pairing and secure-display assumptions remain explicit. Anti-exfiltration signing protocols may be integrated by a backend but are not standardized by this revision.

Public descriptors, xpubs and origins reveal wallet structure and can harm privacy. Capability discovery avoids stable wallet identifiers. Export and policy backups should remain local or explicitly shared. Registration tokens should be treated as sensitive metadata even though they are not spending keys.

Resource accounting, bounded parsing, duplicate-key rejection, and complete response correlation are required to limit parser confusion and denial of service. Processing a file or QR request must never bypass the approvals required over a connected transport.

This proposal does not guarantee that a transaction will be accepted by a mempool or mined. Script validity, policy support, authorized signatures, witness satisfiability, chain maturity and relay acceptance are different statements.

## Backward compatibility and deployment

No Bitcoin consensus upgrade is required. Existing descriptors, PSBTs and vendor protocols remain valid. A software-only adapter can provide WSI for operations whose underlying device already enforces the required security properties. Other capabilities require firmware changes. No existing device becomes conformant just because an adapter implements the method names.

The recommended experimental path is a shared WSI contract over an existing host library, plus at least two independently maintained native/backend integrations and one offline workflow. HWI/BHWI compatibility should be tested explicitly. Per-vendor commands remain adapter internals; host application code targets the standard objects and outcomes.

Changing a wallet's descriptor to satisfy a signer is a wallet migration, not protocol adaptation. Such a migration must never be automatic or disguised as serialization conversion.

## Test vectors and conformance plan

This section is the **WSI Conformance Test Specification (CTS), draft revision 0.2.1**. Its case IDs, applicability and expected security outcomes are normative requirements for a claim against this draft. This revision retains the 64 case IDs from the [archived 0.2.0 matrix](archive/v0.2.0/wsi-conformance-cases-v0.2.0.json). The [CTS manifest](cts/manifest.json) defines the scenarios, applicability, evidence and fixture references for executing the cases. The [harness specification](docs/harness.md) defines their execution through the tested endpoint, and the [conformance instructions](docs/conformance.md) define the assessment procedure.

The corpus provides fixed WSI and Bitcoin inputs and a contract for capability-expanded, generated, stateful, and operator-observed scenarios. The manifest includes reproducible profile resource floors for the published anchors. Additional claimed combinations use the size of the actual instantiated vectors. The CTS verifier exercises static fixture and reference-oracle checks. A hardware CTS result requires execution of every applicable scenario through the actual endpoint, including the specified device observations and release evidence. This working draft has no assessed hardware configurations.

Each case's independent oracle SHOULD use at least two independently maintained descriptor/Miniscript/script implementations where practical. Compare exact scripts and values, then execute final witnesses on regtest or another independent consensus-compatible script interpreter. At the cited upstream snapshot, BIP-379's `Test Vectors` section reads `TBD` and BIP-388 provides valid and invalid policy examples.

In the matrix below `CORE` is mandatory for all conformant endpoints. The next subsection specifies the mapping for `miniscript-wsh`, `miniscript-tapscript`, `descriptor-pair`, and the other named features. `each-advertised-*` covers every value listed in the capability response. `integration` requires an actual signer/backend, `device-ui` requires observation of the signer's trusted interface, and `process` requires the specified evidence or release-scoping procedure.

### Mandatory test cases

| Test ID | Applies when | Category | Stimulus | Required observable result |
|---|---|---|---|---|
| `WSI-ENC-001` | `CORE` | automated | Round-trip the canonical CBOR request/response and compare both frame formats with byte-exact known vectors. Exercise the endpoint's advertised binding in the carrier cases. | The decoded record, bytes, request_hash and policy_id match the independent reference exactly. |
| `WSI-ENC-002` | `CORE` | automated | Inject duplicate map keys, bad UTF-8, nonshort integers, indefinite lengths, tags, unsorted keys and trailing bytes. | All invalid/non-deterministic payloads fail before method dispatch; no signature or uncorrelated WSI response is produced. |
| `WSI-ENC-003` | `CORE` | automated | Alter response ID, request_hash, protocol version and required_features; repeat a request ID with different bytes. | Mismatched responses are rejected by the host; retained conflicting ID is rejected; unsupported features never silently fall back. |
| `WSI-ENC-004` | `CORE` | automated | Exercise the 4,096-byte minimum receive capacity, check the canonical `capabilities` request, and send overlength containers, excessive CBOR depth, incomplete frames, padded capabilities requests and out-of-range uint fields. | The advertised container limit is at least 4,096 bytes. Invalid values, containers and frames are rejected before unsafe allocation or execution. The valid `capabilities` request is accepted. |
| `WSI-CAP-001` | `CORE` | automated | Call capabilities while locked and in each claimed key context. | Schema and limits are valid, no serial/xpub/fingerprint is revealed, and unsupported operations are not claimed. |
| `WSI-CAP-002` | `CORE` | integration | Compare advertised features/enforcement with behavior through the actual adapter and actual signer. | The intersection is reported; host-only checks are never marked device-enforced. |
| `WSI-CAP-003` | `CORE` | integration | Execute advertised PSBT versions, transaction versions, sighashes and registration modes according to the scenario expansions, then test the applicable finite set of unsupported values. | Every required advertised combination works as specified. Unadvertised values fail without transaction or policy mutation. |
| `WSI-CAP-004` | `CORE` | process | Record an initial release baseline and repeat capability and regression tests after firmware, adapter, transport or configuration changes relevant to the claim. | Results identify the tested release tuple. Claims are withdrawn or retested after relevant changes. |
| `WSI-KEY-001` | `CORE` | device-ui | Export a reference xpub on an allowed path with user approval and derive several children independently. | Fingerprint, network, origin, xpub and derived children agree with the signer seed and reference implementation. |
| `WSI-KEY-002` | `CORE` | automated | Request a blocked path, a wrong network and a key for a different seed/passphrase. | No substitution or xprv/seed leakage; precise rejection or correctly scoped new approval. |
| `WSI-KEY-003` | `CORE` | device-ui | Deny get_key on the trusted device after a hostile host request. | No successful export or disclosure occurs following rejection. |
| `WSI-POL-001` | `CORE` | automated | Validate BIP-388 wpkh and 2-of-3 wsh(sortedmulti) accounts and compare exact policy identifiers and addresses. | Policy identity and scripts match independently derived expectations. |
| `WSI-POL-002` | `CORE` | automated | Submit invalid BIP-388 key vectors, duplicate xpubs, invalid derivation ranges, bad origins and wrong network. | Invalid/unsupported data are never approved; issue class accurately distinguishes invalid, unsafe and unsupported. |
| `WSI-POL-003` | `CORE` | automated | Check a supported policy read-only, exercising the host-preflight path if the device can validate only during interactive approval. | Device-validated preflight reports definitive support with `validation=device`. A host-only preflight reports `validation=host`, `support=unknown` and `DEVICE_CHECK_REQUIRED`. Preflight creates no approval. |
| `WSI-POL-004` | `CORE` | integration | For a supported account compare native signer validation with register_policy and sign_psbt checks. | Registration/signing revalidate the exact same policy; support is not cached solely from host preflight. |
| `WSI-POL-005` | `CORE` | automated | Use duplicate derived public keys within one Miniscript or hostile same-fingerprint-but-wrong-xpub origins. | Key ownership is verified from actual derived public keys; collisions are rejected under the applicable rules. |
| `WSI-POL-006` | `CORE` | automated | Provide a valid policy outside a functional capability and another over a declared numeric limit. | Distinct UNSUPPORTED_POLICY and RESOURCE_LIMIT outcomes; neither is mislabeled INVALID_POLICY. |
| `WSI-POL-007` | `CORE` | automated | Submit a provably invalid or unsafe policy and a policy whose device validity cannot be concluded read-only. | invalid/unsafe and unknown are kept distinct; unknown is never upgraded to supported by host inference. |
| `WSI-REG-001` | `CORE` | device-ui | Register a multisigner policy with external keys, absolute/relative locks where claimed, network, origin and full commitment. | Trusted device UI exposes actual terms; explicit approval precedes handle or signature. |
| `WSI-REG-002` | `CORE` | automated | Tamper with the policy, label, network and signer seed/passphrase context. Tamper with an opaque handle when a stored or token mode is supported. | Changed terms or key context cannot reuse prior approval. Invalid handles are rejected. Per-operation mode requires fresh approval of the actual terms and context. |
| `WSI-REG-003` | `CORE` | integration | Exercise every advertised stored, token and per-operation registration mode, including missing/stale registration. | Each mode has correct binding; per-operation mode obtains fresh trusted approval. |
| `WSI-REG-004` | `CORE` | device-ui | Reject registration on-device and attempt to reuse the rejected policy and label. | No successful registration, address confirmation or signature is granted by the rejected request. |
| `WSI-REG-005` | `CORE` | integration | Attempt to reuse approval after changing a bound field. When an adapter uses a vendor commitment covering only some WSI-approved fields, also try a host-generated wrapper hash. | A change to approved terms requires fresh device approval or rejection. The partial-commitment adapter path needs full fresh device review or returns unsupported. A host-generated wrapper hash never establishes device enforcement. |
| `WSI-ADR-001` | `CORE` | device-ui | Derive and display first receive/change and a later ranged address for the same approved account. | Address and scriptPubKey exactly match independent derivation, correct network, branch and index. |
| `WSI-ADR-002` | `CORE` | automated | Swap branch/index, policy, address or token between requests. | Host claims cannot alter the independently derived address; errors or correct displayed script are returned. |
| `WSI-ADR-003` | `CORE` | device-ui | Reject address confirmation on-device. | No success result with confirmed=true; host cannot substitute its own display. |
| `WSI-ADR-004` | `CORE` | integration | Request an index beyond 2^31-1. Where the supported policy format permits an account without change, request branch=1 for such an account. | Operation rejects without substituting branch=0 or another index. |
| `WSI-TX-001` | `CORE` | integration | Sign valid PSBTv0 and/or PSBTv2 for every advertised version and verify ECDSA signatures independently. | Exactly the requested targets are signed; unsigned transaction and unrelated PSBT data are unchanged. |
| `WSI-TX-002` | `CORE` | automated | Request unadvertised transaction nVersion and PSBT version values from the finite unsupported-value scenarios, including nVersion 3 when unadvertised. | Signer or adapter returns the specified unsupported error and preserves nVersion and PSBT semantics. |
| `WSI-TX-003` | `CORE` | automated | Change one target key, input, signature mode, sighash or leaf hash while keeping host-supplied labels unchanged. | Unrequested or forbidden scope never receives a signature; wrong scope is rejected. |
| `WSI-TX-004` | `CORE` | integration | Insert unknown non-conflicting PSBT fields and unrelated preexisting signatures, then sign. | Only valid signature deltas are returned and host retains original unknown fields and order-dependent semantics. |
| `WSI-TX-005` | `CORE` | automated | Inject conflicting PSBT key/value pairs, duplicate targets, fake already-present signatures or malformed deltas. | Request/patch rejected; no duplicate, forged or out-of-scope update silently merged. |
| `WSI-TX-006` | `CORE` | integration | Sign with complete matching prevtx for ALL inputs, including external inputs, and known input/output amounts. | Fee is computed from authenticated outpoints and shown as verified-prevouts. |
| `WSI-TX-007` | `CORE` | automated | Omit or falsify prevtx, witness UTXO value or outpoint, including a malicious external input. | Verified fee mode rejects with PREVOUT_DATA_REQUIRED or INVALID_PSBT; no unverified fee shown as verified. |
| `WSI-TX-008` | `CORE` | device-ui | Falsely bind an external output, another wallet or a same-seed different-policy output as change. Repeat without the false binding. | The false binding is rejected. Without the false binding, the output stays visible. Only a script matching the approved spending account's permitted change branch can be classified as change. |
| `WSI-TX-009` | `CORE` | device-ui | Spend from two policies with both actual change and external outputs. | All outputs and affected accounts are displayed under the conservative multi-account rule. |
| `WSI-TX-010` | `CORE` | automated | Change nLockTime, input nSequence, output amount, destination and PSBTv2 locktime fields between approval and signature. | Any change that alters the reviewed unsigned transaction requires new authorization; no silent repair. |
| `WSI-TX-011` | `CORE` | integration | Finalise host-side witness and verify transaction scripts with an independent engine on regtest. | Every produced signature validates; only intended executable satisfaction is used and accepted by independent script validation. |
| `WSI-TX-012` | `CORE` | integration | Try to sign twice where a valid requested partial signature already exists. | already-present returned only after exact-key/sighash verification; no new hidden signature generated. |
| `WSI-FEE-001` | `fee-unverified-opt-in` | device-ui | Use allow-unverified with insufficient prevtx data after explicitly enabling the feature. | Trusted display warns that aggregate fee is unverified; user opts in and response reports unverified; otherwise rejects. |
| `WSI-SCOPE-001` | `exact-signature-scope` | integration | Request one leaf/input/key/sighash from a PSBT with several otherwise-signable targets. | Only the requested signature is released; omitted targets remain untouched. |
| `WSI-SIGHASH-001` | `each-advertised-sighash` | integration | For each advertised ECDSA or Schnorr sighash, sign and verify exact digest semantics; request disallowed ones. | Each declared flag is honored exactly; unadvertised flags do not silently change to ALL/DEFAULT. |
| `WSI-DPA-001` | `descriptor-pair` | automated | Accept valid receive and change checksummed descriptors with the same AST and distinct allowed derivation suffixes. | Both scripts/branches and paired account identity match independent derivation. |
| `WSI-DPA-002` | `descriptor-pair` | automated | Mutate checksum, change thresholds, timelocks, internal key, key origins, wildcard shape or Taproot tree. | Pair mismatch/invalid checksum is rejected; a weaker change policy is never silently accepted. |
| `WSI-DPA-003` | `raw-external-keys` | device-ui | Register fixed external public keys and a fixed device-owned public key with a verifiable origin in valid contexts. | Device distinguishes ownership, proves its owned key, warns where a fixed key creates address reuse/linkability. |
| `WSI-DPA-004` | `descriptor-pair` | integration | Approve a descriptor without change and attempt branch=1 address and change output classification. | No branch=1 derivation or hidden change is allowed. |
| `WSI-WSH-001` | `miniscript-wsh` | differential | Generate safe type-correct BIP-379 WSH ASTs covering every applicable fragment and wrapper, including nested AND/OR/thresh. | All within-envelope cases compile to expected scripts and accept correct satisfaction cases; no unsupported safe fragment is claimed Full. |
| `WSI-WSH-002` | `miniscript-wsh` | negative | Generate context-invalid, type-invalid, malleable or unsigned-satisfaction WSH expressions and duplicate derived keys. | Unsafe/invalid policies are rejected by device validation and cannot be registered. |
| `WSI-WSH-003` | `hashlocks+miniscript-wsh` | integration | Exercise sha256, hash256, ripemd160 and hash160 with correct 32-byte preimages, wrong digests and wrong lengths. | Correct cases validate; wrong/undersized preimages never satisfy or bypass safety analysis. |
| `WSI-WSH-004` | `timelocks+miniscript-wsh` | integration | Exercise CLTV height/time and CSV block/512-second types across lock boundary, disable flag and transaction version. | Correct flags/units are preserved and interpreted; invalid combinations are rejected; presigning is not misreported as maturity. |
| `WSI-WSH-005` | `multiple-owned-keys+miniscript-wsh` | integration | Use two controlled derived public keys from one xpub on disjoint ranges plus an independent external cosigner. | Both matching keys can sign where requested without conflating distinct derivations or claiming they are independent seed holders. |
| `WSI-WSH-006` | `miniscript-wsh` | integration | Sign a nested 2-of-3/threshold WSH recovery path and finalise it using a different host implementation. | Independent script interpreter accepts intended witness and rejects invalid/missing signatures. |
| `WSI-TR-001` | `miniscript-tapscript` | differential | Generate safe BIP-379 Tapscript leaves covering every applicable fragment/wrapper and a three-leaf depth-2 tree. | Independent descriptor/script engine matches each leaf hash, root, output key, scriptPubKey and valid satisfactions. |
| `WSI-TR-002` | `miniscript-tapscript` | negative | Generate invalid type/context, unsafe, duplicate-key and prohibited timelock-mixing policies for Tapscript. | Device rejects rather than treating unsupported syntax as another script path. |
| `WSI-TR-003` | `taproot-keypath` | integration | Sign a plain tr() key-path-only account; then request the same input under tap-script mode with no approved leaf. | Key-path signing succeeds only when explicitly requested and permitted; it is never substituted for an unavailable leaf. |
| `WSI-TR-004` | `taproot-scriptpath` | integration | Sign a real leaf; corrupt leaf hash, sibling hash, control block, internal key, leaf version or output tweak. | Actual script-path target verifies; every tampered route fails without a signature for a different leaf. |
| `WSI-TR-005` | `miniscript-tapscript` | integration | Sign a multi_a() threshold leaf and independently construct a witness with correct CHECKSIGADD ordering. | Independent script interpreter verifies valid stack and rejects missing/wrong signatures. |
| `WSI-TR-006` | `hashlocks+miniscript-tapscript` | integration | Exercise all four hashlocks and CLTV/CSV height/time forms inside safe Tapscript leaf compositions. | All claimed combinations follow BIP-379 rules and are verified against independent witness execution. |
| `WSI-TR-007` | `multiple-owned-keys+miniscript-tapscript` | integration | Build Tapscript leaves with two signer-controlled keys on disjoint derivation paths from the same xpub and an external cosigner. | Both derived keys are proven to belong to the device, can sign exact requested leaves, and never count as separate independent seed holders. |
| `WSI-CAR-001` | `each-advertised-carrier` | integration | Execute representative core lifecycle on every advertised file/stream binding, including an offline signer when claimed. | Same payloads, commitments, approvals and outputs; no undisclosed online callback. |
| `WSI-CAR-002` | `each-advertised-carrier` | negative | Truncate stream, split frame, reorder/duplicate QR segments, replay stale files and exceed advertised container bounds. | No partial request is executed and no fragmented or stale data can bypass approval. |
| `WSI-CAR-003` | `CORE` | process | Cancel approval, lose response after signing, reset the signer and retry original request. | Host treats lost response as unknown, does not claim signature revocation, and preserves exact transaction approvals. |
| `WSI-UI-001` | `CORE` | device-ui | With hostile host-provided title and change metadata, independently inspect policy, key roles, network, timelocks, hashlocks and outputs on the signer. | Device-approved content matches exact policy/transaction; no host-only UI can fulfill device enforcement. |
| `WSI-UI-002` | `CORE` | device-ui | Refuse at each sensitive boundary (key export, policy approval, address display and signing) and observe device/API behavior. | Refusal cannot be converted into success, stored authorization or release of a new signature. |

#### CTS capability-to-test map

Tests for each advertised PSBT or transaction version, sighash, carrier and registration mode MUST cover every listed value. Each network included in a claim MUST be tested. The CTS manifest expands the scenarios using the actual capability response and its contextual conditions. For complete WSH and Tapscript profile claims, the relevant hashlock, timelock and multiple-owned-key cases are mandatory regardless of whether the corresponding feature strings are listed. For feature claims without a complete profile, the contextual rows below select the matching scenarios in each applicable context. A fragment listed in a subset declaration MUST be tested in its advertised context and within the advertised restrictions.

A mandatory case can contain conditional scenarios, such as checks for an opaque handle only in a mode that issues one. Scenario conditions MUST be derived from the endpoint declaration, its tested configuration and the scenario's setup. Skipping a scenario never waives the remaining scenarios in that case. A scenario exercising an unadvertised value MUST use the finite selection defined by the CTS, within the field's representable protocol domain. For u32 fields this domain spans 0 through 4,294,967,295. An out-of-range integer is tested separately as an invalid field. If there is no unadvertised value in the applicable domain, the unadvertised-value scenario is inapplicable, and all advertised positive scenarios remain mandatory.

| Advertised feature | Additional named cases |
|---|---|
| `policy-bip388` | `WSI-POL-001`, `WSI-POL-002`, `WSI-REG-001` |
| `descriptor-pair` | `WSI-DPA-001`, `WSI-DPA-002`, `WSI-DPA-004` |
| `miniscript-wsh` | `WSI-WSH-001`, `WSI-WSH-002`, `WSI-WSH-006` |
| `miniscript-tapscript` | `WSI-TR-001`, `WSI-TR-002`, `WSI-TR-005` |
| `hashlocks` | `WSI-WSH-003` if WSH is claimed; `WSI-TR-006` if Tapscript is claimed |
| `cltv-height` | `WSI-WSH-004` if WSH is claimed; `WSI-TR-006` if Tapscript is claimed |
| `cltv-time` | `WSI-WSH-004` if WSH is claimed; `WSI-TR-006` if Tapscript is claimed |
| `csv-blocks` | `WSI-WSH-004` if WSH is claimed; `WSI-TR-006` if Tapscript is claimed |
| `csv-time` | `WSI-WSH-004` if WSH is claimed; `WSI-TR-006` if Tapscript is claimed |
| `raw-external-keys` | `WSI-DPA-003` |
| `multiple-owned-keys` | `WSI-WSH-005` if WSH is claimed; `WSI-TR-007` if Tapscript is claimed |
| `taproot-keypath` | `WSI-TR-003` |
| `taproot-scriptpath` | `WSI-TR-004` |
| `exact-signature-scope` | `WSI-SCOPE-001`, `WSI-TX-003` |
| `fee-unverified-opt-in` | `WSI-FEE-001` |

The `WSI-TR-*` tests for a Tapscript-only profile do **not** imply support for MuSig2 signing sessions; Taproot key-path signature support is distinct from threshold nonce orchestration. The device MUST NOT claim `wsi-miniscript-full-v1` on the strength of a WSH-only or Tapscript-only corpus. A subset-capability declaration MUST document which operations and safe policy compositions it actually supports; named fragments by themselves do not constitute a Full claim.

### Test report and decision rule

A test record MUST identify the case ID and scenario instance, outcome (`pass`, `fail`, `not-run`, or `inapplicable`), endpoint build and configuration, fixture identifier, and evidence reference. `inapplicable` requires a documented nonmatching applicability condition. A mandatory case requires evidence of every applicable scenario. An `unknown` result from read-only `check_policy` can pass only a scenario that permits it under section 6.2. A successful device approval and verified address are still required for an account treated as usable.

A conformant endpoint claim requires `pass` for every scenario implied by the declared profiles, features, networks, individual versions, registration modes and carriers. A failure, a `not-run` result or missing evidence for any required scenario prevents that claim. A product may advertise a narrower capability set after assessing the narrowed declaration. Independent evaluators and self-testing vendors SHOULD publish their report with the evidence references, including any failures, omissions and tool versions.

Tests cannot prove a device is honest, uncompromised or remotely authenticated, and WSI does not introduce a certification authority. Those claims require separate governance, provenance and possibly firmware-attestation standards. A conformance report is scoped evidence, not an assurance of secure supply chain or future behavior.

## Reference implementation

This repository's verifier checks the CTS corpus and its reference oracles. The [hardware runner project](https://github.com/RiccardoBiffi/wsi-miniscript-runner) is the implementation location for the harness contract and vendor adapters. Existing HWI, BHWI, firmware clients and Miniscript libraries remain implementation candidates and prior art.

## Open design questions before submission

- Obtain feedback from host-library maintainers and at least two hardware vendors on protocol scope and whether physical carrier bindings should be companion specifications.
- Independently validate the CTS corpus, resource minima and signed and unsigned PSBT oracles. Exercise the applicable suite on physical signers and benchmark the policy UI and constrained-device parsing costs.
- Evaluate the strict `verified-prevouts` fee mode against bandwidth/memory constraints and possible separately specified proof mechanisms.
- Review descriptor-pair structural matching and ranged-key alias rules with Miniscript implementers and compare the descriptor vectors across implementations.
- Decide whether future MuSig2/anti-exfiltration support should be separate BIPs or named extensions; specify their nonce/session lifecycle before enabling them.
- Complete author contact, establish a real public discussion reference, and follow the current BIP-3 submission process. No discussion URL or BIP number is invented here.

## References

Normative dependencies are read as specifications, not as promises about any product's deployment. The investigation used the bitcoin/bips snapshot `a7f91321f25b5be8d93e901775621c21519e80b7` observed on 2026-11-20.

- [BIP-3: Updated BIP Process](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0003.md)
- [BIP-32: HD Wallets](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0032.mediawiki)
- [BIP-174: PSBT](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0174.mediawiki)
- [BIP-370: PSBT Version 2](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0370.mediawiki)
- [BIP-371: Taproot PSBT fields](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0371.mediawiki)
- [BIP-379: Miniscript](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0379.md)
- [BIP-380: Descriptor general operation](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0380.mediawiki)
- [BIP-382: SegWit descriptors](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0382.mediawiki)
- [BIP-386: Taproot descriptors](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0386.mediawiki)
- [BIP-388: Wallet Policies](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0388.mediawiki)
- [BIP-389: Multipath key expressions](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0389.mediawiki)
- [RFC-8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [HWI interface, reviewed snapshot](https://github.com/bitcoin-core/HWI/blob/e63a0af2bf5c7c60b8cc71d99aba59068e8be0f0/hwilib/hwwclient.py)
- [BHWI, reviewed snapshot](https://github.com/wizardsardine/bhwi/tree/401105e98055b9a4ba4cbb86fb768d87a8a068a7)
- [async-hwi, reviewed snapshot](https://github.com/wizardsardine/async-hwi/tree/e365c4c8eb2280c8e0c9f16b7e145a924bff33c4)
- [Detached Signing / Hardware Wallet Standard discussion, 2016](https://mirror.b10c.me/lists/bitcoindev/CAJna-Hi3a5mLBkXfS4Qa=kjFCj4=GVBr4WUDZ=Tg27iX=FiCJA@mail.gmail.com/t/)

The companion research report contains the firmware snapshots, native operation mappings, implementation limits and release/source distinctions underlying the design.

## Changelog

- 0.2.1 (2026-11-24): published the CTS manifest and companion fixtures, specified hardware harness and assessment procedures, and clarified applicability, resource minima, receive capacity and evidence rules. Protocol version remains 1.
- 0.2.0 (2026-11-21): clarified semantic interoperability versus API compatibility; made capability declarations conditional on explicit CTS outcomes; added case IDs, per-feature test mapping, evidence rules and certification limitations; corrected the BIP-379 test-vector status.
- 0.1.0 (2026-11-20): initial author working draft, repository evidence review, protocol/security model, and illustrative encoding vectors.
