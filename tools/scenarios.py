"""Runner-neutral, executable scenario definitions for the original 64 case IDs."""

from itertools import product

from bitcoin_fixtures import CLTV_HEIGHT, CLTV_TIME, CSV_BLOCKS, CSV_TIME


WSH = "wsi-miniscript-wsh-v1"
TAP = "wsi-miniscript-tapscript-v1"
FULL = "wsi-miniscript-full-v1"

LOCKS = {
    "cltv-height": {"field": "locktime", "valid": CLTV_HEIGHT, "invalid": CLTV_HEIGHT - 1},
    "cltv-time": {"field": "locktime", "valid": CLTV_TIME, "invalid": CLTV_TIME - 1},
    "csv-blocks": {"field": "sequence", "valid": CSV_BLOCKS, "invalid": CSV_BLOCKS - 1},
    "csv-time": {"field": "sequence", "valid": CSV_TIME, "invalid": CSV_TIME - 1},
}
HASHES = ("sha256", "hash256", "ripemd160", "hash160")

CASE_FEATURES = {
    "WSI-FEE-001": "fee-unverified-opt-in",
    "WSI-SCOPE-001": "exact-signature-scope",
    "WSI-DPA-001": "descriptor-pair",
    "WSI-DPA-002": "descriptor-pair",
    "WSI-DPA-003": "raw-external-keys",
    "WSI-DPA-004": "descriptor-pair",
    "WSI-TR-003": "taproot-keypath",
    "WSI-TR-004": "taproot-scriptpath",
}


def step(op, **arguments):
    return {"op": op, **arguments}


def call(method, fixture=None, *, user="approve", **parameters):
    result = step("exchange", method=method, user=user, parameters=parameters)
    if fixture is not None:
        result["fixture"] = fixture
    return result


def wire(asset, *, direction="request", **arguments):
    return step("wire", asset=asset, direction=direction, **arguments)


def check(predicate, **arguments):
    return {"predicate": predicate, **arguments}


def terminal(*codes):
    return check("terminal", allowed=list(codes))


def sign(fixture="wpkh", *, user="approve", **arguments):
    return call("sign_psbt", f"bitcoin:policies.{fixture}", user=user, **arguments)


def policy(method, fixture="wpkh", *, user="approve", **arguments):
    return call(method, f"bitcoin:policies.{fixture}", user=user, **arguments)


def address(fixture="wpkh", *, branch=0, index=0, user="approve", **arguments):
    return policy("display_address", fixture, branch=branch, index=index, user=user, **arguments)


def _profile(name):
    return f"profile:{name}"


def _feature(name):
    return f"feature:{name}"


def _claim(context, feature):
    profile = WSH if context == "wsh" else TAP
    return [[_profile(profile)], [_profile(FULL)], [f"context:{context}", _feature(feature)]]


def _rules(case_id):
    if case_id in CASE_FEATURES:
        rules = [[_feature(CASE_FEATURES[case_id])]]
        if case_id.startswith("WSI-DPA"):
            rules.append([_profile(FULL)])
        if case_id.startswith("WSI-TR"):
            rules.extend([[_profile(TAP)], [_profile(FULL)]])
        return rules
    if case_id.startswith("WSI-WSH"):
        return _claim("wsh", "miniscript-wsh")
    if case_id.startswith("WSI-TR"):
        return _claim("tapscript", "miniscript-tapscript")
    return [[]]


def build_cases(source):
    cases = {case["id"]: {**case, "scenarios": []} for case in source}

    def add(case_id, name, steps, assertions, *, axes=(), requires=None, evidence=("wire",)):
        record = cases[f"WSI-{case_id}"]
        record["scenarios"].append({
            "id": name,
            "requires": _rules(record["id"]) if requires is None else requires,
            "axes": list(axes),
            "steps": steps,
            "assertions": assertions,
            "evidence": list(evidence),
        })

    codec = ("wire", "oracle")
    review = ("wire", "device-ui")
    signing = ("wire", "oracle", "device-ui")
    signer = ("wire", "device-path")
    state = ("wire", "device-ui", "process")
    sig = check("exact-signatures")
    preserved = check("psbt-preserved")
    no_effect = check("no-new-authorization-or-signature")

    add("ENC-001", "file-stream-reference", [
        step("oracle", action="codec", catalog="wsi"),
        call("capabilities", user="none"),
    ], [terminal("success"), check("deterministic-encoding"), check("correlation")], evidence=codec)
    malformed = (
        "duplicate-key", "invalid-utf8", "nonshort-uint", "nonshort-length", "indefinite-map",
        "tag", "float", "negative-uint", "unsorted-map", "trailing-byte",
    )
    for name in malformed:
        add("ENC-002", name, [wire(f"wsi:invalid_cbor.{name}")],
            [terminal("carrier-reject"), no_effect])
    for name in ("wrong-id", "wrong-hash", "wrong-version"):
        add("ENC-003", name, [
            wire("wsi:records.capabilities"),
            wire(f"wsi:records.{name}-response", direction="response"),
        ], [terminal("host-reject"), check("no-merge")])
    for name, expected in (
        ("required-unknown-feature", "UNSUPPORTED_FEATURE"),
        ("unknown-version", "UNSUPPORTED_VERSION"),
        ("closed-record", "INVALID_REQUEST"),
    ):
        add("ENC-003", name, [wire(f"wsi:records.{name}")],
            [terminal(expected), check("correlation"), no_effect])
    add("ENC-003", "retained-id-conflict", [
        wire("wsi:records.capabilities"), wire("wsi:records.conflicting-id", retained_id=True),
    ], [terminal("REQUEST_ID_CONFLICT"), no_effect])
    for name in ("depth-65", "uint32-overflow", "map-overclaim"):
        add("ENC-004", name, [wire(f"wsi:invalid_cbor.{name}")],
            [terminal("carrier-reject"), check("bounded-parser"), no_effect], evidence=signer)
    for name in ("over-limit-stream", "short-stream"):
        add("ENC-004", name, [wire(f"wsi:invalid_carriers.{name}")],
            [terminal("carrier-reject"), no_effect], requires=[["carrier:stream"]])
    add("ENC-004", "closed-envelope-at-4096", [wire("wsi:records.limit-4096")],
        [terminal("INVALID_REQUEST"), check("correlation"), no_effect])
    add("ENC-004", "advertised-boundaries", [
        call("capabilities", user="none"),
        step("oracle", action="resource-boundaries", offsets=[-1, 0, 1]),
    ], [check("resource-boundaries"), no_effect], evidence=("wire", "oracle", "device-path"))

    for context in ("locked", "A", "A-with-passphrase"):
        add("CAP-001", f"discovery-{context.lower()}", [
            step("device", action="select-key-context", context=context),
            call("capabilities", user="none"),
        ], [terminal("success"), check("capability-schema"), check("no-key-disclosure")])
    add("CAP-002", "effective-endpoint", [
        call("capabilities", user="none"),
        step("oracle", action="compare-enforcement", fields=[
            "policy_validation", "policy_review", "address_display", "change_verification",
            "signature_scope",
        ]),
    ], [check("claims-match-device-enforcement")], evidence=("wire", "device-ui", "device-path"))
    add("CAP-003", "advertised-ecdsa-combination", [
        policy("register_policy", registration_mode="$registration_mode"),
        sign(psbt_version="$psbt_version", tx_version="$transaction_version",
             sighash="$ecdsa_sighash"),
    ], [terminal("success"), sig, preserved],
        axes=("psbt_version", "transaction_version", "registration_mode", "ecdsa_sighash"),
        evidence=signing)
    add("CAP-003", "advertised-schnorr-combination", [
        sign("tr-key", psbt_version="$psbt_version", tx_version="$transaction_version",
             sighash="$schnorr_sighash", registration_mode="$registration_mode"),
    ], [terminal("success"), sig, preserved], axes=(
        "psbt_version", "transaction_version", "registration_mode", "schnorr_sighash",
    ), requires=[[_feature("taproot-keypath")], [_profile(TAP)], [_profile(FULL)]],
        evidence=signing)
    add("CAP-003", "advertised-schnorr-script-combination", [
        sign("tr-tree", psbt_version="$psbt_version", tx_version="$transaction_version",
             sighash="$schnorr_sighash", registration_mode="$registration_mode", leaf=0),
    ], [terminal("success"), sig, preserved], axes=(
        "psbt_version", "transaction_version", "registration_mode", "schnorr_sighash",
    ), requires=[[_feature("taproot-scriptpath")], [_profile(TAP)], [_profile(FULL)]],
        evidence=signing)
    add("CAP-003", "unadvertised-registration-mode", [
        step("assessment", action="check-unadvertised-registration-mode",
             modes=["stored", "token", "per-operation"]),
    ], [check("unadvertised-registration-not-usable"), no_effect], evidence=signer)
    add("CAP-004", "configuration-change", [
        step("assessment", action="compare-report-scope",
             changed_fields=["firmware", "adapter", "binding", "configuration"]),
    ], [check("changed-scope-requires-retest")], evidence=("process",))

    derivation = [2**31 + 84, 2**31 + 1, 2**31]
    add("KEY-001", "export-and-derive", [
        call("get_key", "bitcoin:accounts.signer-84-0", network="$network", path=derivation),
    ], [terminal("success"), check("device-key-export", children=[0, 1])], evidence=signing)
    add("KEY-002", "unsupported-path", [
        call("get_key", network="$network", path=[2**31] * 256),
    ], [terminal("UNSUPPORTED_DERIVATION", "RESOURCE_LIMIT"), check("no-key-disclosure")])
    add("KEY-002", "unsupported-network", [
        call("get_key", network="regtest-cts-invalid", path=derivation),
    ], [terminal("UNSUPPORTED_NETWORK", "INVALID_REQUEST"), check("no-key-disclosure")])
    add("KEY-002", "changed-key-context", [
        step("device", action="select-key-context", context="A"),
        call("get_key", "bitcoin:accounts.signer-84-0", network="$network", path=derivation),
        step("device", action="select-key-context", context="B"),
        call("get_key", "bitcoin:accounts.cosigner-84-0", network="$network", path=derivation),
    ], [terminal("success"), check("fresh-key-context-approval")], evidence=signing)
    add("KEY-003", "reject-key-export", [
        call("get_key", network="$network", path=derivation, user="reject"),
    ], [terminal("USER_REJECTED"), check("no-key-disclosure")], evidence=review)

    for fixture in ("wpkh", "wsh-sortedmulti"):
        add("POL-001", fixture, [
            policy("check_policy", fixture, user="none"),
            policy("register_policy", fixture),
            address(fixture),
        ], [terminal("success"), check("policy-id"), check("descriptor-derivation")], evidence=signing)
    for mutation in ("key-vector-count", "duplicate-key-expression", "overlapping-key-range",
                     "malformed-origin", "wrong-xpub-network"):
        add("POL-002", mutation, [
            policy("check_policy", "wsh-sortedmulti", user="none", mutation=mutation),
            policy("register_policy", "wsh-sortedmulti", mutation=mutation),
        ], [check("policy-rejection-class", mutation=mutation), no_effect], evidence=signer)
    add("POL-003", "read-only-preflight", [
        policy("check_policy", user="none"),
    ], [check("preflight-evidence", host_issue="DEVICE_CHECK_REQUIRED"), no_effect],
        evidence=signer)
    add("POL-004", "signing-revalidates", [
        policy("check_policy", user="none"), policy("register_policy"), sign(),
        sign(mutation="changed-spending-script"),
    ], [terminal("POLICY_MISMATCH"), sig, check("exact-policy-revalidated")], evidence=signing)
    for mutation in ("same-fingerprint-wrong-xpub", "duplicate-derived-pubkey"):
        add("POL-005", mutation, [policy("register_policy", "wsh-sortedmulti", mutation=mutation)],
            [terminal("INVALID_POLICY", "UNSAFE_POLICY", "KEY_NOT_OWNED"), no_effect], evidence=signer)
    add("POL-006", "functional-and-resource", [
        step("oracle", action="policy-limits", values=["unsupported-valid-policy", "above-limit"]),
    ], [check("distinct-policy-errors", codes=["UNSUPPORTED_POLICY", "RESOURCE_LIMIT"])],
        evidence=signer)
    for mutation in ("unsafe-public-satisfaction", "invalid-key-encoding"):
        add("POL-007", mutation, [
            policy("check_policy", "wsh-sortedmulti", user="none", mutation=mutation),
        ], [check("policy-rejection-class", mutation=mutation), no_effect], evidence=signer)
    add("POL-007", "device-check-unavailable", [
        step("device", action="select-key-context", context="locked"),
        policy("check_policy", user="none"),
    ], [check("unknown-when-device-validation-unavailable"), no_effect], evidence=signer)

    add("REG-001", "review-exact-policy", [
        policy("register_policy", "wsh-sortedmulti", label="CTS vault"),
    ], [terminal("success"), check("trusted-policy-review")], evidence=review)
    for context, prefix in (("wsh", "wsh"), ("tapscript", "tr")):
        for name, suffix in (("cltv-height", "cltv-height"), ("csv-blocks", "csv")):
            add("REG-001", f"{context}-{name}", [
                policy("register_policy", f"{prefix}-{suffix}", label="CTS timed vault"),
            ], [terminal("success"), check("trusted-policy-review")],
                requires=_claim(context, name), evidence=review)
    for mutation in ("changed-handle", "changed-label", "changed-network", "changed-policy",
                     "changed-key-context"):
        for mode in ("stored", "token"):
            add("REG-002", f"{mode}-{mutation}", [
                policy("register_policy", registration_mode=mode, save="registration"),
                address(mutation=mutation, registration="$registration"),
            ], [terminal("INVALID_REGISTRATION", "POLICY_MISMATCH", "UNSUPPORTED_NETWORK"), no_effect],
                requires=[[f"registration_mode:{mode}"]], evidence=signer)
    add("REG-002", "per-operation-no-handle", [
        policy("register_policy", registration_mode="per-operation"),
        address(user="reject", registration_mode="per-operation"),
    ], [terminal("USER_REJECTED"), check("fresh-policy-approval"), no_effect],
        requires=[["registration_mode:per-operation"]], evidence=review)
    for mode in ("stored", "token", "per-operation"):
        add("REG-003", mode, [
            policy("register_policy", registration_mode=mode, save="registration"),
            address(registration_mode=mode, registration="$registration"),
            address(registration_mode=mode, registration=None, user="reject"),
        ], [check("registration-mode-binding", mode=mode)],
            requires=[[f"registration_mode:{mode}"]], evidence=review)
    add("REG-004", "rejection-is-not-registration", [
        policy("register_policy", user="reject", label="CTS refused"),
        address(user="reject", label="CTS refused", registration=None),
        sign(user="reject", label="CTS refused", registration=None),
    ], [check("refusal-or-missing-approval"), no_effect], evidence=state)
    add("REG-005", "equivalent-device-commitment", [
        step("device", action="identify-policy-commitment"),
        policy("register_policy", label="CTS commitment"),
        sign(mutation="changed-label", user="reject"),
    ], [check("device-commitment-or-fresh-review"), no_effect], evidence=signer)
    add("REG-005", "partial-vendor-commitment", [
        step("device", action="identify-policy-commitment"),
        policy("register_policy", label="CTS commitment"),
        sign(mutation="host-only-commitment", user="reject"),
    ], [check("device-commitment-or-fresh-review"), no_effect],
        requires=[["mode:adapter"]], evidence=signer)

    for branch, index in ((0, 0), (1, 0), (0, 1), (1, 1)):
        add("ADR-001", f"branch-{branch}-index-{index}", [
            address(branch=branch, index=index),
        ], [terminal("success"), check("trusted-address-and-script")], evidence=signing)
    for mutation in ("changed-branch-index", "changed-policy", "changed-handle", "host-address"):
        add("ADR-002", mutation, [address(branch=1, index=1, mutation=mutation)],
            [check("trusted-address-or-refusal")], evidence=signing)
    add("ADR-003", "reject-address", [address(user="reject")],
        [terminal("USER_REJECTED"), check("no-confirmed-address")], evidence=review)
    add("ADR-004", "hardened-address-index", [address(index=2**31)],
        [terminal("UNSUPPORTED_DERIVATION", "INVALID_REQUEST"), no_effect])
    add("ADR-004", "descriptor-without-change", [
        address(branch=1, format="descriptor-pair-v1", omit_change=True),
    ], [terminal("UNSUPPORTED_DERIVATION", "INVALID_REQUEST"), no_effect],
        requires=_rules("WSI-DPA-004"))

    add("TX-001", "exact-ecdsa-signature", [sign(psbt_version="$psbt_version")],
        [terminal("success"), sig, preserved], axes=("psbt_version",), evidence=signing)
    for field, values in (
        ("transaction_version", [0, 1, 2, 3, 4, 2**31 - 1, 2**31, 2**32 - 1]),
        ("psbt_version", [0, 1, 2, 3, 2**32 - 1]),
    ):
        add("TX-002", f"unadvertised-{field.replace('_', '-')}", [
            step("oracle", action="unsupported-wire-values", field=field, values=values,
                 fixture="bitcoin:policies.wpkh"),
        ], [check("unsupported-version-without-conversion", field=field), no_effect], evidence=codec)
    for mutation in ("target-key", "target-input", "target-mode", "target-sighash"):
        add("TX-003", mutation, [sign(mutation=mutation)],
            [check("wrong-target-rejected", mutation=mutation), no_effect], evidence=signer)
    add("TX-003", "target-leaf", [sign("tr-tree", mutation="target-leaf")],
        [check("wrong-target-rejected", mutation="target-leaf"), no_effect],
        requires=_rules("WSI-TR-004"), evidence=signer)
    add("TX-004", "preserve-unknown-fields", [
        sign(mutation="unrelated-maps-and-signatures", psbt_version="$psbt_version"),
    ], [terminal("success"), sig, preserved], axes=("psbt_version",), evidence=signing)
    for mutation in ("duplicate-psbt-key", "duplicate-target", "forged-existing-signature"):
        add("TX-005", mutation, [sign(mutation=mutation)],
            [terminal("INVALID_PSBT", "INVALID_REQUEST"), no_effect])
    for mutation in ("conflicting-delta", "wrong-delta-signature", "out-of-scope-delta"):
        add("TX-005", mutation, [
            step("oracle", action="negative-patch", mutation=mutation, fixture="bitcoin:policies.wpkh"),
        ], [terminal("host-reject"), check("no-merge")], evidence=codec)
    add("TX-006", "all-transaction-prevouts", [sign(external_input=True)],
        [terminal("success"), sig, check("verified-fee-and-display")], evidence=signing)
    for mutation, code in (
        ("missing-prevtx", "PREVOUT_DATA_REQUIRED"),
        ("wrong-prevtx", "INVALID_PSBT"),
        ("wrong-witness-value", "INVALID_PSBT"),
        ("wrong-prevout-index", "INVALID_PSBT"),
    ):
        add("TX-007", mutation, [sign(external_input=True, mutation=mutation)],
            [terminal(code), no_effect], evidence=signer)
    for output in ("external", "other-account", "same-seed-other-policy"):
        add("TX-008", f"false-{output}", [
            sign(change_destination=output, claim_change=True),
        ], [terminal("POLICY_MISMATCH"), no_effect], evidence=review)
        add("TX-008", f"unclassified-{output}", [
            sign(change_destination=output, claim_change=False),
        ], [terminal("success"), check("all-unclassified-outputs-visible")], evidence=review)
    add("TX-008", "verified-change-control", [sign(claim_change=True)],
        [terminal("success"), check("change-matches-approved-output")], evidence=signing)
    add("TX-009", "two-spending-accounts", [
        sign(policies=["wpkh", "wpkh-account-1"], claim_change=True),
    ], [terminal("success"), sig, check("all-outputs-and-accounts-visible")], evidence=signing)
    for field, value in (("locktime", 123), ("sequence", 123), ("output-value", 1),
                         ("output-script", "external"), ("v2-required-locktime", 123)):
        requires = [["psbt_version:2"]] if field == "v2-required-locktime" else None
        add("TX-010", field, [
            step("carrier", action="change-after-review", field=field, value=value,
                 fixture="bitcoin:policies.wpkh", psbt_version=2 if requires else "$preferred_psbt"),
        ], [check("original-or-new-approval"), check("no-silent-transaction-repair")],
            requires=requires, evidence=("wire", "device-ui", "device-path"))
    add("TX-011", "independent-finalization", [sign(),
        step("oracle", action="finalize-and-test-regtest", fixture="bitcoin:policies.wpkh"),
    ], [terminal("success"), sig, check("witness-valid")], evidence=signing)
    add("TX-012", "already-present-valid", [sign(save="signature"),
        sign(existing_signature="$signature"),
    ], [terminal("success"), check("already-present-without-delta"),
        check("no-new-signature-issuance")], evidence=("wire", "oracle", "device-path"))
    add("FEE-001", "unverified-explicit-opt-in", [
        sign(external_input=True, mutation="missing-prevtx", fee_mode="allow-unverified"),
    ], [terminal("success"), check("trusted-unverified-fee-warning"), sig], evidence=signing)
    add("FEE-001", "unverified-refused", [
        sign(external_input=True, mutation="missing-prevtx", fee_mode="allow-unverified",
             user="reject"),
    ], [terminal("USER_REJECTED"), check("trusted-unverified-fee-warning"), no_effect],
        evidence=review)
    add("SCOPE-001", "one-of-two-inputs", [
        sign(policies=["wpkh", "wpkh-account-1"], target_indices=[0]),
    ], [terminal("success"), sig, check("no-unrequested-device-signature")],
        evidence=("wire", "oracle", "device-path"))
    add("SCOPE-001", "one-leaf-of-two", [
        sign("tr-tree", leaf=0, extra_eligible_leaf=1),
    ], [terminal("success"), sig, check("no-unrequested-device-signature")],
        requires=[[*clause, _feature("exact-signature-scope")] for clause in _rules("WSI-TR-004")],
        evidence=("wire", "oracle", "device-path"))
    for mode, fixture, flags in (
        ("ecdsa", "wpkh", [1, 2, 3, 129, 130, 131]),
        ("schnorr", "tr-key", [0, 1, 2, 3, 129, 130, 131]),
        ("script-schnorr", "tr-tree", [0, 1, 2, 3, 129, 130, 131]),
    ):
        axis = "ecdsa_sighash" if mode == "ecdsa" else "schnorr_sighash"
        rules = None if mode == "ecdsa" else _rules("WSI-TR-003" if mode == "schnorr" else "WSI-TR-004")
        add("SIGHASH-001", f"{mode}-advertised", [sign(fixture, sighash=f"${axis}")],
            [terminal("success"), sig, check("weakened-sighash-review-if-applicable")],
            axes=(axis,), requires=rules, evidence=signing)
        add("SIGHASH-001", f"{mode}-unadvertised", [
            step("oracle", action="unsupported-wire-values", field=axis, values=flags,
                 fixture=f"bitcoin:policies.{fixture}"),
        ], [check("unsupported-sighash-without-fallback"), no_effect], requires=rules, evidence=codec)

    add("DPA-001", "checksum-branches", [
        policy("check_policy", format="descriptor-pair-v1", user="none"),
        address(format="descriptor-pair-v1"),
        address(format="descriptor-pair-v1", branch=1, index=1),
    ], [terminal("success"), check("policy-id"), check("descriptor-derivation")], evidence=signing)
    for mutation in ("descriptor-checksum", "descriptor-threshold", "descriptor-locktime",
                     "descriptor-internal-key", "descriptor-origin", "descriptor-wildcard",
                     "descriptor-tap-tree"):
        fixture = ("tr-tree" if mutation in ("descriptor-internal-key", "descriptor-tap-tree") else
                   "wsh-csv" if mutation == "descriptor-locktime" else "wsh-sortedmulti")
        add("DPA-002", mutation, [
            policy("register_policy", fixture, format="descriptor-pair-v1", mutation=mutation),
        ], [terminal("INVALID_POLICY"), no_effect], evidence=signer)
    add("DPA-003", "fixed-owned-and-external-key", [
        policy("register_policy", "wsh-sortedmulti", format="descriptor-pair-v1", fixed_keys=True),
    ], [terminal("success"), check("key-roles-and-linkability")], evidence=review)
    add("DPA-004", "no-implicit-change-branch", [
        policy("register_policy", format="descriptor-pair-v1", omit_change=True),
        address(branch=1, format="descriptor-pair-v1", omit_change=True),
        sign(format="descriptor-pair-v1", omit_change=True, claim_change=False),
    ], [check("unavailable-change-branch"), check("all-unclassified-outputs-visible")],
        evidence=review)

    for context, prefix, group in (("wsh", "wsh", "WSH"), ("tapscript", "tr", "TR")):
        add(f"{group}-001", "syntax-corpus", [
            step("oracle", action="miniscript-corpus", context=context, validity="safe",
                 fixture=f"miniscript:contexts.{context}.positive"),
        ], [check("context-fragment-and-wrapper-coverage"), check("compiled-script-and-witness")],
            evidence=("wire", "oracle", "device-path"))
        invalid_grammar = {
            "wrong-context": ["wrong-context"],
            "wrong-type": ["wrong-top-level-type", "wrong-operand-type", "short-hash", "threshold-overflow"],
            "public-satisfaction": ["no-signature"],
            "malleable-satisfaction": ["malleable-or"],
            "duplicate-derived-pubkey": ["duplicate-key"],
            "mixed-timelock-types": ["mixed-cltv-types", "mixed-csv-types"],
        }
        for mutation, entries in invalid_grammar.items():
            add(f"{group}-002", mutation, [
                step("oracle", action="miniscript-corpus", context=context, validity=mutation,
                     fixture=f"miniscript:contexts.{context}.negative", entries=entries),
            ], [check("unsafe-policy-not-registered", reason=mutation), no_effect],
                evidence=("wire", "oracle", "device-path"))
        for algo in HASHES:
            fixture = f"{prefix}-{algo}"
            case = "WSH-003" if context == "wsh" else "TR-006"
            for preimage in ("correct", "wrong-digest", "wrong-length", "absent"):
                add(case, f"{algo}-{preimage}", [
                    sign(fixture, preimage=preimage),
                    step("oracle", action="preimage-witness", fixture=f"bitcoin:policies.{fixture}",
                         preimage=preimage),
                ], [check("preimage-semantics", preimage=preimage)],
                    requires=_claim(context, "hashlocks"), evidence=signing)
        for name, lock in LOCKS.items():
            fixture = f"{prefix}-{'csv' if name == 'csv-blocks' else name}"
            case = "WSH-004" if context == "wsh" else "TR-006"
            for kind, value in (("below", lock["invalid"]), ("at", lock["valid"]),
                                ("above", lock["valid"] + 1)):
                add(case, f"{name}-{kind}", [
                    sign(fixture, **{lock["field"]: value}),
                    step("oracle", action="locktime-boundary", fixture=f"bitcoin:policies.{fixture}",
                         field=lock["field"], value=value),
                ], [check("timelock-semantics", boundary=kind)],
                    requires=_claim(context, name), evidence=signing)
            extra = ("version-one", "disable-flag", "wrong-units") if name.startswith("csv") else (
                "final-sequence", "wrong-units",
            )
            for kind in extra:
                add(case, f"{name}-{kind}", [
                    sign(fixture, mutation=kind),
                ], [check("invalid-timelock-rejected"), no_effect],
                    requires=_claim(context, name), evidence=signer)
        case = "WSH-005" if context == "wsh" else "TR-007"
        fixture = "wsh-multiple-owned" if context == "wsh" else "tr-tree"
        add(case, "separate-paths-same-seed", [
            policy("register_policy", fixture, multiple_owned_keys=True),
            sign(fixture, multiple_owned_keys=True),
        ], [terminal("success"), sig, check("owned-derivations-and-seed-roles")],
            requires=_claim(context, "multiple-owned-keys"), evidence=signing)

    add("WSH-006", "threshold-recovery-witness", [
        sign("wsh-threshold"),
        step("oracle", action="witness-threshold", context="wsh", include_negative=True),
    ], [terminal("success"), sig, check("valid-and-invalid-witnesses")], evidence=signing)
    add("TR-001", "three-leaf-tree", [
        policy("check_policy", "tr-tree", user="none"),
        address("tr-tree"),
        step("oracle", action="taproot-tree", fixture="bitcoin:policies.tr-tree"),
    ], [terminal("success"), check("taproot-commitment", leaves=3, depth=2)], evidence=signing)
    add("TR-003", "only-explicit-keypath", [
        sign("tr-key"), sign("tr-key", mutation="script-mode-without-leaf"),
    ], [terminal("POLICY_MISMATCH", "INVALID_PSBT"), sig, no_effect], evidence=signing)
    add("TR-004", "explicit-leaf", [sign("tr-tree", leaf=0)],
        [terminal("success"), sig, check("taproot-leaf")], evidence=signing)
    for mutation in ("leaf-hash", "sibling-hash", "control-block", "internal-key",
                     "leaf-version", "output-tweak"):
        add("TR-004", mutation, [sign("tr-tree", leaf=0, mutation=mutation)],
            [check("taproot-route-rejected"), no_effect], evidence=signer)
    add("TR-005", "checksigadd-witness", [
        sign("tr-tree", leaf=0),
        step("oracle", action="witness-threshold", context="tapscript", include_negative=True),
    ], [terminal("success"), sig, check("valid-and-invalid-witnesses")], evidence=signing)

    add("CAR-001", "complete-lifecycle", [
        call("capabilities", user="none"), call("get_key", network="$network", path=derivation),
        policy("check_policy", user="none"), policy("register_policy"), address(), sign(),
        step("carrier", action="verify-no-online-callback-if-offline"),
    ], [terminal("success"), sig, check("exact-carrier-semantics")], evidence=signing)
    for carrier, cases_for_carrier in (
        ("stream", ("truncated-stream", "split-complete-stream", "oversize-stream")),
        ("file", ("stale-file", "wrong-magic-file", "oversize-file")),
    ):
        for action in cases_for_carrier:
            add("CAR-002", action, [
                step("carrier", action=action, asset="wsi:records.capabilities"),
            ], [check("safe-reassembly-and-retry")], requires=[[f"carrier:{carrier}"]], evidence=state)
    for action in ("duplicate-qr-segment", "reordered-qr-segments", "missing-qr-segment"):
        add("CAR-002", action, [
            step("carrier", action=action, asset="wsi:records.capabilities"),
        ], [check("safe-reassembly-and-retry")], requires=[["binding:qr"]], evidence=state)
    add("CAR-003", "interrupted-review", [
        sign(user="cancel"),
        step("carrier", action="disconnect-before-response", phase="after-approval"),
        step("device", action="restart"),
        step("carrier", action="retry-identical-request"),
    ], [check("lost-response-is-unknown"), check("retry-approval-or-authentic-cached-response")],
        evidence=state)
    add("UI-001", "trusted-policy-and-transaction", [
        policy("register_policy", "wsh-sortedmulti", label="CTS EXTERNAL", host_title="Single key"),
        sign("wsh-sortedmulti", claim_change=False, host_title="All change"),
    ], [terminal("success"), check("trusted-policy-review"), check("all-unclassified-outputs-visible")],
        evidence=signing)
    for method, entry in (
        ("get-key", call("get_key", network="$network", path=derivation, user="reject")),
        ("register-policy", policy("register_policy", user="reject")),
        ("display-address", address(user="reject")),
        ("sign-psbt", sign(user="reject")),
    ):
        add("UI-002", method, [entry], [terminal("USER_REJECTED"), no_effect], evidence=review)

    missing = [case["id"] for case in cases.values() if not case["scenarios"]]
    if missing:
        raise ValueError(f"cases have no executable scenarios: {missing}")
    return list(cases.values())


def parameter_sets(scenario, domains):
    axes = scenario["axes"]
    for values in product(*(domains[axis] for axis in axes)):
        yield dict(zip(axes, values))
