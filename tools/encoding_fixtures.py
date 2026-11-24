"""Synthetic byte fixtures for the WSI envelope and carriers."""

from hashlib import sha256
from struct import pack

from wsi_reference import (
    MAGIC,
    MAX_CONTAINER,
    EncodingError,
    commitment,
    decode,
    encode,
    frame,
    request,
    response,
    unframe,
)


def build_vectors(bitcoin):
    cap = request("capabilities", {}, "encoding")
    accepted = encode(cap)
    unknown = request("capabilities", {}, "required-feature", ["cts-unsupported-feature"])
    rejected = response(unknown, error={"code": "UNSUPPORTED_FEATURE", "message": "fixture"})
    basic = {
        "type": "response",
        "v": 1,
        "id": cap["id"],
        "request_hash": commitment("WSI/request/v1", accepted),
        "error": {"code": "BUSY", "message": "fixture"},
    }

    def committed(record, domain):
        payload = encode(record)
        return {
            "cbor_hex": payload.hex(),
            "file_hex": frame(payload, "file").hex(),
            "stream_hex": frame(payload, "stream").hex(),
            "commitment_domain": domain,
            "commitment_hex": commitment(domain, payload).hex(),
        }

    def invalid(payload):
        return {
            "cbor_hex": payload.hex(),
            "file_hex": frame(payload, "file").hex(),
            "stream_hex": frame(payload, "stream").hex(),
        }

    vectors = {
        "records": {
            "capabilities": committed(cap, "WSI/request/v1"),
            "required-unknown-feature": committed(unknown, "WSI/request/v1"),
            "unsupported-feature-response": committed(rejected, "WSI/CTS/fixture"),
            "correlated-error-response": committed(basic, "WSI/CTS/fixture"),
            "wrong-id-response": committed(
                {**basic, "id": b"\x00" * 16}, "WSI/CTS/fixture"
            ),
            "wrong-hash-response": committed(
                {**basic, "request_hash": b"\x00" * 32}, "WSI/CTS/fixture"
            ),
            "wrong-version-response": committed({**basic, "v": 2}, "WSI/CTS/fixture"),
            "conflicting-id": committed(
                {**cap, "method": "get_key", "params": {"network": "regtest", "path": []}},
                "WSI/request/v1",
            ),
            "unknown-version": committed({**cap, "v": 2}, "WSI/request/v1"),
            "closed-record": committed({**cap, "extra": 0}, "WSI/request/v1"),
            "limit-4096": committed(
                {**cap, "extra": b"\x00" * (4096 - len(MAGIC) - len(encode({**cap, "extra": b""})) - 2)},
                "WSI/request/v1",
            ),
        },
        "invalid_cbor": {
            "duplicate-key": invalid(bytes.fromhex("a2617601617601")),
            "invalid-utf8": invalid(bytes.fromhex("a16176 61ff")),
            "nonshort-uint": invalid(bytes.fromhex("a161761801")),
            "nonshort-length": invalid(bytes.fromhex("b801617601")),
            "indefinite-map": invalid(bytes.fromhex("bf617601ff")),
            "tag": invalid(b"\xc0" + accepted),
            "float": invalid(bytes.fromhex("f90000")),
            "negative-uint": invalid(bytes.fromhex("20")),
            "unsorted-map": invalid(bytes.fromhex("a262696450") + cap["id"] + bytes.fromhex("617601")),
            "trailing-byte": invalid(accepted + b"\x00"),
            "depth-65": invalid(b"\x81" * 64 + b"\x00"),
            "uint32-overflow": invalid(bytes.fromhex("a161761b0000000100000000")),
            "map-overclaim": invalid(bytes.fromhex("ba ffffffff")),
        },
        "invalid_carriers": {
            "over-limit-stream": pack(">I", MAX_CONTAINER + 1).hex(),
            "short-stream": frame(accepted, "stream")[:-1].hex(),
            "wrong-magic-file": (b"X" + frame(accepted, "file")[1:]).hex(),
            "zero-stream": pack(">I", 0).hex(),
        },
        "known_answers": {
            "cbor-a-one": "a1616101",
            "cbor-keys-byte-order": "a36161006261610162616202",
            "capabilities-cbor": (
                "a66176016269645081e32c7ab1fd7e1a3e085d2235f46123"
                "64747970656772657175657374666d6574686f646c636170"
                "6162696c697469657366706172616d73a0717265717569726564"
                "5f666561747572657380"
            ),
        },
    }
    vectors["records"].update(operation_vectors(bitcoin, committed))
    return vectors


def operation_vectors(bitcoin, committed):
    policy = bitcoin["policies"]["wpkh"]["bip388"]
    policy_bytes = encode(policy)
    policy_id = commitment("WSI/policy/v1", policy_bytes)
    wallet = {"policy": policy, "label": "WSI CTS"}
    account = bitcoin["accounts"]["signer-84-0"]
    origin = {"network": "regtest", "path": account["path"]}
    instance = bitcoin["policies"]["wpkh"]["addresses"]["1/0"]
    address_ref = {"policy_id": policy_id, "branch": 1, "index": 0}

    def record(name, method, params, result=None):
        operation = request(method, params, name)
        records = {name: committed(operation, "WSI/request/v1")}
        if result is not None:
            records[f"{name}-response"] = committed(
                response(operation, result=result), "WSI/CTS/fixture"
            )
        return records

    result = {"wpkh-policy": committed(policy, "WSI/policy/v1")}
    result.update(record("get-key", "get_key", origin, {
        **origin, "fingerprint": bytes.fromhex(account["fingerprint"]), "xpub": account["xpub"],
    }))
    result.update(record("check-policy", "check_policy", {"policy": policy}, {
        "policy_id": policy_id, "validity": "valid", "support": "supported", "validation": "device",
        "owned_key_count": 1, "issues": [], "warnings": [],
    }))
    result.update(record("register-policy", "register_policy", wallet, {
        "policy_id": policy_id, "label": wallet["label"], "mode": "per-operation",
    }))
    result.update(record("display-address", "display_address", {
        "wallet": wallet, "branch": 1, "index": 0,
    }, {
        **address_ref, "address": instance["address"],
        "script_pubkey": bytes.fromhex(instance["script_pubkey"]), "confirmed": True,
    }))
    for version in (0, 2):
        psbt = bitcoin["psbts"][f"wpkh-v{version}"]
        result.update(record(f"sign-psbt-v{version}", "sign_psbt", {
            "psbt": bytes.fromhex(psbt["hex"]),
            "wallets": [wallet],
            "input_bindings": [{"input": 0, "address": {**address_ref, "branch": 0}}],
            "change_bindings": [{"output": 1, "address": address_ref}],
            "targets": [{**target, "pubkey": bytes.fromhex(target["pubkey"])} for target in psbt["targets"]],
            "fee_mode": "verified-prevouts",
        }))
    return result


def verify(vectors):
    known = vectors["known_answers"]
    if encode({"a": 1}).hex() != known["cbor-a-one"]:
        raise ValueError("CBOR RFC example differs")
    if encode({"ab": 2, "aa": 1, "a": 0}).hex() != known["cbor-keys-byte-order"]:
        raise ValueError("CBOR map key order differs")
    if vectors["records"]["capabilities"]["cbor_hex"] != known["capabilities-cbor"]:
        raise ValueError("canonical request differs from the known response")
    for name, fixture in vectors["records"].items():
        raw = bytes.fromhex(fixture["cbor_hex"])
        if encode(decode(raw)) != raw:
            raise ValueError(f"record {name} does not round-trip")
        for carrier in ("file", "stream"):
            if unframe(bytes.fromhex(fixture[f"{carrier}_hex"]), carrier) != raw:
                raise ValueError(f"record {name} has mismatched {carrier} bytes")
        domain = fixture["commitment_domain"].encode("ascii")
        if sha256(domain + bytes(1) + raw).hexdigest() != fixture["commitment_hex"]:
            raise ValueError(f"record {name} commitment differs")
    if len(bytes.fromhex(vectors["records"]["limit-4096"]["file_hex"])) != 4096:
        raise ValueError("incorrect 4096-byte fixture")
    for name, fixture in vectors["invalid_cbor"].items():
        try:
            decode(bytes.fromhex(fixture["cbor_hex"]))
        except EncodingError:
            continue
        raise ValueError(f"invalid CBOR accepted: {name}")
    for name, data in vectors["invalid_carriers"].items():
        try:
            unframe(bytes.fromhex(data), name.rsplit("-", 1)[1])
        except EncodingError:
            continue
        raise ValueError(f"invalid carrier accepted: {name}")
