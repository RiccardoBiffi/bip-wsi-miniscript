#!/usr/bin/env python3
"""Deterministic Bitcoin data for the WSI CTS. All keys are public test material."""

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
import hashlib
import hmac
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
from tempfile import TemporaryDirectory


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
HARDENED = 1 << 31
REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
REGTEST_GENESIS_TIME = 1296688602
CLTV_HEIGHT = 144
CLTV_TIME = REGTEST_GENESIS_TIME + 144 * 600
CSV_BLOCKS = 144
CSV_TIME = (1 << 22) | 2
PREIMAGE = bytes(range(32))
HASH_OPCODES = {"sha256": 0xA8, "hash256": 0xAA, "ripemd160": 0xA6, "hash160": 0xA9}
PREIMAGE_TYPES = {"ripemd160": 0x0A, "sha256": 0x0B, "hash160": 0x0C, "hash256": 0x0D}
MNEMONICS = {
    "signer": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "cosigner": "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "external": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
}
ACCOUNT_SPECS = {
    "signer-84-0": ("signer", (84, 1, 0)),
    "signer-84-1": ("signer", (84, 1, 1)),
    "signer-48-0": ("signer", (48, 1, 0, 2)),
    "signer-86-0": ("signer", (86, 1, 0)),
    "cosigner-84-0": ("cosigner", (84, 1, 0)),
    "cosigner-48-0": ("cosigner", (48, 1, 0, 2)),
    "cosigner-86-0": ("cosigner", (86, 1, 0)),
    "external-84-0": ("external", (84, 1, 0)),
    "external-48-0": ("external", (48, 1, 0, 2)),
    "external-86-0": ("external", (86, 1, 0)),
}
ADDRESS_INDICES = (0, 1)
FUNDING_VALUE_SAT = 1_000_000
DEFAULT_FEE_SAT = 1_000


def sha256(value):
    return hashlib.sha256(value).digest()


def hash256(value):
    return sha256(sha256(value))


def ripemd160(value):
    return hashlib.new("ripemd160", value).digest()


def hash160(value):
    return ripemd160(sha256(value))


HASHES = {"sha256": sha256, "hash256": hash256, "ripemd160": ripemd160, "hash160": hash160}


def tagged_hash(tag, value):
    prefix = sha256(tag.encode("ascii"))
    return sha256(prefix + prefix + value)


def compact_size(value):
    if value < 0:
        raise ValueError("negative CompactSize")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def varbytes(value):
    return compact_size(len(value)) + value


def u32(value):
    return struct.pack("<I", value)


def u64(value):
    return struct.pack("<Q", value)


def version_bytes(version):
    if not -(1 << 31) <= version < 1 << 32:
        raise ValueError("transaction version does not fit 32 bits")
    return u32(version & 0xFFFFFFFF)


def big32(value):
    return value.to_bytes(32, "big")


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 != x2:
        slope = (y2 - y1) * pow((x2 - x1) % P, -1, P) % P
    elif (y1 + y2) % P == 0:
        return None
    else:
        slope = 3 * x1 * x1 * pow(2 * y1 % P, -1, P) % P
    x = (slope * slope - x1 - x2) % P
    return x, (slope * (x1 - x) - y1) % P


@lru_cache(maxsize=512)
def point_mul(scalar):
    point = None
    addend = G
    while scalar:
        if scalar & 1:
            point = point_add(point, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return point


def lift_x(xonly):
    x = int.from_bytes(xonly, "big")
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    if x >= P or y * y % P != (x**3 + 7) % P:
        raise ValueError("invalid x-only key")
    return x, P - y if y & 1 else y


BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(body):
    data = body + hash256(body)[:4]
    encoded = ""
    value = int.from_bytes(data, "big")
    while value:
        value, digit = divmod(value, 58)
        encoded = BASE58[digit] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + encoded


@dataclass(frozen=True)
class ExtendedKey:
    secret: int
    chain_code: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\0" * 4
    child_number: int = 0

    @property
    def pubkey(self):
        x, y = point_mul(self.secret)
        return bytes([2 | (y & 1)]) + big32(x)

    @property
    def fingerprint(self):
        return hash160(self.pubkey)[:4]

    def derive(self, child):
        key_data = b"\0" + big32(self.secret) if child & HARDENED else self.pubkey
        digest = hmac.digest(self.chain_code, key_data + struct.pack(">I", child), "sha512")
        tweak = int.from_bytes(digest[:32], "big")
        secret = (self.secret + tweak) % N
        if tweak >= N or not secret:
            raise ValueError("invalid deterministic BIP32 child")
        return ExtendedKey(secret, digest[32:], self.depth + 1, self.fingerprint, child)

    def serialize(self, private=False):
        version = bytes.fromhex("04358394" if private else "043587cf")
        key_data = b"\0" + big32(self.secret) if private else self.pubkey
        return base58check(
            version + bytes([self.depth]) + self.parent_fingerprint
            + struct.pack(">I", self.child_number) + self.chain_code + key_data
        )


@lru_cache(maxsize=None)
def seed(owner):
    return hashlib.pbkdf2_hmac("sha512", MNEMONICS[owner].encode("ascii"), b"mnemonic", 2048)


@lru_cache(maxsize=None)
def master(owner):
    digest = hmac.digest(b"Bitcoin seed", seed(owner), "sha512")
    secret = int.from_bytes(digest[:32], "big")
    if not 0 < secret < N:
        raise ValueError("invalid deterministic BIP32 master key")
    return ExtendedKey(secret, digest[32:])


@lru_cache(maxsize=None)
def account_key(account):
    owner, path = ACCOUNT_SPECS[account]
    key = master(owner)
    for child in path:
        key = key.derive(child | HARDENED)
    return key


@lru_cache(maxsize=None)
def derived_key(account, branch, index):
    return account_key(account).derive(branch).derive(index)


def account_info(account):
    owner, path = ACCOUNT_SPECS[account]
    key = account_key(account)
    origin = master(owner).fingerprint.hex() + "".join(f"/{child}h" for child in path)
    return {
        "owner": owner,
        "fingerprint": master(owner).fingerprint.hex(),
        "path": [child | HARDENED for child in path],
        "origin": origin,
        "xpub": key.serialize(),
        "pubkey": key.pubkey.hex(),
    }


DESCRIPTOR_INPUT = (
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
)
CHECKSUM_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def polymod(values, generators, top_shift):
    residue = 1
    mask = (1 << top_shift) - 1
    for value in values:
        top = residue >> top_shift
        residue = ((residue & mask) << 5) ^ value
        for bit, generator in enumerate(generators):
            if top & (1 << bit):
                residue ^= generator
    return residue


def descriptor_checksum(descriptor):
    values = []
    group = []
    for char in descriptor:
        value = DESCRIPTOR_INPUT.index(char)
        values.append(value & 31)
        group.append(value >> 5)
        if len(group) == 3:
            values.append(group[0] * 9 + group[1] * 3 + group[2])
            group.clear()
    if group:
        values.append(group[0] if len(group) == 1 else group[0] * 3 + group[1])
    generators = (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)
    residue = polymod(values + [0] * 8, generators, 35) ^ 1
    checksum = "".join(CHECKSUM_CHARS[(residue >> shift) & 31] for shift in range(35, -1, -5))
    return f"{descriptor}#{checksum}"


def witness_address(version, program, hrp="bcrt"):
    value = int.from_bytes(program, "big")
    pad = (-8 * len(program)) % 5
    value <<= pad
    symbols = [version] + [value >> shift & 31 for shift in range(8 * len(program) + pad - 5, -1, -5)]
    hrp_values = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    residue = polymod(hrp_values + symbols + [0] * 6, generators, 25)
    residue ^= 1 if version == 0 else 0x2BC830A3
    symbols.extend(residue >> shift & 31 for shift in range(25, -1, -5))
    return hrp + "1" + "".join(CHECKSUM_CHARS[symbol] for symbol in symbols)


def push(data):
    if len(data) > 75:
        raise ValueError("fixture push exceeds single-byte Script push")
    return bytes([len(data)]) + data


def script_num(value):
    if value == 0:
        return b"\0"
    if 1 <= value <= 16:
        return bytes([0x50 + value])
    if value < 0:
        raise ValueError("negative number outside fixture script model")
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "little")
    if encoded[-1] & 0x80:
        encoded += b"\0"
    return push(encoded)


def pk_script(key, verify=False):
    return push(key) + (b"\xad" if verify else b"\xac")


def multisig_script(keys, threshold, *, verify=False, tapscript=False):
    if tapscript:
        return (
            pk_script(keys[0]) + b"".join(push(key) + b"\xba" for key in keys[1:])
            + script_num(threshold) + (b"\x9d" if verify else b"\x9c")
        )
    return (
        script_num(threshold) + b"".join(map(push, keys)) + script_num(len(keys))
        + (b"\xaf" if verify else b"\xae")
    )


def condition_script(kind, value):
    if kind in HASH_OPCODES:
        return b"\x82" + script_num(32) + b"\x88" + bytes([HASH_OPCODES[kind]]) + push(value) + b"\x87"
    if kind == "after":
        return script_num(value) + b"\xb1"
    if kind == "older":
        return script_num(value) + b"\xb2"
    raise ValueError(f"unsupported condition {kind}")


def condition_expression(kind, value):
    return f"{kind}({value.hex() if isinstance(value, bytes) else value})"


@dataclass(frozen=True)
class KeyRole:
    account: str
    branches: tuple = (0, 1)


@dataclass(frozen=True)
class Leaf:
    id: str
    roles: tuple
    condition: tuple | None = None
    threshold: int = 1

    def expression(self, keys, tapscript=False):
        used_keys = [keys[index] for index in self.roles]
        if len(used_keys) == 1:
            primary = f"pk({used_keys[0]})"
        else:
            operation = "multi_a" if tapscript else "multi"
            primary = f"{operation}({self.threshold},{','.join(used_keys)})"
        if self.condition is None:
            return primary
        return f"and_v(v:{primary},{condition_expression(*self.condition)})"

    def script(self, keys, tapscript=False):
        used_keys = [keys[index] for index in self.roles]
        verify = self.condition is not None
        if len(used_keys) == 1:
            primary = pk_script(used_keys[0], verify)
        else:
            primary = multisig_script(used_keys, self.threshold, verify=verify, tapscript=tapscript)
        return primary + condition_script(*self.condition) if verify else primary


def map_tree(tree, leaf_value):
    if isinstance(tree, Leaf):
        return leaf_value(tree)
    left, right = tree
    return "{" + map_tree(left, leaf_value) + "," + map_tree(right, leaf_value) + "}"


def tap_tree(tree, keys):
    if isinstance(tree, Leaf):
        script = tree.script(keys, tapscript=True)
        digest = tagged_hash("TapLeaf", b"\xc0" + varbytes(script))
        return digest, [(tree, script, digest, [])]
    left, left_leaves = tap_tree(tree[0], keys)
    right, right_leaves = tap_tree(tree[1], keys)
    for leaf in left_leaves:
        leaf[3].append(right)
    for leaf in right_leaves:
        leaf[3].append(left)
    return tagged_hash("TapBranch", b"".join(sorted((left, right)))), left_leaves + right_leaves


@dataclass(frozen=True)
class Policy:
    kind: str
    roles: tuple
    tree: Leaf | tuple | None = None

    def expression(self, keys):
        if self.kind == "wpkh":
            return f"wpkh({keys[0]})"
        if self.kind == "wsh-sortedmulti":
            return f"wsh(sortedmulti(2,{','.join(keys)}))"
        if self.kind == "wsh-threshold":
            return f"wsh(or_d(pk({keys[3]}),{self.tree.expression(keys)}))"
        if self.kind == "wsh":
            return f"wsh({self.tree.expression(keys)})"
        if self.tree is None:
            return f"tr({keys[0]})"
        return f"tr({keys[0]},{map_tree(self.tree, lambda leaf: leaf.expression(keys, tapscript=True))})"

    def descriptor(self, branch, private=False):
        keys = []
        for role in self.roles:
            info = account_info(role.account)
            xkey = account_key(role.account).serialize(private=private)
            keys.append(f"[{info['origin']}]{xkey}/{role.branches[branch]}/*")
        return descriptor_checksum(self.expression(keys))

    def bip388(self):
        keys = []
        placeholders = []
        for role in self.roles:
            info = account_info(role.account)
            expression = f"[{info['origin']}]{info['xpub']}"
            if expression not in keys:
                keys.append(expression)
            receive, change = role.branches
            suffix = "/**" if role.branches == (0, 1) else f"/<{receive};{change}>/*"
            placeholders.append(f"@{keys.index(expression)}{suffix}")
        return {"format": "bip388-v1", "network": "regtest", "template": self.expression(placeholders), "keys": keys}

    def instantiate(self, branch, index):
        roles = []
        for role in self.roles:
            info = account_info(role.account)
            child = role.branches[branch]
            key = derived_key(role.account, child, index)
            roles.append({
                "account": role.account,
                "owner": info["owner"],
                "fingerprint": info["fingerprint"],
                "path": [*info["path"], child, index],
                "pubkey": key.pubkey.hex(),
            })
        keys = [bytes.fromhex(role["pubkey"]) for role in roles]
        if self.kind == "wpkh":
            program = hash160(keys[0])
            return {"keys": roles, "script_pubkey": (b"\x00\x14" + program).hex(), "address": witness_address(0, program)}
        if self.kind.startswith("wsh"):
            if self.kind == "wsh-sortedmulti":
                script = multisig_script(sorted(keys), 2)
            elif self.kind == "wsh-threshold":
                script = pk_script(keys[3]) + b"\x73\x64" + self.tree.script(keys) + b"\x68"
            else:
                script = self.tree.script(keys)
            program = sha256(script)
            return {
                "keys": roles, "witness_script": script.hex(),
                "script_pubkey": (b"\x00\x20" + program).hex(), "address": witness_address(0, program),
            }
        xonly_keys = [key[1:] for key in keys]
        internal_key = xonly_keys[0]
        root, leaves = (b"", []) if self.tree is None else tap_tree(self.tree, xonly_keys)
        tweak = int.from_bytes(tagged_hash("TapTweak", internal_key + root), "big")
        if tweak >= N:
            raise ValueError("invalid deterministic Taproot tweak")
        x, y = point_add(lift_x(internal_key), point_mul(tweak))
        program = big32(x)
        leaf_info = {}
        for leaf, script, digest, siblings in leaves:
            control_block = bytes([0xC0 | (y & 1)]) + internal_key + b"".join(siblings)
            leaf_info[leaf.id] = {
                "script": script.hex(), "hash": digest.hex(), "version": 0xC0,
                "control_block": control_block.hex(), "roles": list(leaf.roles),
            }
        return {
            "keys": roles, "script_pubkey": (b"\x51\x20" + program).hex(),
            "address": witness_address(1, program), "tap_internal_key": internal_key.hex(),
            "tap_merkle_root": root.hex(), "tap_leaves": leaf_info, "tap_leaf_order": list(leaf_info),
        }


def policy_specs():
    wpkh = KeyRole("signer-84-0")
    wsh_a = KeyRole("signer-48-0")
    wsh_b = KeyRole("signer-48-0", (2, 3))
    wsh_c = KeyRole("cosigner-48-0")
    tap_a = KeyRole("signer-86-0", (2, 3))
    tap_b = KeyRole("signer-86-0", (4, 5))
    tap_c = KeyRole("cosigner-86-0")
    policies = {
        "wpkh": Policy("wpkh", (wpkh,)),
        "wpkh-account-1": Policy("wpkh", (KeyRole("signer-84-1"),)),
        "external-wpkh": Policy("wpkh", (KeyRole("external-84-0"),)),
        "wsh-sortedmulti": Policy("wsh-sortedmulti", (wsh_a, wsh_c, KeyRole("external-48-0"))),
        "wsh-multiple-owned": Policy("wsh-sortedmulti", (wsh_a, wsh_b, wsh_c)),
        "wsh-threshold": Policy(
            "wsh-threshold", (wsh_a, wsh_b, wsh_c, KeyRole("external-48-0")),
            Leaf("threshold-recovery", (0, 1, 2), ("older", CSV_BLOCKS), 2),
        ),
        "tr-key": Policy("tr", (KeyRole("signer-86-0"),)),
        "tr-tree": Policy(
            "tr", (KeyRole("signer-86-0"), tap_a, tap_b, tap_c,
                   KeyRole("signer-86-0", (6, 7)), KeyRole("signer-86-0", (8, 9))),
            (Leaf("threshold", (1, 2, 3), threshold=2), (
                Leaf("sha256", (4,), ("sha256", sha256(PREIMAGE))),
                Leaf("cltv-height", (5,), ("after", CLTV_HEIGHT)),
            )),
        ),
    }
    conditions = {
        "csv": ("older", CSV_BLOCKS), "csv-time": ("older", CSV_TIME),
        "cltv-height": ("after", CLTV_HEIGHT), "cltv-time": ("after", CLTV_TIME),
        **{name: (name, digest(PREIMAGE)) for name, digest in HASHES.items()},
    }
    for name, condition in conditions.items():
        policies[f"wsh-{name}"] = Policy("wsh", (wsh_a,), Leaf(name, (0,), condition))
        policies[f"tr-{name}"] = Policy(
            "tr", (KeyRole("external-86-0"), tap_a), Leaf(name, (1,), condition)
        )
    return policies


POLICIES = policy_specs()


def tx_out(output):
    return u64(output["value_sat"]) + varbytes(bytes.fromhex(output["script_pubkey"]))


def outpoint(tx_input):
    return bytes.fromhex(tx_input["txid"])[::-1] + u32(tx_input["vout"])


def transaction(version, inputs, outputs, locktime, witnesses=None):
    tx = version_bytes(version) + (b"\0\x01" if witnesses is not None else b"")
    tx += compact_size(len(inputs))
    for tx_input in inputs:
        script_sig = bytes.fromhex(tx_input.get("script_sig", ""))
        tx += outpoint(tx_input) + varbytes(script_sig) + u32(tx_input["sequence"])
    tx += compact_size(len(outputs)) + b"".join(map(tx_out, outputs))
    if witnesses is not None:
        for stack in witnesses:
            tx += compact_size(len(stack)) + b"".join(map(varbytes, stack))
    return tx + u32(locktime)


def txid(raw_tx):
    return hash256(raw_tx)[::-1].hex()


def coinbase(height, outputs):
    tx_input = {
        "txid": "00" * 32, "vout": 0xFFFFFFFF, "sequence": 0xFFFFFFFF,
        "script_sig": (script_num(height) + b"\0").hex(),
    }
    return transaction(2, [tx_input], outputs, 0)


def psbt_map(entries):
    pairs = sorted(entries.items()) if isinstance(entries, dict) else entries
    return b"".join(varbytes(bytes.fromhex(key)) + varbytes(bytes.fromhex(value)) for key, value in pairs) + b"\0"


def serialize_psbt(global_map, input_maps, output_maps):
    """Ordered key/value lists permit intentional duplicate keys in negative vectors."""
    return b"psbt\xff" + b"".join(map(psbt_map, (global_map, *input_maps, *output_maps)))


def psbt_derivation(role):
    return role["fingerprint"] + b"".join(map(u32, role["path"])).hex()


def add_derivations(entries, address, *, tx_input):
    if "tap_internal_key" not in address:
        prefix = "06" if tx_input else "02"
        for role in address["keys"]:
            entries[prefix + role["pubkey"]] = psbt_derivation(role)
        if "witness_script" in address:
            entries["05" if tx_input else "01"] = address["witness_script"]
        return

    entries["17" if tx_input else "05"] = address["tap_internal_key"]
    leaves = address["tap_leaves"]
    if tx_input:
        if address["tap_merkle_root"]:
            entries["18"] = address["tap_merkle_root"]
        for leaf in leaves.values():
            entries["15" + leaf["control_block"]] = leaf["script"] + f"{leaf['version']:02x}"
    elif leaves:
        tree = bytearray()
        for leaf_id in address["tap_leaf_order"]:
            leaf = leaves[leaf_id]
            depth = (len(bytes.fromhex(leaf["control_block"])) - 33) // 32
            tree += bytes([depth, leaf["version"]]) + varbytes(bytes.fromhex(leaf["script"]))
        entries["06"] = tree.hex()
    prefix = "16" if tx_input else "07"
    for role_index, role in enumerate(address["keys"]):
        hashes = sorted(leaf["hash"] for leaf in leaves.values() if role_index in leaf["roles"])
        entries[prefix + role["pubkey"][2:]] = compact_size(len(hashes)).hex() + "".join(hashes) + psbt_derivation(role)


def apply_overrides(entries, overrides):
    for key, value in overrides.items():
        if value is None:
            entries.pop(key, None)
        else:
            entries[key] = value


def psbt_addresses(vectors, references):
    resolved = []
    for reference in references:
        policy_id, branch, index = (reference, 0, 0) if isinstance(reference, str) else reference
        policy = vectors["policies"][policy_id]
        resolved.append((policy_id, branch, index, policy["addresses"][f"{branch}/{index}"]))
    return resolved


def policy_leaf(policy, leaf_id=None):
    if policy.kind != "tr":
        return policy.tree
    if leaf_id == "keypath" or policy.tree is None:
        return None
    def leaves(tree):
        if isinstance(tree, Leaf):
            yield tree
        else:
            yield from leaves(tree[0])
            yield from leaves(tree[1])
    return next(leaf for leaf in leaves(policy.tree) if leaf_id is None or leaf.id == leaf_id)


def lookup_index(mapping, index, default=None):
    if mapping is None:
        return default
    return mapping.get(index, mapping.get(str(index), default))


def make_psbt(
    vectors, policy_ids, *, psbt_version=0, tx_version=2, sequences=None, locktime=None,
    sighashes=None, include_non_witness_utxos=True, change_policy=None, external_input=False,
    outputs=None, leaf_selection=None, target_roles=None, preimages=None, required_locktimes=None,
    input_overrides=None, output_overrides=None, global_overrides=None,
):
    """Construct a serialized PSBT and its intent from an immutable fixture recipe.

    A policy reference is an ID or ``[id, branch, index]``. ``sequences`` and
    ``sighashes`` are per-input lists. Leaf IDs, role lists, preimage hex strings
    and map mutations are indexed by input. Mutations use hex key/value pairs
    and null to remove a key. Output overrides affect PSBT metadata only.
    """
    if psbt_version not in (0, 2):
        raise ValueError("PSBT version must be 0 or 2")
    policy_ids = list(policy_ids)
    if external_input:
        policy_ids.append("external-wpkh")
    refs = psbt_addresses(vectors, policy_ids)
    if not refs:
        raise ValueError("at least one fixture input is required")
    policies = [POLICIES[policy_id] for policy_id, _, _, _ in refs]
    leaves = [policy_leaf(policy, lookup_index(leaf_selection, i)) for i, policy in enumerate(policies)]
    if sequences is None:
        sequences = [leaf.condition[1] if leaf and leaf.condition and leaf.condition[0] == "older" else 0xFFFFFFFE
                     for leaf in leaves]
    implicit_locktime = locktime is None
    if implicit_locktime:
        locktime = max((leaf.condition[1] for leaf in leaves if leaf and leaf.condition and leaf.condition[0] == "after"), default=0)
    sighashes = sighashes if sighashes is not None else [None] * len(refs)
    if len(sequences) != len(refs) or len(sighashes) != len(refs):
        raise ValueError("sequence and sighash lists must cover every input")

    inputs = []
    input_maps = []
    targets = []
    input_total = 0
    for i, ((policy_id, branch, index, address), policy, leaf) in enumerate(zip(refs, policies, leaves)):
        funding = vectors["transactions"][policy_id]
        vout = funding["address_vouts"][f"{branch}/{index}"]
        prevout = funding["outputs"][vout]
        inputs.append({
            "policy": policy_id, "branch": branch, "index": index,
            "txid": funding["txid"], "vout": vout, "sequence": sequences[i],
            "prevout": prevout,
        })
        input_total += prevout["value_sat"]
        entries = {"01": tx_out(prevout).hex()}
        if include_non_witness_utxos:
            entries["00"] = funding["hex"]
        if sighashes[i] is not None:
            entries["03"] = u32(sighashes[i]).hex()
        if psbt_version == 2:
            entries.update({"0e": bytes.fromhex(funding["txid"])[::-1].hex(), "0f": u32(vout).hex(),
                            "10": u32(sequences[i]).hex()})
            requirements = lookup_index(required_locktimes, i)
            if requirements is None and implicit_locktime and leaf and leaf.condition and leaf.condition[0] == "after":
                value = leaf.condition[1]
                requirements = {"time" if value >= 500_000_000 else "height": value}
            for kind, value in (requirements or {}).items():
                entries[{"time": "11", "height": "12"}[kind]] = u32(value).hex()
        if leaf and leaf.condition and leaf.condition[0] in HASHES:
            kind, digest = leaf.condition
            supplied = lookup_index(preimages, i, PREIMAGE.hex())
            if supplied is not None:
                entries[f"{PREIMAGE_TYPES[kind]:02x}" + digest.hex()] = supplied
        add_derivations(entries, address, tx_input=True)
        apply_overrides(entries, lookup_index(input_overrides, i, {}))
        input_maps.append(entries)

        tap_mode = policy.kind == "tr"
        mode = "tap-script" if tap_mode and leaf else "tap-key" if tap_mode else "ecdsa"
        if tap_mode:
            candidates = leaf.roles if leaf else (0,)
        elif policy.kind == "wsh-threshold":
            candidates = leaf.roles
        else:
            candidates = tuple(range(len(address["keys"])))
        selected = lookup_index(target_roles, i, [role for role in candidates if address["keys"][role]["owner"] == "signer"])
        for role_index in selected:
            pubkey = address["keys"][role_index]["pubkey"]
            target = {"input": i, "mode": mode, "pubkey": pubkey[2:] if tap_mode else pubkey,
                      "sighash": sighashes[i] if sighashes[i] is not None else (0 if tap_mode else 1)}
            if tap_mode and leaf:
                target["leaf_hash"] = address["tap_leaves"][leaf.id]["hash"]
            targets.append(target)

    if len({(tx_input["txid"], tx_input["vout"]) for tx_input in inputs}) != len(inputs):
        raise ValueError("fixture recipe spends the same outpoint twice")
    if outputs is None:
        recipient = vectors["policies"]["external-wpkh"]["addresses"]["0/1"]
        outputs = [{"value_sat": input_total - DEFAULT_FEE_SAT, "script_pubkey": recipient["script_pubkey"]}]
        if change_policy is not None:
            outputs[0]["value_sat"] = input_total * 3 // 5
            change_ref = (change_policy, 1, 0) if isinstance(change_policy, str) else change_policy
            change_id, branch, index, address = psbt_addresses(vectors, [change_ref])[0]
            outputs.append({"value_sat": input_total - DEFAULT_FEE_SAT - outputs[0]["value_sat"],
                            "script_pubkey": address["script_pubkey"], "change": [change_id, branch, index]})

    fallback_locktime = locktime
    if psbt_version == 2:
        try:
            locktime = v2_locktime([{bytes.fromhex(key): bytes.fromhex(value) for key, value in entries.items()}
                                    for entries in input_maps], fallback_locktime)
        except ValueError:
            # Invalid lock combinations remain serializable for negative cases.
            locktime = fallback_locktime
    raw_tx = transaction(tx_version, inputs, outputs, locktime)
    if psbt_version == 0:
        globals_ = {"00": raw_tx.hex()}
    else:
        globals_ = {"fb": "02000000", "02": version_bytes(tx_version).hex(), "03": u32(fallback_locktime).hex(),
                    "04": compact_size(len(inputs)).hex(), "05": compact_size(len(outputs)).hex()}
    apply_overrides(globals_, global_overrides or {})
    output_maps = []
    for i, output in enumerate(outputs):
        entries = {"03": u64(output["value_sat"]).hex(), "04": output["script_pubkey"]} if psbt_version == 2 else {}
        if "change" in output:
            address = psbt_addresses(vectors, [output["change"]])[0][3]
            add_derivations(entries, address, tx_input=False)
        apply_overrides(entries, lookup_index(output_overrides, i, {}))
        output_maps.append(entries)

    raw_psbt = serialize_psbt(globals_, input_maps, output_maps)
    return {
        "psbt_version": psbt_version, "hex": raw_psbt.hex(), "base64": base64.b64encode(raw_psbt).decode("ascii"),
        "psbt_sha256": sha256(raw_psbt).hex(), "unsigned_tx_hex": raw_tx.hex(), "unsigned_txid": txid(raw_tx),
        "tx_version": tx_version, "locktime": locktime, "inputs": inputs, "outputs": outputs,
        "fee_sat": input_total - sum(output["value_sat"] for output in outputs), "targets": targets,
        "maps": {"global": globals_, "inputs": input_maps, "outputs": output_maps},
    }


def build_vectors():
    """Return the catalog of public, deterministic regtest fixture data."""
    vectors = {
        "format": "wsi-bitcoin-fixtures-v1", "network": "regtest",
        "test_keys": {owner: {"mnemonic": phrase, "passphrase": "", "seed_hex": seed(owner).hex(),
                              "master_fingerprint": master(owner).fingerprint.hex()}
                      for owner, phrase in MNEMONICS.items()},
        "accounts": {account: account_info(account) for account in ACCOUNT_SPECS},
        "policies": {}, "transactions": {}, "psbts": {},
        "timelocks": {"cltv_height": CLTV_HEIGHT, "cltv_time": CLTV_TIME,
                      "csv_blocks": CSV_BLOCKS, "csv_time_sequence": CSV_TIME},
        "preimage": PREIMAGE.hex(),
        "regtest": {"genesis": REGTEST_GENESIS, "genesis_time": REGTEST_GENESIS_TIME,
                    "block_interval_seconds": 600, "tip_height": len(POLICIES) + CSV_BLOCKS + 2},
    }
    for height, (policy_id, policy) in enumerate(POLICIES.items(), 1):
        addresses = {f"{branch}/{index}": policy.instantiate(branch, index)
                     for branch in (0, 1) for index in ADDRESS_INDICES}
        vectors["policies"][policy_id] = {
            "bip388": policy.bip388(),
            "descriptor_pair": {"format": "descriptor-pair-v1", "network": "regtest",
                                "receive": policy.descriptor(0), "change": policy.descriptor(1)},
            "addresses": addresses,
        }
        outputs = [{"value_sat": FUNDING_VALUE_SAT + i * 1000, "script_pubkey": address["script_pubkey"]}
                   for i, address in enumerate(addresses.values())]
        raw_tx = coinbase(height, outputs)
        vectors["transactions"][policy_id] = {
            "height": height, "hex": raw_tx.hex(), "txid": txid(raw_tx), "outputs": outputs,
            "address_vouts": {key: i for i, key in enumerate(addresses)},
        }
    for version in (0, 2):
        for policy_id in POLICIES:
            if policy_id != "external-wpkh":
                vectors["psbts"][f"{policy_id}-v{version}"] = make_psbt(
                    vectors, [policy_id], psbt_version=version, change_policy=policy_id,
                )
        vectors["psbts"][f"wpkh-multi-account-v{version}"] = make_psbt(
            vectors, ["wpkh", "wpkh-account-1"], psbt_version=version,
            change_policy="wpkh-account-1",
        )
        vectors["psbts"][f"wpkh-external-input-v{version}"] = make_psbt(
            vectors, ["wpkh"], psbt_version=version, external_input=True, change_policy="wpkh",
        )
    return vectors


class ByteReader:
    def __init__(self, data):
        self.data = data
        self.position = 0

    def read(self, size):
        limit = self.position + size
        if limit > len(self.data):
            raise ValueError("truncated fixture serialization")
        value = self.data[self.position:limit]
        self.position = limit
        return value

    def size(self):
        prefix = self.read(1)[0]
        if prefix < 0xFD:
            return prefix
        limits = {0xFD: (2, 0xFD), 0xFE: (4, 0x10000), 0xFF: (8, 0x100000000)}
        width, minimum = limits[prefix]
        value = int.from_bytes(self.read(width), "little")
        if value < minimum:
            raise ValueError("nonminimal CompactSize in fixture serialization")
        return value

    def varbytes(self):
        return self.read(self.size())

    def end(self):
        if self.position != len(self.data):
            raise ValueError("unexpected bytes after fixture serialization")

    def psbt_map(self):
        entries = {}
        while key := self.varbytes():
            if key in entries:
                raise ValueError(f"duplicate PSBT key {key.hex()}")
            entries[key] = self.varbytes()
        return entries


def unpack(entries, key, width, *, signed=False, default=None):
    if key not in entries and default is not None:
        return default
    if key not in entries or len(entries[key]) != width:
        raise ValueError(f"invalid PSBT field {key.hex()} length")
    return int.from_bytes(entries[key], "little", signed=signed)


def v2_locktime(input_maps, fallback):
    times, heights = [], []
    for entries in input_maps:
        if b"\x11" not in entries and b"\x12" not in entries:
            continue
        time = unpack(entries, b"\x11", 4, default=0)
        height = unpack(entries, b"\x12", 4, default=0)
        if b"\x11" in entries and time < 500_000_000:
            raise ValueError("invalid PSBTv2 time-based locktime")
        if b"\x12" in entries and not 0 < height < 500_000_000:
            raise ValueError("invalid PSBTv2 height-based locktime")
        times.append(time)
        heights.append(height)
    if not times:
        return fallback
    if all(heights):
        return max(heights)
    if all(times):
        return max(times)
    raise ValueError("incompatible PSBTv2 locktime domains")


def project_psbt_v2(raw_psbt):
    """Reconstruct a BIP370 unsigned transaction and a PSBTv0 oracle projection."""
    reader = ByteReader(raw_psbt)
    if reader.read(5) != b"psbt\xff":
        raise ValueError("invalid PSBT magic")
    global_map = reader.psbt_map()
    if global_map.get(b"\xfb") != b"\x02\0\0\0" or b"\0" in global_map:
        raise ValueError("invalid PSBTv2 global fields")

    def read_count(key):
        count_reader = ByteReader(global_map[key])
        count = count_reader.size()
        count_reader.end()
        return count

    input_maps = [reader.psbt_map() for _ in range(read_count(b"\x04"))]
    output_maps = [reader.psbt_map() for _ in range(read_count(b"\x05"))]
    reader.end()
    locktime = v2_locktime(input_maps, unpack(global_map, b"\x03", 4, default=0))
    inputs = []
    for entries in input_maps:
        previous = entries[b"\x0e"]
        if len(previous) != 32:
            raise ValueError("invalid PSBTv2 previous TXID length")
        inputs.append({"txid": previous[::-1].hex(), "vout": unpack(entries, b"\x0f", 4),
                       "sequence": unpack(entries, b"\x10", 4, default=0xFFFFFFFF)})
    outputs = []
    for entries in output_maps:
        amount = unpack(entries, b"\x03", 8, signed=True)
        if amount < 0:
            raise ValueError("negative PSBTv2 output value")
        outputs.append({"value_sat": amount, "script_pubkey": entries[b"\x04"].hex()})
    tx = transaction(unpack(global_map, b"\x02", 4, signed=True), inputs, outputs, locktime)

    def common(entries, excluded):
        return {key.hex(): value.hex() for key, value in entries.items() if key not in excluded}

    globals_v0 = common(global_map, {bytes([key]) for key in (2, 3, 4, 5, 6, 0xFB)})
    globals_v0["00"] = tx.hex()
    v0 = serialize_psbt(
        globals_v0,
        [common(entries, {bytes([key]) for key in range(0x0E, 0x13)}) for entries in input_maps],
        [common(entries, {b"\x03", b"\x04"}) for entries in output_maps],
    )
    return tx, v0


class CoreRpcError(RuntimeError):
    def __init__(self, message):
        super().__init__(message)
        match = re.search(r"^error code:\s*(-?\d+)\s*$", message, re.MULTILINE)
        self.code = int(match.group(1)) if match else None


class CoreRpc:
    def __init__(self, executable, arguments):
        self.command = [executable, *arguments, "-regtest"]
        self.blockchain_info = self.call("getblockchaininfo")
        if self.blockchain_info["chain"] != "regtest" or self.call("getblockhash", 0) != REGTEST_GENESIS:
            raise ValueError("Bitcoin oracle requires the standard regtest chain")

    def call(self, method, *args):
        arguments = [arg if isinstance(arg, str) else json.dumps(arg, separators=(",", ":")) for arg in args]
        proc = subprocess.run([*self.command, method, *arguments], capture_output=True, text=True, timeout=30)
        if proc.returncode:
            raise CoreRpcError(f"{method}:\n{proc.stderr.strip()}")
        try:
            return json.loads(proc.stdout, parse_float=Decimal)
        except json.JSONDecodeError:
            return proc.stdout.strip()

    __call__ = call


@contextmanager
def regtest_node(*, bitcoind="bitcoind", bitcoin_cli="bitcoin-cli"):
    """Start an isolated non-P2P Bitcoin Core node with a fresh temporary datadir."""
    with TemporaryDirectory(prefix="wsi-cts-regtest-") as directory:
        with socket.socket() as rpc_port:
            rpc_port.bind(("127.0.0.1", 0))
            port = rpc_port.getsockname()[1]
        arguments = [f"-datadir={directory}", "-conf=/dev/null", f"-rpcport={port}"]
        command = [bitcoind, *arguments, "-regtest", "-nosettings", "-listen=0", "-connect=0",
                   "-discover=0", "-dnsseed=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                   "-printtoconsole=0", "-daemonwait"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            log_path = Path(directory, "regtest", "debug.log")
            details = "\n".join(log_path.read_text().splitlines()[-12:]) if log_path.exists() else result.stderr.strip()
            raise CoreRpcError(f"could not start temporary regtest node\n{details}")
        core = None
        try:
            core = CoreRpc(bitcoin_cli, arguments)
            yield core
        finally:
            if core is None:
                subprocess.run([bitcoin_cli, *arguments, "-regtest", "stop"], capture_output=True, timeout=10, check=False)
            else:
                core.call("stop")
            # Core closes the debug log and releases its datadir after the RPC returns.
            pid_path = Path(directory, "regtest", "bitcoind.pid")
            try:
                pid = int(pid_path.read_text())
            except FileNotFoundError:
                pass
            else:
                wait_for_stop(pid_path, pid)


def wait_for_stop(pid_path, pid):
    from os import kill
    from time import monotonic, sleep

    deadline = monotonic() + 10
    while pid_path.exists() and monotonic() < deadline:
        try:
            kill(pid, 0)
        except ProcessLookupError:
            return
        sleep(0.05)
    if pid_path.exists():
        raise CoreRpcError("temporary regtest node did not stop")


def expect(actual, expected, label):
    if actual != expected:
        raise ValueError(f"{label}: expected {expected!r}, got {actual!r}")


def check_core_transaction(decoded, vector, label):
    expect(decoded["txid"], vector["unsigned_txid"], f"{label} transaction ID")
    expect(decoded["version"], vector["tx_version"], f"{label} transaction version")
    expect(decoded["locktime"], vector["locktime"], f"{label} transaction locktime")
    expect([(item["txid"], item["vout"], item["sequence"]) for item in decoded["vin"]],
           [(item["txid"], item["vout"], item["sequence"]) for item in vector["inputs"]], f"{label} inputs")
    expect([(int(item["value"] * 100_000_000), item["scriptPubKey"]["hex"]) for item in decoded["vout"]],
           [(item["value_sat"], item["script_pubkey"]) for item in vector["outputs"]], f"{label} outputs")


def fixture_block(previous_hash, height, raw_coinbase, interval):
    prefix = (u32(0x20000000) + bytes.fromhex(previous_hash)[::-1] + hash256(raw_coinbase)
              + u32(REGTEST_GENESIS_TIME + height * interval) + u32(0x207FFFFF))
    target = 0x7FFFFF << (8 * (0x20 - 3))
    for nonce in range(0x100000000):
        header = prefix + u32(nonce)
        digest = hash256(header)
        if int.from_bytes(digest, "little") <= target:
            return digest[::-1].hex(), header + b"\x01" + raw_coinbase
    raise ValueError("failed to find deterministic regtest block nonce")


def prepare_regtest(vectors, core, *, tip_height=None):
    """Load fixture blocks into a disposable empty or matching regtest chain."""
    fixture = vectors["regtest"]
    height_limit = fixture["tip_height"] if tip_height is None else tip_height
    if not 0 < height_limit <= fixture["tip_height"]:
        raise ValueError("regtest fixture height is out of range")
    tip = core.call("getblockcount")
    if tip > height_limit:
        raise ValueError("regtest node has blocks beyond the requested fixture stage")
    funding = {tx["height"]: bytes.fromhex(tx["hex"]) for tx in vectors["transactions"].values()}
    chain = []
    previous_hash = fixture["genesis"]
    for height in range(1, height_limit + 1):
        raw_tx = funding.get(height)
        if raw_tx is None:
            raw_tx = coinbase(height, [{"value_sat": 0, "script_pubkey": "6a"}])
        previous_hash, raw_block = fixture_block(previous_hash, height, raw_tx, fixture["block_interval_seconds"])
        chain.append((previous_hash, raw_block))
    if tip:
        expect(core.call("getblockhash", tip), chain[tip - 1][0], "existing regtest chain differs from fixture")
    for height, (block_hash, raw_block) in enumerate(chain[tip:], tip + 1):
        result = core.call("submitblock", raw_block.hex())
        # bitcoin-cli represents JSON null as an empty response.
        if result not in (None, "", "duplicate"):
            raise ValueError(f"regtest fixture block {height} rejected: {result}")
        expect(core.call("getblockhash", height), block_hash, f"regtest fixture block {height}")
    return {"height": len(chain), "block_hash": chain[-1][0]}


def ecdsa_sighash(vector, index, script, sighash):
    if sighash != 1:
        raise ValueError("the fixture reference signer supports ECDSA SIGHASH_ALL")
    inputs = vector["inputs"]
    current = inputs[index]
    payload = (
        struct.pack("<i", vector["tx_version"]) + hash256(b"".join(map(outpoint, inputs)))
        + hash256(b"".join(u32(item["sequence"]) for item in inputs)) + outpoint(current)
        + varbytes(script) + u64(current["prevout"]["value_sat"]) + u32(current["sequence"])
        + hash256(b"".join(map(tx_out, vector["outputs"]))) + u32(vector["locktime"]) + u32(sighash)
    )
    return hash256(payload)


def tap_sighash(vector, index, leaf_hash, sighash):
    if sighash not in (0, 1):
        raise ValueError("the fixture reference signer supports Schnorr DEFAULT and ALL")
    inputs = vector["inputs"]
    payload = (
        bytes([0, sighash]) + struct.pack("<i", vector["tx_version"]) + u32(vector["locktime"])
        + sha256(b"".join(map(outpoint, inputs)))
        + sha256(b"".join(u64(item["prevout"]["value_sat"]) for item in inputs))
        + sha256(b"".join(varbytes(bytes.fromhex(item["prevout"]["script_pubkey"])) for item in inputs))
        + sha256(b"".join(u32(item["sequence"]) for item in inputs))
        + sha256(b"".join(map(tx_out, vector["outputs"])))
        + bytes([2 if leaf_hash is not None else 0]) + u32(index)
    )
    if leaf_hash is not None:
        payload += leaf_hash + b"\0" + u32(0xFFFFFFFF)
    return tagged_hash("TapSighash", payload)


def der_int(value):
    data = big32(value).lstrip(b"\0") or b"\0"
    if data[0] & 0x80:
        data = b"\0" + data
    return b"\x02" + bytes([len(data)]) + data


def ecdsa_sign(secret, digest, sighash):
    # RFC6979 with SHA256. These private keys belong solely to the fixture chain.
    data = big32(secret) + big32(int.from_bytes(digest, "big") % N)
    key, value = b"\0" * 32, b"\x01" * 32
    for update in (b"\0", b"\x01"):
        key = hmac.digest(key, value + update + data, "sha256")
        value = hmac.digest(key, value, "sha256")
    while True:
        value = hmac.digest(key, value, "sha256")
        nonce = int.from_bytes(value, "big")
        if 0 < nonce < N:
            r = point_mul(nonce)[0] % N
            s = ((r * secret + int.from_bytes(digest, "big")) * pow(nonce, -1, N)) % N
            if r and s:
                body = der_int(r) + der_int(min(s, N - s))
                return b"\x30" + bytes([len(body)]) + body + bytes([sighash])
        key = hmac.digest(key, value + b"\0", "sha256")
        value = hmac.digest(key, value, "sha256")


def even_secret(secret):
    return N - secret if point_mul(secret)[1] & 1 else secret


def schnorr_sign(secret, digest, sighash):
    secret = even_secret(secret)
    pubkey = big32(point_mul(secret)[0])
    aux = tagged_hash("BIP0340/aux", b"\0" * 32)
    masked = bytes(left ^ right for left, right in zip(big32(secret), aux))
    nonce = int.from_bytes(tagged_hash("BIP0340/nonce", masked + pubkey + digest), "big") % N
    if not nonce:
        raise ValueError("deterministic Schnorr nonce is zero")
    nonce = even_secret(nonce)
    nonce_x = big32(point_mul(nonce)[0])
    challenge = int.from_bytes(tagged_hash("BIP0340/challenge", nonce_x + pubkey + digest), "big") % N
    signature = nonce_x + big32((nonce + challenge * secret) % N)
    return signature + (bytes([sighash]) if sighash else b"")


def fixture_witnesses(vectors, vector, *, leaf_selection=None, preimages=None):
    """Satisfy the fixture policies using public seeds, for the Core script oracle."""
    witnesses = []
    for i, tx_input in enumerate(vector["inputs"]):
        policy_id = tx_input["policy"]
        policy = POLICIES[policy_id]
        address = vectors["policies"][policy_id]["addresses"][f"{tx_input['branch']}/{tx_input['index']}"]
        roles = address["keys"]
        secrets = [derived_key(role["account"], *role["path"][-2:]).secret for role in roles]
        keys = [bytes.fromhex(role["pubkey"]) for role in roles]
        leaf = policy_leaf(policy, lookup_index(leaf_selection, i))
        witness = []
        if leaf and leaf.condition and leaf.condition[0] in HASHES:
            witness.append(bytes.fromhex(lookup_index(preimages, i, PREIMAGE.hex())))
        default = 0 if policy.kind == "tr" else 1
        entry = vector["maps"]["inputs"][i].get("03")
        sighash = int.from_bytes(bytes.fromhex(entry), "little") if entry is not None else default

        if policy.kind == "tr":
            if leaf is None:
                tweak_payload = bytes.fromhex(address["tap_internal_key"] + address["tap_merkle_root"])
                tweak = int.from_bytes(tagged_hash("TapTweak", tweak_payload), "big")
                tweaked_secret = (even_secret(secrets[0]) + tweak) % N
                witness.append(schnorr_sign(tweaked_secret, tap_sighash(vector, i, None, sighash), sighash))
            else:
                tap = address["tap_leaves"][leaf.id]
                digest = tap_sighash(vector, i, bytes.fromhex(tap["hash"]), sighash)
                for j in reversed(range(len(leaf.roles))):
                    witness.append(schnorr_sign(secrets[leaf.roles[j]], digest, sighash) if j < leaf.threshold else b"")
                witness += [bytes.fromhex(tap["script"]), bytes.fromhex(tap["control_block"])]
        elif policy.kind == "wpkh":
            script = b"\x76\xa9\x14" + hash160(keys[0]) + b"\x88\xac"
            digest = ecdsa_sighash(vector, i, script, sighash)
            witness += [ecdsa_sign(secrets[0], digest, sighash), keys[0]]
        else:
            script = bytes.fromhex(address["witness_script"])
            digest = ecdsa_sighash(vector, i, script, sighash)
            if policy.kind in ("wsh-sortedmulti", "wsh-threshold"):
                order = sorted((0, 1), key=keys.__getitem__) if policy.kind == "wsh-sortedmulti" else (0, 1)
                witness.append(b"")  # CHECKMULTISIG dummy argument
                witness.extend(ecdsa_sign(secrets[j], digest, sighash) for j in order)
                if policy.kind == "wsh-threshold":
                    witness.append(b"")  # Dissatisfy the first branch of or_d.
            else:
                witness.append(ecdsa_sign(secrets[0], digest, sighash))
            witness.append(script)
        witnesses.append(witness)
    return witnesses


def signed_spend(vectors, vector, *, leaf_selection=None, preimages=None, witness_edit=None):
    witnesses = fixture_witnesses(vectors, vector, leaf_selection=leaf_selection, preimages=preimages)
    if witness_edit is not None:
        witness_edit(witnesses[0])
    return transaction(vector["tx_version"], vector["inputs"], vector["outputs"], vector["locktime"], witnesses)


def verify_maturity(vectors, core):
    """Evaluate byte-identical signed transactions before and after maturity."""
    before_height = max(tx["height"] for tx in vectors["transactions"].values()) + 100
    before_chain = prepare_regtest(vectors, core, tip_height=before_height)
    candidates = {}
    for context in ("wsh", "tr"):
        for lock in ("csv", "cltv-height", "cltv-time"):
            fixture_id = f"{context}-{lock}-v0"
            vector = vectors["psbts"][fixture_id]
            tx_input = vector["inputs"][0]
            utxo = core.call("gettxout", tx_input["txid"], tx_input["vout"], False)
            if not utxo or utxo["confirmations"] < 100:
                raise ValueError(f"{fixture_id}: funding coinbase must already be mature")
            raw_tx = signed_spend(vectors, vector)
            before = core.call("testmempoolaccept", [raw_tx.hex()])[0]
            rejection = "non-BIP68-final" if lock == "csv" else "non-final"
            expect(before["allowed"], False, f"{fixture_id} before maturity")
            expect(before["reject-reason"], rejection, f"{fixture_id} before maturity reason")
            candidates[fixture_id] = (raw_tx, before)
    mature_chain = prepare_regtest(vectors, core)
    checks = []
    for fixture_id, (raw_tx, before) in candidates.items():
        after = core.call("testmempoolaccept", [raw_tx.hex()])[0]
        expect(after["allowed"], True, f"{fixture_id} after maturity")
        expect(after["txid"], before["txid"], f"{fixture_id} maturity txid")
        expect(after["wtxid"], before["wtxid"], f"{fixture_id} maturity wtxid")
        checks.append({"psbt": fixture_id, "txid": after["txid"], "wtxid": after["wtxid"],
                       "before_status": before["reject-reason"], "after_status": "accepted"})
    return mature_chain, {"before": before_chain, "after": mature_chain, "checks": checks}


def verify_witnesses(vectors, core):
    """Independently execute valid and invalid synthetic spends without broadcasting."""
    accepted, rejected = [], []

    def check(label, vector, expected, *, leaf_selection=None, preimages=None, witness_edit=None):
        raw_tx = signed_spend(vectors, vector, leaf_selection=leaf_selection, preimages=preimages, witness_edit=witness_edit)
        result = core.call("testmempoolaccept", [raw_tx.hex()])[0]
        expect(result["txid"], vector["unsigned_txid"], f"{label} verified spend txid")
        if result.get("allowed") != expected:
            raise ValueError(f"{label}: expected allowed={expected}, got {result}")
        if expected:
            accepted.append(label)
        else:
            reason = result["reject-reason"]
            if "script-verify-flag-failed" not in reason:
                raise ValueError(f"{label}: expected script failure, got {reason}")
            rejected.append({"case": label, "reason": reason})

    for label, vector in vectors["psbts"].items():
        if vector["psbt_version"] == 0:
            check(label, vector, True)
    for leaf_id in ("sha256", "cltv-height", "keypath"):
        selection = {0: leaf_id}
        vector = make_psbt(vectors, ["tr-tree"], leaf_selection=selection)
        check(f"tr-tree:{leaf_id}", vector, True, leaf_selection=selection)
    for policy_id in ("tr-key", "tr-tree"):
        check(f"{policy_id}:schnorr-all", make_psbt(vectors, [policy_id], sighashes=[1]), True)

    def flip_byte(stack, element, offset):
        value = bytearray(stack[element])
        value[offset] ^= 1
        stack[element] = bytes(value)

    deep_selection = {0: "sha256"}
    deep_leaf = make_psbt(vectors, ["tr-tree"], leaf_selection=deep_selection)
    for label, element, offset in (
        ("wrong-leaf-script", -2, 1), ("wrong-control-parity", -1, 0),
        ("wrong-internal-key", -1, 1), ("wrong-sibling", -1, -1),
    ):
        check(f"tr-tree:{label}", deep_leaf, False, leaf_selection=deep_selection,
              witness_edit=lambda stack: flip_byte(stack, element, offset))
    check("tr-tree:threshold-missing-signature", make_psbt(vectors, ["tr-tree"]), False,
          witness_edit=lambda stack: stack.__setitem__(1, b""))
    check("wsh-threshold:wrong-signature", make_psbt(vectors, ["wsh-threshold"]), False,
          witness_edit=lambda stack: flip_byte(stack, 1, -2))
    for context in ("wsh", "tr"):
        for hash_name in HASHES:
            vector = make_psbt(vectors, [f"{context}-{hash_name}"])
            check(f"{context}-{hash_name}:wrong-preimage", vector, False, preimages={0: "ff" * 32})
            check(f"{context}-{hash_name}:short-preimage", vector, False, preimages={0: "ff" * 31})
        check(f"{context}-csv:below-minimum", make_psbt(vectors, [f"{context}-csv"], sequences=[CSV_BLOCKS - 1]), False)
        check(f"{context}-csv:version-1", make_psbt(vectors, [f"{context}-csv"], tx_version=1), False)
        check(f"{context}-csv:disabled", make_psbt(vectors, [f"{context}-csv"], sequences=[HARDENED | CSV_BLOCKS]), False)
        check(f"{context}-csv-time:wrong-unit", make_psbt(vectors, [f"{context}-csv-time"], sequences=[2]), False)
        check(f"{context}-cltv-height:below-minimum", make_psbt(vectors, [f"{context}-cltv-height"], locktime=CLTV_HEIGHT - 1), False)
        check(f"{context}-cltv-time:final-sequence", make_psbt(vectors, [f"{context}-cltv-time"], sequences=[0xFFFFFFFF]), False)
    return {"accepted": accepted, "rejected": rejected}


def verify(vectors):
    """Check committed vectors against deterministic regeneration and BIP370 reconstruction."""
    expect(vectors, build_vectors(), "reproducible Bitcoin fixture catalog")
    for label, vector in vectors["psbts"].items():
        raw_psbt = base64.b64decode(vector["base64"], validate=True)
        expect(raw_psbt.hex(), vector["hex"], f"{label} hex encoding")
        expect(sha256(raw_psbt).hex(), vector["psbt_sha256"], f"{label} PSBT digest")
        if vector["psbt_version"] == 2:
            tx, projected = project_psbt_v2(raw_psbt)
            expect(tx.hex(), vector["unsigned_tx_hex"], f"{label} reconstructed transaction")
            v0 = vectors["psbts"][label.removesuffix("-v2") + "-v0"]
            expect(projected.hex(), v0["hex"], f"{label} PSBTv0 projection")
    return {"policies": len(vectors["policies"]), "psbts": len(vectors["psbts"])}


def verify_regtest(vectors, *, bitcoin_cli="bitcoin-cli", cli_args=(), fund=False, core=None):
    """Verify descriptor, previous transaction, PSBT and optional witness anchors."""
    core = core if core is not None else CoreRpc(bitcoin_cli, cli_args)
    counts = {"descriptors": 0, "addresses": 0, "funding_transactions": 0, "psbt_v0": 0, "psbt_v2": 0}
    for policy_id, policy in vectors["policies"].items():
        for branch, label in enumerate(("receive", "change")):
            descriptor = policy["descriptor_pair"][label]
            expected_checksum = descriptor.rsplit("#", 1)[1]
            info = core.call("getdescriptorinfo", descriptor)
            expect(info["checksum"], expected_checksum, f"{policy_id} {label} checksum")
            addresses = core.call("deriveaddresses", descriptor, [min(ADDRESS_INDICES), max(ADDRESS_INDICES)])
            expect(addresses, [policy["addresses"][f"{branch}/{index}"]["address"] for index in ADDRESS_INDICES],
                   f"{policy_id} {label} addresses")
            counts["descriptors"] += 1
            counts["addresses"] += len(addresses)
        previous = vectors["transactions"][policy_id]
        decoded = core.call("decoderawtransaction", previous["hex"])
        expect(decoded["txid"], previous["txid"], f"{policy_id} funding txid")
        expect([(int(item["value"] * 100_000_000), item["scriptPubKey"]["hex"]) for item in decoded["vout"]],
               [(item["value_sat"], item["script_pubkey"]) for item in previous["outputs"]], f"{policy_id} funding outputs")
        counts["funding_transactions"] += 1

    core_v2 = None
    for label, vector in vectors["psbts"].items():
        encoded = base64.b64decode(vector["base64"], validate=True)
        expect(encoded.hex(), vector["hex"], f"{label} base64 and hex")
        expect(sha256(encoded).hex(), vector["psbt_sha256"], f"{label} byte digest")
        version = vector["psbt_version"]
        if version == 2:
            tx, v0 = project_psbt_v2(encoded)
            expect(tx.hex(), vector["unsigned_tx_hex"], f"{label} BIP370 transaction")
            if core_v2 is not False:
                try:
                    decoded = core.call("decodepsbt", vector["base64"])
                except CoreRpcError as error:
                    message = str(error).lower()
                    if "version" not in message or not any(s in message for s in ("unsupported", "not supported")):
                        raise
                    core_v2 = False
                else:
                    core_v2 = True
            if core_v2 is False:
                decoded = core.call("decodepsbt", base64.b64encode(v0).decode("ascii"))
        else:
            decoded = core.call("decodepsbt", vector["base64"])
        check_core_transaction(decoded["tx"], vector, label)
        for i, tx_input in enumerate(vector["inputs"]):
            prevout = decoded["inputs"][i]["witness_utxo"]
            expect(int(prevout["amount"] * 100_000_000), tx_input["prevout"]["value_sat"], f"{label} input {i} value")
            expect(prevout["scriptPubKey"]["hex"], tx_input["prevout"]["script_pubkey"], f"{label} input {i} script")
        counts[f"psbt_v{version}"] += 1
    report = {
        "network": "regtest", "bitcoin_core_version": core.call("getnetworkinfo")["version"],
        "checks": counts, "psbt_v2_oracle": "native" if core_v2 else "BIP370 projection verified by Core as PSBTv0",
    }
    if fund:
        report["chain"], report["maturity"] = verify_maturity(vectors, core)
        report["witnesses"] = verify_witnesses(vectors, core)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "verify", "verify-regtest"))
    parser.add_argument("--vectors", type=Path, help="check a committed fixture JSON instead of regenerating it")
    parser.add_argument("--bitcoind", default="bitcoind")
    parser.add_argument("--bitcoin-cli", default="bitcoin-cli")
    args = parser.parse_args()
    vectors = json.loads(args.vectors.read_text(encoding="utf-8")) if args.vectors else build_vectors()
    if args.action == "build":
        report = vectors
    elif args.action == "verify":
        report = verify(vectors)
    else:
        with regtest_node(bitcoind=args.bitcoind, bitcoin_cli=args.bitcoin_cli) as core:
            report = verify_regtest(vectors, core=core, fund=True)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
