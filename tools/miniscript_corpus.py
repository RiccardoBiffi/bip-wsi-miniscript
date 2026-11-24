"""Reproducible BIP-379 grammar fixtures and independent descriptor checks."""

import re
from subprocess import CalledProcessError

from bitcoin_fixtures import (
    HASHES,
    PREIMAGE,
    account_info,
    big32,
    condition_script,
    derived_key,
    descriptor_checksum,
    hash160,
    lift_x,
    multisig_script,
    point_add,
    point_mul,
    push,
    script_num,
    sha256,
    tagged_hash,
    varbytes,
    witness_address,
)


KEY_LAYOUT = {
    "A": ("signer-48-0", (0, 1)),
    "B": ("signer-48-0", (2, 3)),
    "C": ("cosigner-48-0", (0, 1)),
    "D": ("external-48-0", (0, 1)),
    "E": ("cosigner-48-0", (2, 3)),
    "I": ("external-48-0", (2, 3)),
}
FRAGMENTS = {
    "0", "1", "pk", "pkh", "pk_k", "pk_h", "after", "older", *HASHES,
    "and_v", "and_b", "and_n", "andor", "or_b", "or_c", "or_d", "or_i", "thresh",
}
WRAPPERS = set("ascdvjntul")
VERIFY = {0x87: 0x88, 0x9C: 0x9D, 0xAC: 0xAD, 0xAE: 0xAF}


def pk(key):
    return ("pk", key)


def require_key(key, condition):
    return ("and_v", ("v", pk(key)), condition)


def positive_layouts(context):
    """Compose typed grammar fragments with signature-requiring top-level B nodes."""
    a, b, c, d, e = map(pk, "ABCDE")
    multisig = "multi" if context == "wsh" else "multi_a"
    layouts = {
        "literals": ("or_i", ("0",), require_key("A", ("1",))),
        "pk": a,
        "pkh": ("pkh", "A"),
        "pk-k": ("c", ("pk_k", "A")),
        "pk-h": ("c", ("pk_h", "A")),
        "and-v": ("and_v", ("v", a), b),
        "and-b-alt": ("and_b", a, ("a", b)),
        "and-b-swap": ("and_b", a, ("s", b)),
        "and-n": ("and_n", a, b),
        "andor": ("andor", a, b, c),
        "or-b": ("or_b", a, ("s", b)),
        "or-c": ("t", ("or_c", a, ("v", b))),
        "or-d": ("or_d", a, b),
        "or-i": ("or_i", a, b),
        "dup-if": require_key("A", ("d", ("v", ("older", 144)))),
        "nonzero": ("j", a),
        "zero-not-equal": ("n", a),
        "left-selector": ("l", a),
        "right-selector": ("u", a),
        "cltv-height": require_key("A", ("after", 144)),
        "cltv-time": require_key("A", ("after", 500_001_000)),
        "csv-blocks": require_key("A", ("older", 144)),
        "csv-time": require_key("A", ("older", (1 << 22) | 2)),
        "nested": ("or_d", a, ("and_v", ("v", b), ("thresh", 2, c, ("s", d), ("s", e)))),
    }
    for name, hash_function in HASHES.items():
        layouts[name] = require_key("A", (name, hash_function(PREIMAGE)))
    for threshold in range(1, 4):
        layouts[f"{multisig}-{threshold}-of-3"] = (multisig, threshold, "A", "B", "C")
        layouts[f"thresh-{threshold}-of-3"] = ("thresh", threshold, a, ("s", b), ("s", c))
    return layouts


def negative_layouts(context):
    a, b = map(pk, "AB")
    wrong_multisig = "multi_a" if context == "wsh" else "multi"
    return {
        "wrong-context": ("invalid-context", (wrong_multisig, 1, "A", "B")),
        "wrong-top-level-type": ("invalid-type", ("v", a)),
        "wrong-operand-type": ("invalid-type", ("and_v", a, b)),
        "duplicate-key": ("duplicate-key", ("and_v", ("v", a), a)),
        "no-signature": ("unsigned-satisfaction", ("or_i", a, ("older", 144))),
        "malleable-or": (
            "malleable-satisfaction",
            require_key("A", ("or_i", ("older", 144), ("older", 145))),
        ),
        "mixed-cltv-types": (
            "mixed-timelocks",
            require_key("A", ("and_v", ("v", ("after", 144)), ("after", 500_001_000))),
        ),
        "mixed-csv-types": (
            "mixed-timelocks",
            require_key("A", ("and_v", ("v", ("older", 144)), ("older", (1 << 22) | 2))),
        ),
        "short-hash": ("invalid-hash-length", require_key("A", ("sha256", b"\0" * 31))),
        "threshold-overflow": ("invalid-threshold", ("thresh", 3, a, ("s", b))),
    }


def render(node, keys):
    if isinstance(node, str):
        return keys[node]
    if isinstance(node, bytes):
        return node.hex()
    if isinstance(node, int):
        return str(node)
    name, *children = node
    if name in {"0", "1"}:
        return name
    if name in WRAPPERS:
        wrapped = render(children[0], keys)
        nested_wrapper = children[0][0] in WRAPPERS
        return name + ("" if nested_wrapper else ":") + wrapped
    return f"{name}({','.join(render(child, keys) for child in children)})"


def syntax_tokens(node):
    name, *children = node
    return {name}.union(*(syntax_tokens(child) for child in children if isinstance(child, tuple)))


def ast_dimensions(node):
    children = [ast_dimensions(child) for child in node[1:] if isinstance(child, tuple)]
    return (1 + sum(count for count, _ in children),
            1 + max((depth for _, depth in children), default=0))


def ast_resources(tree, depth=0):
    if isinstance(tree, list):
        left, right = (ast_resources(child, depth + 1) for child in tree)
        return {key: (left[key] + right[key] if key == "leaves" else max(left[key], right[key]))
                for key in left}
    nodes, ast_depth = ast_dimensions(tree)
    return {"ast_nodes": nodes, "ast_depth": ast_depth, "leaves": 1, "tap_depth": depth}


def script(node, keys, *, tapscript):
    """Compile a valid AST using the BIP-379 Script translations in the catalog."""
    name, *args = node
    if name in {"0", "1"}:
        return script_num(int(name))
    if name in {"pk", "pk_k", "pkh", "pk_h"}:
        key = keys[args[0]]
        prefix = b"\x76\xa9" + push(hash160(key)) + b"\x88" if "h" in name else push(key)
        return prefix + (b"\xac" if name in {"pk", "pkh"} else b"")
    if name in HASHES or name in {"after", "older"}:
        return condition_script(name, args[0])
    if name in {"multi", "multi_a"}:
        return multisig_script([keys[label] for label in args[1:]], args[0], tapscript=tapscript)
    if name == "thresh":
        threshold, first, *remaining = args
        return (
            script(first, keys, tapscript=tapscript)
            + b"".join(script(child, keys, tapscript=tapscript) + b"\x93" for child in remaining)
            + script_num(threshold) + b"\x87"
        )
    first, *rest = [script(child, keys, tapscript=tapscript) for child in args]
    if name == "v":
        opcode = VERIFY.get(first[-1])
        return first + b"\x69" if opcode is None else first[:-1] + bytes([opcode])
    if name in WRAPPERS:
        before, after = {
            "a": (b"\x6b", b"\x6c"), "s": (b"\x7c", b""), "c": (b"", b"\xac"),
            "d": (b"\x76\x63", b"\x68"), "j": (b"\x82\x92\x63", b"\x68"),
            "n": (b"", b"\x92"), "t": (b"", b"\x51"),
            "l": (b"\x63\x00\x67", b"\x68"), "u": (b"\x63", b"\x67\x00\x68"),
        }[name]
        return before + first + after
    second = rest[0]
    if name == "andor":
        return first + b"\x64" + rest[1] + b"\x67" + second + b"\x68"
    before, between, after = {
        "and_v": (b"", b"", b""), "and_b": (b"", b"", b"\x9a"),
        "and_n": (b"", b"\x64\x00\x67", b"\x68"), "or_b": (b"", b"", b"\x9b"),
        "or_d": (b"", b"\x73\x64", b"\x68"), "or_c": (b"", b"\x64", b"\x68"),
        "or_i": (b"\x63", b"\x67", b"\x68"),
    }[name]
    return before + first + between + second + after


def tree_descriptor(tree, keys):
    if isinstance(tree, list):
        return "{" + ",".join(tree_descriptor(child, keys) for child in tree) + "}"
    return render(tree, keys)


def descriptor(context, tree, keys):
    expression = tree_descriptor(tree, keys)
    return f"wsh({expression})" if context == "wsh" else f"tr({keys['I']},{expression})"


def tap_tree(tree, keys):
    if isinstance(tree, list):
        left, right = [tap_tree(child, keys) for child in tree]
        digest = tagged_hash("TapBranch", b"".join(sorted((left[0], right[0]))))
        return digest, [
            {**leaf, "path": [*leaf["path"], sibling[0]]}
            for child, sibling in ((left, right), (right, left)) for leaf in child[1]
        ]
    raw = script(tree, keys, tapscript=True)
    digest = tagged_hash("TapLeaf", b"\xc0" + varbytes(raw))
    return digest, [{"script": raw, "hash": digest, "path": []}]


def expected(context, tree, branch, index):
    keys = {
        role: derived_key(account, branches[branch], index).pubkey
        for role, (account, branches) in KEY_LAYOUT.items()
    }
    if context == "wsh":
        raw = script(tree, keys, tapscript=False)
        program = sha256(raw)
        return {
            "address": witness_address(0, program),
            "script_pubkey": (b"\x00\x20" + program).hex(),
            "witness_script": raw.hex(),
        }
    keys = {role: key[1:] for role, key in keys.items()}
    root, leaves = tap_tree(tree, keys)
    internal = keys["I"]
    tweak = int.from_bytes(tagged_hash("TapTweak", internal + root), "big")
    x, y = point_add(lift_x(internal), point_mul(tweak))
    program = big32(x)
    return {
        "address": witness_address(1, program),
        "script_pubkey": (b"\x51\x20" + program).hex(),
        "internal_key": internal.hex(),
        "merkle_root": root.hex(),
        "output_key": program.hex(),
        "leaves": [
            {
                "version": 0xC0, "script": leaf["script"].hex(), "hash": leaf["hash"].hex(),
                "control_block": (bytes([0xC0 | (y & 1)]) + internal + b"".join(leaf["path"])).hex(),
            }
            for leaf in leaves
        ],
    }


def policy_records(context, tree):
    keys = {
        role: f"[{account_info(account)['origin']}]{account_info(account)['xpub']}"
        for role, (account, _) in KEY_LAYOUT.items()
    }
    # BIP-388 numbers key placeholders by their first occurrence, including the internal key.
    used = descriptor(context, tree, {role: f"$key{role}$" for role in keys})
    keys = {role: keys[role] for role in re.findall(r"\$key([A-Z])\$", used)}
    unique_keys = list(dict.fromkeys(keys.values()))
    placeholders = {}
    for role, key in keys.items():
        receive, change = KEY_LAYOUT[role][1]
        suffix = "/**" if (receive, change) == (0, 1) else f"/<{receive};{change}>/*"
        placeholders[role] = f"@{unique_keys.index(key)}{suffix}"
    bip388 = {
        "format": "bip388-v1", "network": "regtest", "keys": unique_keys,
        "template": descriptor(context, tree, placeholders),
    }
    pair = {"format": "descriptor-pair-v1", "network": "regtest"}
    for branch, name in enumerate(("receive", "change")):
        resolved = {role: f"{key}/{KEY_LAYOUT[role][1][branch]}/*" for role, key in keys.items()}
        pair[name] = descriptor_checksum(descriptor(context, tree, resolved))
    return {"bip388": bip388, "descriptor_pair": pair}


def build_vectors():
    contexts = {}
    for context in ("wsh", "tapscript"):
        layouts = positive_layouts(context)
        coverage = set().union(*(syntax_tokens(root) for root in layouts.values()))
        required = FRAGMENTS | WRAPPERS | {"multi" if context == "wsh" else "multi_a"}
        if required != coverage:
            raise ValueError(f"{context} grammar discrepancy: missing {required - coverage}, extra {coverage - required}")
        positives = {
            name: {**policy_records(context, root), "tokens": sorted(syntax_tokens(root)),
                   "resources": ast_resources(root),
                   "expected": {
                       branch_name: [expected(context, root, branch, index) for index in (0, 1)]
                       for branch, branch_name in enumerate(("receive", "change"))
                   }}
            for name, root in layouts.items()
        }
        if context == "tapscript":
            tree = [layouts["pk"], [require_key("B", ("older", 144)), ("multi_a", 2, "C", "D", "E")]]
            positives["three-leaf-depth-two"] = {
                **policy_records(context, tree), "tokens": ["and_v", "multi_a", "older", "pk", "v"],
                "resources": ast_resources(tree),
                "expected": {
                    name: [expected(context, tree, branch, index) for index in (0, 1)]
                    for branch, name in enumerate(("receive", "change"))
                },
            }
        contexts[context] = {
            "fragments": sorted(coverage - WRAPPERS), "wrappers": sorted(coverage & WRAPPERS),
            "positive": positives,
            "negative": {
                name: {
                    **policy_records(context, root), "failure_class": reason,
                    "validity": "valid" if reason in {"unsigned-satisfaction", "malleable-satisfaction"}
                    else "invalid",
                    "issue": "UNSAFE_POLICY" if reason in {"unsigned-satisfaction", "malleable-satisfaction"}
                    else "INVALID_POLICY",
                }
                for name, (reason, root) in negative_layouts(context).items()
            },
        }
    return {"network": "regtest", "indices": [0, 1], "contexts": contexts}


def verify(vectors):
    if vectors != build_vectors():
        raise ValueError("Miniscript grammar fixtures differ from their deterministic definitions")


def rpc_error_code(error):
    if isinstance(error, CalledProcessError):
        message = error.stderr or b""
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        match = re.search(r"^error code:\s*(-?\d+)\s*$", message, re.MULTILINE)
        return int(match.group(1)) if match else None
    return getattr(error, "code", None)


def verify_regtest(vectors, rpc):
    """Check scriptPubKeys and addresses using Bitcoin Core's descriptor compiler."""
    totals = {"positive": 0, "negative": 0, "derived": 0}
    for context, fixtures in vectors["contexts"].items():
        for name, fixture in fixtures["positive"].items():
            for branch in ("receive", "change"):
                label = f"{context}/{name}/{branch}"
                desc = fixture["descriptor_pair"][branch]
                info = rpc("getdescriptorinfo", desc)
                if not info["isrange"] or not info["issolvable"] or info["hasprivatekeys"]:
                    raise ValueError(f"{label}: malformed public ranged descriptor")
                actual = rpc("deriveaddresses", desc, vectors["indices"])
                targets = fixture["expected"][branch]
                if actual != [entry["address"] for entry in targets]:
                    raise ValueError(f"{label}: Bitcoin Core address mismatch: {actual}")
                for address, target in zip(actual, targets):
                    if rpc("validateaddress", address)["scriptPubKey"] != target["script_pubkey"]:
                        raise ValueError(f"{label}: Bitcoin Core scriptPubKey mismatch")
                    totals["derived"] += 1
            totals["positive"] += 1
        for name, fixture in fixtures["negative"].items():
            desc = fixture["descriptor_pair"]["receive"]
            try:
                rpc("getdescriptorinfo", desc)
                rpc("deriveaddresses", desc, vectors["indices"])
            except Exception as error:
                # An RPC parameter/descriptor rejection is evidence. Transport and node errors propagate.
                if rpc_error_code(error) not in {-5, -8}:
                    raise
                totals["negative"] += 1
                continue
            raise ValueError(f"{context}/{name}: Bitcoin Core accepted a negative descriptor")
    return totals
