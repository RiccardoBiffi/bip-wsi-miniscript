#!/usr/bin/env python3
"""Generate and verify the WSI CTS without a hardware signer."""

import argparse
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator

import bitcoin_fixtures
import encoding_fixtures
import miniscript_corpus
from scenarios import FULL, TAP, WSH, build_cases, parameter_sets
from wsi_reference import encode


ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "archive/v0.2.0"
SOURCE = ARCHIVE / "wsi-conformance-cases-v0.2.0.json"
CTS = ROOT / "cts"
MANIFEST = CTS / "manifest.json"
CORE = "wsi-core-v1"
DRAFT_VERSION = "0.2.1"

AXES = {
    "psbt_version": "psbt_versions",
    "transaction_version": "transaction_versions",
    "registration_mode": "registration_modes",
    "ecdsa_sighash": "ecdsa_sighashes",
    "schnorr_sighash": "schnorr_sighashes",
}
STATIC_ARTIFACTS = {
    "manifest_schema": "cts/manifest.schema.json",
    "report_schema": "cts/report.schema.json",
    "mutations": "cts/mutations.json",
    "draft": "BIP.md",
    "harness": "docs/harness.md",
    "conformance": "docs/conformance.md",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    def unique_members(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    return json.loads(path.read_bytes(), object_pairs_hook=unique_members)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def digest(data):
    return sha256(data).hexdigest()


def source_data():
    return read_json(SOURCE)


def expected_profiles(cases):
    common = {
        case["id"] for case in cases
        if case["applies"] in ("CORE", "each-advertised-sighash", "each-advertised-carrier")
    }
    wsh = {case["id"] for case in cases if case["id"].startswith("WSI-WSH-")}
    tap = {case["id"] for case in cases if case["id"].startswith("WSI-TR-")}
    dpa = {case["id"] for case in cases if case["id"].startswith("WSI-DPA-")}
    return {
        CORE: sorted(common), WSH: sorted(common | wsh),
        TAP: sorted(common | tap), FULL: sorted(common | wsh | tap | dpa),
    }


def validate_schema(value, path):
    schema = read_json(path)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    error = next(validator.iter_errors(value), None)
    if error:
        location = ".".join(map(str, error.absolute_path))
        raise ValueError(f"{path.name} ({location or 'root'}): {error.message}")


def fixture_catalogs():
    bitcoin = bitcoin_fixtures.build_vectors()
    return {
        "wsi": encoding_fixtures.build_vectors(bitcoin),
        "bitcoin": bitcoin,
        "miniscript": miniscript_corpus.build_vectors(),
    }


def profile_resources(catalogs):
    bitcoin = catalogs["bitcoin"]
    contexts = catalogs["miniscript"]["contexts"]
    resources = {}
    for profile in (CORE, WSH, TAP, FULL):
        policies = ["wpkh", "wpkh-account-1", "wsh-sortedmulti"]
        grammar = []
        if profile in (WSH, FULL):
            policies.extend(name for name in bitcoin["policies"] if name.startswith("wsh-")
                            and name not in policies)
            grammar.extend(contexts["wsh"]["positive"].values())
        if profile in (TAP, FULL):
            policies.extend(name for name in bitcoin["policies"] if name.startswith("tr-"))
            grammar.extend(contexts["tapscript"]["positive"].values())
        records = [bitcoin["policies"][name] for name in policies] + grammar
        resource = {
            "container_bytes": 4096,
            "policy_bytes": max(len(encode(record["bip388"])) for record in records),
            "template_bytes": max(len(record["bip388"]["template"].encode()) for record in records),
            "label_bytes": len("CTS commitment" if profile == CORE else "CTS timed vault"),
            "policies_per_sign": 2,
            "keys": max(len(re.findall(r"@\d+", record["bip388"]["template"])) for record in records),
            "owned_keys": max(
                sum(key["owner"] == "signer" for key in bitcoin["policies"][name]["addresses"]["0/0"]["keys"])
                for name in policies
            ),
            "ast_nodes": max((record["resources"]["ast_nodes"] for record in grammar), default=0),
            "ast_depth": max((record["resources"]["ast_depth"] for record in grammar), default=0),
        }
        if profile == FULL:
            resource["policy_bytes"] = max(resource["policy_bytes"],
                                           max(len(encode(record["descriptor_pair"])) for record in records))
            resource["descriptor_bytes"] = max(
                len(record["descriptor_pair"][branch].encode())
                for branch in ("receive", "change") for record in records
            )
        if profile in (TAP, FULL):
            resource["tap_leaves"] = 3
            resource["tap_depth"] = 2
        anchors = policies + ["wpkh-multi-account", "wpkh-external-input"]
        for version in (0, 2):
            psbts = [bitcoin["psbts"][f"{name}-v{version}"] for name in anchors]
            resource[f"psbt_bytes_v{version}"] = max(len(psbt["hex"]) // 2 for psbt in psbts)
            for field in ("inputs", "outputs", "targets"):
                resource[field] = max(resource.get(field, 0), max(len(psbt[field]) for psbt in psbts))
        resources[profile] = resource
    return resources


def generated_files(catalogs):
    rendered = {}
    artifacts = {}
    for name, catalog in catalogs.items():
        path = f"cts/fixtures/{name}.json"
        data = json_bytes(catalog)
        rendered[ROOT / path] = data
        artifacts[name] = {"path": path, "sha256": digest(data)}
    for name, path in STATIC_ARTIFACTS.items():
        artifacts[name] = {"path": path, "sha256": digest((ROOT / path).read_bytes())}
    cases = build_cases(source_data()["cases"])
    for case in cases:
        del case["fixture_status"]
    manifest = {
        "schema_version": 1,
        "draft_version": DRAFT_VERSION,
        "protocol_version": 1,
        "artifacts": artifacts,
        "profiles": expected_profiles(cases),
        "profile_resources": profile_resources(catalogs),
        "axes": AXES,
        "cases": cases,
    }
    rendered[MANIFEST] = json_bytes(manifest)
    return rendered, manifest


def references(value, key):
    if isinstance(value, dict):
        for field, item in value.items():
            if field == key:
                yield item
            yield from references(item, key)
    elif isinstance(value, list):
        for item in value:
            yield from references(item, key)


def resolve(catalogs, reference):
    catalog, path = reference.split(":", 1)
    value = catalogs[catalog]
    for key in path.split("."):
        value = value[key]
    return value


def verify_archive():
    originals = {
        "bip-draft-wallet-signer-interface-v0.2.0.md":
            "9d508357008ec8c240371a0923440e5ecdc31b70780af329279f074178d90c62",
        "wsi-conformance-cases-v0.2.0.json":
            "13d063c8109f8b5a7f020b1caec897f51bf263e1ff6678136fd3f75dd01243c3",
    }
    for name, expected in originals.items():
        require(digest((ARCHIVE / name).read_bytes()) == expected, f"source hash differs: {name}")
    ids = [case["id"] for case in source_data()["cases"]]
    table = re.findall(r"^\| `(WSI-[A-Z]+-\d{3})` \|", (ROOT / "BIP.md").read_text(), re.M)
    require(len(ids) == len(set(ids)) == 64 and table == ids, "draft and archival case IDs differ")


def verify_catalog(manifest, catalogs):
    validate_schema(manifest, CTS / "manifest.schema.json")
    mutations = read_json(CTS / "mutations.json")["mutations"]
    for name, recipe in mutations.items():
        require(recipe["operations"], f"mutation recipe {name} has no operations")
        sources = recipe["source"]
        for source in sources if isinstance(sources, list) else [sources]:
            if source != "exchange.fixture":
                resolve(catalogs, source)
    ids = set()
    for case in manifest["cases"]:
        for scenario in case["scenarios"]:
            identity = case["id"], scenario["id"]
            require(identity not in ids, f"duplicate scenario {identity}")
            ids.add(identity)
            require(set(scenario["axes"]) <= AXES.keys(), f"unknown axis in {identity}")
            for key in ("asset", "fixture"):
                for reference in references(scenario["steps"], key):
                    try:
                        resolve(catalogs, reference)
                    except (KeyError, ValueError, TypeError) as error:
                        raise ValueError(f"unresolved fixture {reference} in {identity}") from error
            for name in references(scenario["steps"], "mutation"):
                require(name in mutations, f"missing mutation recipe {name} in {identity}")
            for step in scenario["steps"]:
                if step.get("action") == "miniscript-corpus" and "entries" in step:
                    require(set(step["entries"]) <= resolve(catalogs, step["fixture"]).keys(),
                            f"unknown Miniscript corpus entries in {identity}")
    encoding_fixtures.verify(catalogs["wsi"])
    bitcoin_fixtures.verify(catalogs["bitcoin"])
    miniscript_corpus.verify(catalogs["miniscript"])
    require({case["id"] for case in manifest["cases"]} ==
            {case["id"] for case in source_data()["cases"]}, "missing original case")
    return len(ids)


def scope_tags(claims, endpoint):
    features = set(claims["features"])
    formats = set(claims["policy_formats"])
    tags = {f"profile:{profile}" for profile in claims["profiles"]}
    tags.update(f"feature:{feature}" for feature in features)
    tags.add(f"carrier:{endpoint['carrier']}")
    tags.add(f"binding:{endpoint['binding']['medium']}")
    tags.add(f"mode:{endpoint['mode']}")
    tags.update(f"registration_mode:{mode}" for mode in claims["registration_modes"])
    tags.update(f"psbt_version:{version}" for version in claims["psbt_versions"])
    if "descriptor-pair-v1" in formats:
        tags.add("feature:descriptor-pair")
    if FULL in claims["profiles"]:
        tags.update({f"profile:{WSH}", f"profile:{TAP}"})
    for context, profile in (("wsh", WSH), ("tapscript", TAP)):
        coverage = claims["miniscript"][context]["coverage"]
        if coverage != "none":
            tags.update({f"context:{context}", f"feature:miniscript-{context}"})
        if coverage == "full-v1":
            tags.add(f"profile:{profile}")
    return tags


def key_for(case_id, scenario_id, parameters):
    return case_id, scenario_id, tuple(sorted(parameters.items()))


def required_scenarios(manifest, claims, endpoint):
    tags = scope_tags(claims, endpoint)
    domains = {axis: claims[field] for axis, field in AXES.items()}
    for case in manifest["cases"]:
        for scenario in case["scenarios"]:
            if any(set(clause) <= tags for clause in scenario["requires"]):
                for parameters in parameter_sets(scenario, domains):
                    yield key_for(case["id"], scenario["id"], parameters), set(scenario["evidence"])


def check_scope(claims, endpoint, manifest):
    require(claims["carriers"] == [endpoint["carrier"]], "carrier scope differs from the endpoint")
    profiles = set(claims["profiles"])
    require(profiles <= manifest["profiles"].keys(), "unknown profile in report")
    require(profiles or claims["features"], "report must name a profile or feature")
    source = source_data()
    features = set(source["feature_case_ids"]) | set(source["contextual_feature_case_ids"])
    require(set(claims["features"]) <= features, "unknown feature in report")
    require("bip388-v1" in claims["policy_formats"], "Core requires BIP-388")
    require(claims["psbt_versions"], "Core requires a PSBT version")
    require(2 in claims["transaction_versions"], "Core requires transaction version 2")
    require(1 in claims["ecdsa_sighashes"], "Core requires ECDSA ALL")
    require(claims["registration_modes"], "Core requires a registration mode")
    require(set(claims["ecdsa_sighashes"]) <= {1, 2, 3, 129, 130, 131}, "invalid ECDSA sighash")
    require(set(claims["schnorr_sighashes"]) <= {0, 1, 2, 3, 129, 130, 131}, "invalid Schnorr sighash")
    for name in ("policy_review", "address_display", "change_verification", "signature_scope"):
        require(claims["enforcement"][name] == "device", f"Core requires device {name}")
    limits = claims["limits"]
    require(4096 <= limits["container_bytes"] <= 16_777_216, "container limit outside WSI bounds")
    tags = scope_tags(claims, endpoint)
    for profile in {CORE, *(name for name in manifest["profiles"] if f"profile:{name}" in tags)}:
        for field, lower in manifest["profile_resources"][profile].items():
            if field.startswith("psbt_bytes_v"):
                if int(field[-1]) not in claims["psbt_versions"]:
                    continue
                field = "psbt_bytes"
            require(limits[field] >= lower, f"{profile} fixture minimum for {field} is {lower}")
    if WSH in profiles or FULL in profiles:
        require(claims["miniscript"]["wsh"]["coverage"] == "full-v1", "WSH profile requires full coverage")
    if TAP in profiles or FULL in profiles:
        require(claims["miniscript"]["tapscript"]["coverage"] == "full-v1", "Tapscript profile requires full coverage")
    if claims["miniscript"]["tapscript"]["coverage"] == "full-v1":
        require({0, 1} <= set(claims["schnorr_sighashes"]), "Tapscript requires Schnorr DEFAULT and ALL")
        require(limits["tap_leaves"] >= 3 and limits["tap_depth"] >= 2, "Tapscript tree below fixture minimum")
    if {"taproot-keypath", "taproot-scriptpath"}.intersection(claims["features"]):
        require(claims["schnorr_sighashes"], "Taproot signing claims require a Schnorr sighash")
    contextual = set(source["contextual_feature_case_ids"])
    if contextual.intersection(claims["features"]):
        require(any(value["coverage"] != "none" for value in claims["miniscript"].values()),
                "contextual feature requires a declared Miniscript context")
    if profiles.intersection({WSH, TAP, FULL}):
        require(limits["owned_keys"] >= 2, "Miniscript fixture minimum is two owned keys")
        require(claims["enforcement"]["policy_validation"] == "device",
                "complete Miniscript requires definitive device validation")
    if FULL in profiles or {"descriptor-pair", "raw-external-keys"}.intersection(claims["features"]):
        require("descriptor-pair-v1" in claims["policy_formats"], "claim requires descriptor-pair-v1")


def evidence_files(entries, root):
    evidence = {}
    for entry in entries:
        name = entry["id"]
        require(name not in evidence, f"duplicate evidence ID {name}")
        path = (root / entry["path"]).resolve()
        require(path.is_relative_to(root), f"evidence escapes report directory: {entry['path']}")
        require(path.is_file(), f"evidence file is missing: {entry['path']}")
        require(digest(path.read_bytes()) == entry["sha256"], f"evidence digest differs: {entry['path']}")
        evidence[name] = entry["kind"]
    return evidence


def verify_report(path, manifest):
    report = read_json(path)
    validate_schema(report, CTS / "report.schema.json")
    require(report["suite"]["version"] == manifest["draft_version"], "suite version mismatch")
    require(report["suite"]["manifest_sha256"] == digest(MANIFEST.read_bytes()),
            "report manifest digest differs from this checkout")
    assessment = report["assessment"]
    require(datetime.fromisoformat(assessment["started_at"].replace("Z", "+00:00")) <=
            datetime.fromisoformat(assessment["completed_at"].replace("Z", "+00:00")),
            "assessment ends before it starts")
    claims, endpoint = report["claims"], report["endpoint"]
    check_scope(claims, endpoint, manifest)
    all_scenarios = {(case["id"], item["id"]): item for case in manifest["cases"]
                     for item in case["scenarios"]}
    required = dict(required_scenarios(manifest, claims, endpoint))
    evidence = evidence_files(report["evidence"], path.resolve().parent)
    seen = set()
    blocking = []
    for row in report["results"]:
        key = key_for(row["case_id"], row["scenario_id"], row["parameters"])
        require(key not in seen, f"duplicate result {key}")
        seen.add(key)
        require(key[:2] in all_scenarios, f"unknown result {key}")
        scenario = all_scenarios[key[:2]]
        require(set(row["parameters"]) == set(scenario["axes"]), f"wrong parameter axes {key}")
        require(set(row["evidence_ids"]) <= evidence.keys(), f"unknown evidence reference for {key}")
        if key not in required:
            require(row["outcome"] == "inapplicable", f"result outside claimed scope: {key}")
        elif row["outcome"] != "pass":
            blocking.append((key, row["outcome"]))
        else:
            observed = {evidence[name] for name in row["evidence_ids"]}
            require(required[key] <= observed, f"missing evidence kinds for {key}: {sorted(required[key] - observed)}")
    missing = required.keys() - seen
    require(not missing, f"{len(missing)} mandatory results are missing, first: {sorted(missing)[0] if missing else ''}")
    require(not blocking, f"{len(blocking)} mandatory results are blocking, first: {blocking[0] if blocking else ''}")
    lane = assessment["lane"]
    decision = "hardware report complete" if lane == "hardware" else "simulator preflight complete"
    print(f"{decision}, {len(required)} mandatory results with evidence")


def run_regtest(catalogs):
    with bitcoin_fixtures.regtest_node() as core:
        bitcoin = bitcoin_fixtures.verify_regtest(catalogs["bitcoin"], core=core, fund=True)
        miniscript = miniscript_corpus.verify_regtest(catalogs["miniscript"], core)
    print("Bitcoin Core checks:", json.dumps(bitcoin, sort_keys=True))
    print("Miniscript checks:", json.dumps(miniscript, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "verify", "verify-regtest", "verify-report"))
    parser.add_argument("report", nargs="?", type=Path)
    args = parser.parse_args()
    if (args.command == "verify-report") != (args.report is not None):
        parser.error("verify-report requires a report path")
    verify_archive()
    catalogs = fixture_catalogs()
    rendered, manifest = generated_files(catalogs)
    count = verify_catalog(manifest, catalogs)
    if args.command == "generate":
        for path, data in rendered.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    else:
        for path, data in rendered.items():
            require(path.is_file() and path.read_bytes() == data,
                    f"generated artifact differs: {path.relative_to(ROOT)}")
    if args.command == "verify-regtest":
        run_regtest(catalogs)
    elif args.command == "verify-report":
        verify_report(args.report, manifest)
    print(f"{args.command}: 64 cases, {count} scenarios, draft {DRAFT_VERSION}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, bitcoin_fixtures.CoreRpcError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
