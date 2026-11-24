"""Exercise applicability and evidence rules without a hardware device."""

from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import cts  # noqa: E402


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = cts.read_json(cts.MANIFEST)

    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.report_path = root / "report.json"
        self.report = {
            "schema_version": 1,
            "suite": {
                "version": self.manifest["draft_version"],
                "manifest_sha256": cts.digest(cts.MANIFEST.read_bytes()),
            },
            "assessment": {
                "kind": "self-test", "lane": "simulator", "assessor": "synthetic test",
                "started_at": "2000-01-01T00:00:00Z", "completed_at": "2000-01-01T00:01:00Z",
            },
            "endpoint": {
                "mode": "native", "model": "synthetic fixture",
                "firmware": {"version": "test"}, "adapter": None,
                "carrier": "stream",
                "binding": {"name": "simulated-stream", "version": "1", "medium": "ipc"},
                "network": "regtest", "configuration": {},
            },
            "claims": {
                "protocol_version": 1, "profiles": [cts.CORE],
                "features": [], "carriers": ["stream"],
                "policy_formats": ["bip388-v1"], "psbt_versions": [0, 2],
                "transaction_versions": [2, 3], "registration_modes": ["per-operation"],
                "ecdsa_sighashes": [1, 129], "schnorr_sighashes": [],
                "enforcement": {
                    "policy_validation": "device", "policy_review": "device",
                    "address_display": "device", "change_verification": "device",
                    "signature_scope": "device",
                },
                "limits": {
                    "container_bytes": 65536, "psbt_bytes": 8192, "policy_bytes": 4096,
                    "template_bytes": 4096, "descriptor_bytes": 0, "keys": 8, "owned_keys": 3,
                    "ast_nodes": 128, "ast_depth": 16, "tap_leaves": 0, "tap_depth": 0,
                    "inputs": 8, "outputs": 8, "targets": 8, "policies_per_sign": 2,
                    "label_bytes": 32,
                },
                "miniscript": {context: {"coverage": "none", "fragments": [], "restrictions": []}
                              for context in ("wsh", "tapscript")},
            },
            "tools": {"runner": "test fixture"},
            "evidence": [],
            "results": [],
        }
        for kind in ("wire", "oracle", "device-ui", "device-path", "process"):
            path = f"{kind}.txt"
            data = f"synthetic verifier test for {kind}\n".encode()
            (root / path).write_bytes(data)
            self.report["evidence"].append({"id": kind, "kind": kind, "path": path,
                                            "sha256": cts.digest(data)})
        for (case, scenario, parameters), kinds in self.required():
            self.report["results"].append({
                "case_id": case, "scenario_id": scenario, "parameters": dict(parameters),
                "outcome": "pass", "evidence_ids": sorted(kinds),
            })

    def required(self, report=None):
        report = self.report if report is None else report
        return list(cts.required_scenarios(self.manifest, report["claims"], report["endpoint"]))

    def verify(self):
        self.report_path.write_bytes(cts.json_bytes(self.report))
        return cts.verify_report(self.report_path, self.manifest)

    def test_core_expands_advertised_combinations(self):
        matches = [dict(params) for (case, scenario, params), _ in self.required()
                   if (case, scenario) == ("WSI-CAP-003", "advertised-ecdsa-combination")]
        self.assertEqual(len(matches), 8)
        self.assertIn({"psbt_version": 2, "transaction_version": 3,
                       "ecdsa_sighash": 129, "registration_mode": "per-operation"}, matches)
        self.verify()

    def test_full_forces_context_and_descriptor_scenarios(self):
        report = deepcopy(self.report)
        report["claims"]["profiles"] = [cts.FULL]
        report["claims"]["schnorr_sighashes"] = [0, 1]
        report["claims"]["registration_modes"] = ["token"]
        case_ids = {case for (case, _, _), _ in self.required(report)}
        self.assertEqual(case_ids, set(self.manifest["profiles"][cts.FULL]))
        self.assertIn("WSI-TR-003", case_ids)
        self.assertIn("WSI-WSH-005", case_ids)
        self.assertIn("WSI-DPA-003", case_ids)
        self.assertNotIn("WSI-FEE-001", case_ids)

    def test_qr_medium_activates_segmentation_scenarios(self):
        self.report["endpoint"]["binding"]["medium"] = "qr"
        required = {scenario for (case, scenario, _), _ in self.required()
                    if case == "WSI-CAR-002"}
        self.assertIn("reordered-qr-segments", required)
        self.assertNotIn("stale-file", required)

    def test_missing_mandatory_row_blocks(self):
        self.report["results"].pop()
        with self.assertRaisesRegex(ValueError, "mandatory results are missing"):
            self.verify()

    def test_inapplicable_cannot_skip_mandatory_row(self):
        row = self.report["results"][0]
        row.update(outcome="inapplicable", notes="simulated skip", evidence_ids=[])
        with self.assertRaisesRegex(ValueError, "mandatory results are blocking"):
            self.verify()

    def test_evidence_must_match_kind_and_digest(self):
        row = next(item for item in self.report["results"] if "device-ui" in item["evidence_ids"])
        row["evidence_ids"].remove("device-ui")
        with self.assertRaisesRegex(ValueError, "missing evidence kinds"):
            self.verify()
        self.report["evidence"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "evidence digest differs"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
