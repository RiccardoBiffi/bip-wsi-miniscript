# Technical conformance assessment

Use this procedure to assess an implementation against a specific release of the WSI Conformance Test Specification (CTS). The assessment describes a tested endpoint and issuer under the WSI draft. Publish the evidence and scope alongside any statement of technical conformity.

## 1. Specify the claim

Identify the device model, firmware version and build, adapter and revision when used, carrier binding and version, relevant settings, and one Bitcoin network. Include the firmware digest when available and document how the assessor identified the running build. Create a report for each distinct endpoint scope. Record the protocol version, profiles, features, policy formats, PSBT and transaction versions, signing hash types, registration modes, device enforcement and resource limits covered by the assessment.

Save the endpoint's observed `capabilities` response as evidence. Compare it with the endpoint behavior and the declared assessment scope. When an adapter is in use, test the effective capabilities available through that adapter and carrier. Identify any capabilities reported during discovery whose scope remains unassessed. Label the assessment `self-test` for the implementer's own execution or `independent` when an identified evaluator independently repeats the applicable suite.

## 2. Prepare and execute

1. Pin the CTS checkout and the SHA-256 of its manifest. Pin the runner, adapter and independent validation tools. Run `python3 tools/cts.py verify` and `python3 tools/cts.py verify-regtest` from that checkout. Record the commands and outcomes in the report package.
2. Prepare a dedicated endpoint with the suite's synthetic test key context and an isolated regtest node for witness and maturity checks. Record how the device, firmware, settings and key context were selected. For a hardware assessment, use the physical endpoint and its trusted interface.
3. Expand the manifest's scenarios for the endpoint scope and run the positive, negative, process and device UI steps. Collect required evidence for each applicable parameter tuple. An observer records exact device-visible policy terms and approval or refusal. Checks claimed as device-enforced need signer-side evidence appropriate to the scenario. Follow the [harness contract](harness.md).
4. Record the suite version, manifest digest, assessment lane and assessor, endpoint, claims, tool versions, evidence file digests and scenario results in a JSON report. Keep evidence paths relative to the report package. Explain reasons for missing runs, narrow applicability, and any redactions. Validate the package with `python3 tools/cts.py verify-report REPORT`. The [report schema](../cts/report.schema.json) defines the interchange format.

## 3. Determine the result

| Outcome | Use when |
| --- | --- |
| `pass` | The scenario ran and all required assertions are supported by the required evidence. |
| `fail` | Execution produced an outcome that violated a required assertion. Record the observed and expected outcomes with evidence. |
| `not-run` | A required scenario, parameter tuple, independent check or required observation remains unexecuted or unsupported by evidence. Give the reason. |
| `inapplicable` | Manifest applicability excludes the scenario or parameter tuple for this scope. Cite the condition in the notes. |

An endpoint conforms to a stated scope when every applicable mandatory scenario and parameter tuple passes with the required evidence. The required set includes the Core tests and the cases implied by each profile, feature, version, mode and carrier in the scope. Give an overall result only after checking completeness and evidence references. A failure or a missing mandatory result blocks that claim. A narrower assessment can support a smaller passing claim when its required scenario set is complete. Preserve the original results and explain the scope of the narrower claim.

Use simulator reports for simulator evidence and debugging. Hardware conformity requires an execution package tied to the tested physical endpoint, including its device observations. Evaluate device-path and screen evidence when reviewing a report. Validation of the JSON and referenced digests checks package integrity and coverage.

## 4. Publish and maintain the assessment

Publish the scope, issuer, date, report and tool references. State which mandatory cases passed, failed or were unexecuted under the scope and disclose any limitations on access to the evidence. Distribute evidence in a reproducible form consistent with the assessor's disclosure policy. A detached signature over the report can identify the issuer and protect the integrity of the published result. The report authenticates the tested firmware only to the extent established by the recorded provenance evidence.

Use a statement that names the assurance level and exact scope. An example for a completed independent assessment follows.

> Independently assessed by [evaluator] on [date]. [Device model and firmware build], through [adapter revision and carrier binding] on [network], passed the applicable WSI draft CTS [version and manifest SHA-256] scenarios for [profiles and features]. Evidence and limitations appear in [report reference].

Treat a changed firmware, adapter, carrier, configuration, key-context behavior or CTS release as a change in scope. Identify which cases the change can affect. Repeat those cases under the new scope, repeat discovery, and record the basis and identity of any evidence reused for unaffected cases. If the impact cannot be bounded, rerun the applicable suite. Reissue, narrow or withdraw the prior claim according to the resulting evidence.
