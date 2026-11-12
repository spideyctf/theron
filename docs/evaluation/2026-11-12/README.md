# Evaluation snapshot — 12 November 2026

Scanner and scanned repository: `ff71cf657d0597cddfacf072749972af3f88c13a`.
These measurements precede the documentation-only commit that publishes this snapshot.

## Files

- [benchmark.json](benchmark.json): unchanged evaluator output, including all 240 variant records, source hashes, manifest hash and the unresolved label.
- [metrics.json](metrics.json): derived metrics, environment, check results and explicit unmeasured quantities.
- [self-scan-summary.json](self-scan-summary.json): a fresh four-module GitHub scan of the exact commit. This is a smoke test, not ground truth or a comparative runtime measurement.

The benchmark was rerun on 12 November 2026 in Asia/Calcutta. Its results match the previous evaluation: TP=91, FN=28, FP=4, TN=116, one error. It exited 1 for the existing `77_DS-14` label typo. Fixed files generated seven alerts across six files; three alerts are outside the label match. Neither the evaluator nor dataset labels were modified.

The synthetic corpus was inspected during tuning and is not held out. Detection requires the labelled CWE and target function span; removed/renamed fixed targets use whole-file matching. CWE-78 is accepted under CWE-77. See [the protocol](../../PYSASTBENCH.md).

## Metric definitions

All rates use the scored variant counts, excluding the one error. Precision here counts variant outcomes and is not individual-alert precision.

| Metric | Formula | Result |
| --- | --- | ---: |
| Precision | TP / (TP + FP) | 95.79% |
| Recall | TP / (TP + FN) | 76.47% |
| F1 | 2TP / (2TP + FP + FN) | 85.05% |
| Accuracy | (TP + TN) / (TP + FP + FN + TN) | 86.61% |
| Specificity | TN / (TN + FP) | 96.67% |
| Balanced accuracy | (recall + specificity) / 2 | 86.57% |
| False-positive rate | FP / (FP + TN) | 3.33% |
| False-negative rate | FN / (TP + FN) | 23.53% |

Accuracy depends on the class balance of this corpus. Per-CWE metrics and counts are in the root README and JSON. No AUC is calculated because there is no ranked prediction/threshold sweep. Do not treat these as deployment accuracy or confidence-calibrated probabilities.

## Self-scan and engineering checks

The GitHub self-scan analyzed 76 supported files in 58.24 seconds: one application informational notice, zero application vulnerability alerts, 18 context detections (15 example, 3 test), and 151 SBOM components including 15 unresolved versions. The notice concerns unresolved dependency versions. OSV was queried live; results can change. A single run cannot establish scalability, detection quality or SBOM completeness.

Python: 237 tests passed, with one FastAPI/Starlette test-client dependency deprecation warning. Frontend: 8 tests passed; TypeScript and Vite production build passed. Environment: Windows, Python 3.12.6, Node 22.17.1, npm 11.12.0. The checks use mocks/fixtures where appropriate; passing them does not validate every external advisory or vulnerable flow.

## Reproduction

Follow [the root README](../../../README.md#reproduce-the-checks) using dataset commit `3ad04b72c516d0533a5dc9c8042c9808e69e0f40` and scanner commit above. Compare manifest/source hashes and per-case outcomes, not just rounded aggregate scores. The external dataset is not redistributed here.

To repeat the self-scan, configure `GITHUB_TOKEN` for read access, then run:

```powershell
ai-sec-scan --repo spideyctf/theron --branch ff71cf657d0597cddfacf072749972af3f88c13a --format json --output self-scan.json
```

The SHA used as `--branch` pins the target. Record your configuration, software versions and date; live network/advisory behavior may differ.
