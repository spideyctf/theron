# Frozen OWASP evaluation results

Default Python SAST, all labelled categories. These are synthetic file/CWE case metrics, not alert-level exploit precision or the official OWASP scorecard.

Detector freeze: `a504494e35b961770a5c37896a7f115bfe025088`. No detector changes followed validation/test unblinding. The later adapter change adds Semgrep JSON import only.

| Split | Engine | TP | FN | FP | TN | Errors | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| development | Theron before | 5 | 274 | 7 | 451 | 0 | 41.67% | 1.79% | 3.44% |
| development | Theron frozen | 56 | 223 | 14 | 444 | 0 | 80.00% | 20.07% | 32.09% |
| development | Bandit | 85 | 194 | 11 | 447 | 0 | 88.54% | 30.47% | 45.33% |
| development | Semgrep | 42 | 237 | 29 | 429 | 0 | 59.15% | 15.05% | 24.00% |
| validation | Theron before | 0 | 84 | 0 | 164 | 0 | undefined | 0.00% | 0.00% |
| validation | Theron frozen | 0 | 84 | 1 | 163 | 0 | 0.00% | 0.00% | 0.00% |
| validation | Bandit | 59 | 25 | 20 | 144 | 0 | 74.68% | 70.24% | 72.39% |
| validation | Semgrep | 28 | 56 | 20 | 144 | 0 | 58.33% | 33.33% | 42.42% |
| test | Theron before | 3 | 86 | 5 | 151 | 0 | 37.50% | 3.37% | 6.19% |
| test | Theron frozen | 14 | 75 | 5 | 151 | 0 | 73.68% | 15.73% | 25.93% |
| test | Bandit | 63 | 26 | 47 | 109 | 0 | 57.27% | 70.79% | 63.32% |
| test | Semgrep | 31 | 58 | 22 | 134 | 0 | 58.49% | 34.83% | 43.66% |

## Ablations

| Split | Disabled feature | TP | FN | FP | TN | Precision | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| development | interprocedural | 54 | 225 | 14 | 444 | 79.41% | 19.35% |
| development | local_imports | 54 | 225 | 14 | 444 | 79.41% | 19.35% |
| development | sanitizers | 56 | 223 | 22 | 436 | 71.79% | 20.07% |
| validation | interprocedural | 0 | 84 | 1 | 163 | 0.00% | 0.00% |
| validation | local_imports | 0 | 84 | 1 | 163 | 0.00% | 0.00% |
| validation | sanitizers | 0 | 84 | 1 | 163 | 0.00% | 0.00% |
| test | interprocedural | 14 | 75 | 5 | 151 | 73.68% | 15.73% |
| test | local_imports | 14 | 75 | 5 | 151 | 73.68% | 15.73% |
| test | sanitizers | 14 | 75 | 5 | 151 | 73.68% | 15.73% |

## Interpretation

- Test detection increased from 3 to 14 of 89 vulnerable cases, with five fixed-case matches both before and after. The test split has only six coarse families.
- Validation recall is zero: its category mix exposes unsupported and unmodelled behavior. This result must remain visible.
- Both pinned baselines detect more labelled vulnerabilities on validation/test. Theron has fewer fixed-case matches on test; neither number alone establishes superiority.
- Disabling interprocedural/local-import analysis loses two development detections. Disabling context-specific sanitizer flags adds eight development false-positive cases. All three ablations are neutral on validation/test, so the held-out gains cannot be attributed to them.
- The baseline versions, configurations, semantic CWE mappings and unmatched-alert behavior are documented in README.md. Per-CWE and per-case outcomes remain in each raw result.
- The initial baseline is reconstructed from archived commit 34f6ab0, not a guessed reproduction of its behavior. The before/after detector source hashes are recorded.
- Bootstrap intervals and undefined resample counts are in summary.json. With few related templates they do not establish real-world generalization or statistical superiority.
- Validation/test outcomes are now exposed. Keep them as a frozen report/regression resource; future tuning based on these outcomes needs a new untouched final evaluation.
- Runtime numbers are single-run diagnostics across different tool environments; do not present them as a fair performance ranking.
