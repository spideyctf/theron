# Step 5 frozen engineering results

Implementation frozen at `36ee9eef341b561cb79f8f1c2edfbd9c7533187f`. No detector/correlation/label/split tuning followed these outcomes.

**This is exposed synthetic regression plus provisional development evidence. Zero real-code cases or graph edges have independent adjudication.** The nine real validation and nine real test candidates remain closed; the app and target applications were not started.

## Fresh exact-byte baseline comparison

The previous Windows baseline stage contained extra carriage returns. Fresh Bandit and Semgrep runs now use exact corpus bytes; native Linux input/rule hashes were verified. Older reports remain preserved. Historical per-case differences are retained in summary.json; old line-level provenance is not validated.

| Exposed split | Engine | TP | FN | FP | TN | Errors | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| development | theron | 56 | 223 | 14 | 444 | 0 | 80.00% | 20.07% | 32.09% |
| development | bandit | 85 | 194 | 11 | 447 | 0 | 88.54% | 30.47% | 45.33% |
| development | semgrep | 49 | 230 | 31 | 427 | 0 | 61.25% | 17.56% | 27.30% |
| validation | theron | 0 | 84 | 1 | 163 | 0 | 0.00% | 0.00% | 0.00% |
| validation | bandit | 59 | 25 | 20 | 144 | 0 | 74.68% | 70.24% | 72.39% |
| validation | semgrep | 28 | 56 | 20 | 144 | 0 | 58.33% | 33.33% | 42.42% |
| test | theron | 14 | 75 | 5 | 151 | 0 | 73.68% | 15.73% | 25.93% |
| test | bandit | 63 | 26 | 47 | 109 | 0 | 57.27% | 70.79% | 63.32% |
| test | semgrep | 31 | 58 | 22 | 134 | 0 | 58.49% | 34.83% | 43.66% |

All 1,230 cases and 14 categories remain included. Matching is the unchanged file/CWE adapter, not alert-level exploit precision or the official OWASP scorecard. Baseline support differs; raw unmatched-alert counts, errors, per-category outcomes and descriptive template-cluster intervals are preserved. Timing across Windows and WSL is not a performance ranking.

The controlled old-stage Semgrep development replay reproduces the earlier 42 TP / 29 FP. Exact-byte staging yields 49 TP / 31 FP, changing nine case outcomes (seven FN to TP, two TN to FP). Validation/test Semgrep, all Bandit outcomes and all Theron outcomes are unchanged. See staging-diagnostic.json; the primary comparison uses the corrected stage, not whichever run looks better.

Theron still has zero validation recall and lower test recall than both baselines. Fewer fixed-case matches at lower coverage do not establish superiority. These already-exposed splits are not fresh holdouts.

## Ablations

| Exposed split | Disabled feature | TP | FN | FP | TN |
| --- | --- | ---: | ---: | ---: | ---: |
| development | interprocedural | 54 | 225 | 14 | 444 |
| development | local_imports | 54 | 225 | 14 | 444 |
| development | sanitizers | 56 | 223 | 22 | 436 |
| validation | interprocedural | 0 | 84 | 1 | 163 |
| validation | local_imports | 0 | 84 | 1 | 163 |
| validation | sanitizers | 0 | 84 | 1 | 163 |
| test | interprocedural | 14 | 75 | 5 | 151 |
| test | local_imports | 14 | 75 | 5 | 151 |
| test | sanitizers | 14 | 75 | 5 | 151 |

Helper/import ablations each lose two development detections; disabling sanitizer models adds eight development fixed-case matches. All three remain neutral on exposed validation/test. No held-out benefit is attributed to neutral ablations.

## Seven real-code development pairs

Only the same 14 full-file snapshots were scanned. Four pairs have previously proposed target sink lines; three require more source/caller matching context. All seven remain represented. A match means a candidate matched the upstream CWE and proposed line, not an independently validated vulnerability. Patched-code candidates are not automatically false positives. All other alerts remain in compact baseline records.

| Case | Upstream snapshot role | Proposed sink | Theron default | Theron experimental | Bandit | Semgrep |
| --- | --- | ---: | --- | --- | --- | --- |
| CVE-2019-10856 | vul_func | 63 | no match | no match | no match | no match |
| CVE-2019-10856 | fix_func | 66 | no match | no match | no match | no match |
| CVE-2020-10691 | vul_func | unassigned | context needed | context needed | context needed | context needed |
| CVE-2020-10691 | fix_func | unassigned | context needed | context needed | context needed | context needed |
| CVE-2020-26215 | vul_func | 862 | no match | match | no match | no match |
| CVE-2020-26215 | fix_func | 867 | no match | match | no match | no match |
| CVE-2021-21354 | vul_func | 64 | no match | no match | no match | no match |
| CVE-2021-21354 | fix_func | 64 | no match | no match | no match | no match |
| CVE-2022-31506 | vul_func | 137 | match | match | no match | no match |
| CVE-2022-31506 | fix_func | 138 | no match | no match | no match | no match |
| CVE-2024-0243 | vul_func | unassigned | context needed | context needed | context needed | context needed |
| CVE-2024-0243 | fix_func | unassigned | context needed | context needed | context needed | context needed |
| CVE-2024-3571 | vul_func | unassigned | context needed | context needed | context needed | context needed |
| CVE-2024-3571 | fix_func | unassigned | context needed | context needed | context needed | context needed |

The real ablation records preserve every candidate and notice. Local-import ablation is structurally limited here because the probe scans isolated files without a repository index. Missing library callers/archive taint/untyped callback context remain failures, not excluded successes. Independent precision/recall is unavailable.

| Real development ablation | Default proposed matches, vulnerable / patched | Experimental proposed matches, vulnerable / patched |
| --- | --- | --- |
| interprocedural | 0 / 0 | 1 / 1 |
| local_imports | 1 / 0 | 2 / 1 |
| sanitizers | 1 / 0 | 2 / 1 |

Only four pairs have proposed target lines; these are candidate counts, not TP/FP rates. Disabling helper calls loses the OpenDiamond vulnerable-flow match. Sanitizer ablation is neutral here: the patched safe_join call is an unsupported return wrapper, not demonstrated explicit sanitizer handling. An original safe_join-to-shell control also misses CWE-78; see failure-probes.json. This is a future development fix, not a detector change hidden inside this evaluation.

## Correlation controls and cost

Nine original author-labelled controls preserve findings, context and summary under enabled/disabled correlation: **True**. Enabled-pass per-case median times range from 0.0255 to 0.1237 ms (one warm-up, 30 repetitions). These tiny controls do not establish scale, throughput or reviewer-time benefit.

Bandit/Semgrep graph comparison is not applicable. The pilot adds inspectable relationships, not newly detected vulnerabilities or independent real-code edge validation.

## Remaining research gate

An output-blinded independent-review packet and separate upstream-role key are provided. A human reviewer must adjudicate sources, sinks, guards, eligibility and matching units; mark missing context unknown. No assistant-written draft has been counted as independent validation. No source/body from the real validation/test reserve was used.

The engineering comparison is complete. Publication-level independent real-code/edge accuracy and any claimed triage benefit remain unmeasured. No industry-readiness or publication-acceptance claim follows.
