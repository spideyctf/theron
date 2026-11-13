# Final real-code, external-label and operational evaluation

13 November 2026. **The final static probe matches 0/9 vulnerable reference cases. Theron is not publication-ready as a broadly accurate analyzer.** The engineering pipeline works within tested bounds; the broader detection claim fails this test.

Detector/rules freeze: `4c166e0b179e1ff10a3a432e2bd439765b601a81`. [Selection](selection.json), [pre-exposure protocol](PROTOCOL.md), [summary](summary.json). Protocol commit `d0b186e` precedes all final source retrieval; scoring adapter commit `7a7fb81` precedes outcomes. Its later addition only reproduces published inputs; matching labels/rules were unchanged. `git diff 4c166e0 -- scanner rules` remains empty. No post-result tuning was performed.

## External labels: corroborated, with limits

The unchanged external PatchEval metadata defines the nine reserved cases and their original CWE/function spans. All 22 pinned files match Git blob bytes and all 38 declared function hashes. No label/retrieval errors were discarded. External CNA CVE records at CVEProject/cvelistV5 revision `74be3883281f235199e31e1bcbe3421e8d30ec3c` cover all nine CVEs; seven overlap the benchmark CWEs and seven include exact patch-reference URLs (case-insensitive comparison).

CVE-2021-39163 has benchmark CWE-863 versus CNA CWE-200. CVE-2021-23727 has no CNA CWE in this snapshot. Missing exact patch URL overlap does not mean the patch is invalid. These discrepancies remain visible; labels and denominators were not changed in response to results. [CVE records](external-cve-records.json), [corroboration](label-corroboration.json), [source receipts](source-exposure.json).

These are independently authored external vulnerability/repair labels, not independent adjudication of Theron alerts or proof that patched files contain no other flaws. No second human reviewer participated. The user previously declined external review; automation cannot truthfully satisfy that human-review gate. Original CVE categories and repair spans are an imperfect SAST oracle. [PatchEval itself warns](https://github.com/bytedance/PatchEval#-verified-dataset-and-docker-images) that reference patches need not satisfy every strengthened test.

## Untouched test at the frozen detector

| Tool / available context | Vulnerable reference cases matched | Patched reference cases matched | Whole-file alerts | Scanner errors |
| --- | ---: | ---: | ---: | ---: |
| Theron isolated | 0/9 | 0/9 | 0 | 0 |
| Theron grouped available files | 0/9 | 0/9 | 0 | 0 |
| Bandit 1.9.4 | 0/9 | 0/9 | 10 across 4 files | 0 |
| Semgrep CE 1.185.0 | 0/9 | 0/9 | 12 across 5 files | 0 |

Matching uses the original CWE and original function span, excluding coverage notices. All nine cases remain represented. Zero matched patched cases is not an established false-positive rate, and zero alerts does not establish 100% precision. These are frozen reference-span observations on nine project-separated candidates, not independently adjudicated whole-project accuracy. No confidence interval on confirmed real-world accuracy is justified by this proxy. Tool alert counts do not establish which tool is better.

The final sample was source-unopened before this freeze and run. Source and results are now exposed; future detector tuning needs a fresh holdout. Grouping uses only the declared available files at each CVE/role/revision, not complete repositories/callers. Baselines use identical 22 input files and 337 pinned Python rule files, verified as 359 exact-byte inputs on native WSL. Same configuration/CWE mapping as previous comparisons; Windows/WSL timings are not ranked. [Baseline configuration](baseline-environment.json), [byte inventory](baseline-inputs.json).

[Isolated results](theron-isolated.json), [grouped results](theron-grouped.json), [Bandit](bandit.json), [Semgrep](semgrep.json), [post-result static failure audit](failure-audit.json).

| Case | Missing mechanism / interpretation |
| --- | --- |
| Red DiscordBot, CVE-2020-15278 | Member-cache and authorization hierarchy semantics |
| GenericSetup, CVE-2021-21360 | Object creation and inherited View permissions |
| Celery, CVE-2021-23727 | Backend data selects a module attribute and invokes a reconstructed callable |
| Synapse, CVE-2021-39163 | Membership-dependent room visibility; original/CNA CWE disagreement |
| PyJWT, CVE-2022-29217 | Key-format and algorithm confusion |
| Planet SDK, CVE-2023-32303 | Secret-file creation permissions and existing-file repair |
| MechanicalSoup, CVE-2023-34457 | Remote form data to local-file read/upload and multipart boundaries |
| Superset, CVE-2023-49736 | Dialect-specific SQL fragment helper; no downstream execution sink in supplied context |
| h11, CVE-2025-43859 | Stateful chunk-footer validation; constructor metadata is not itself the parser sink |

The failure audit is assistant/author review after outcomes, with no new scoring units or detector changes. It explains hypotheses and context limits, not independent exploit validation.

## Bounded operational results

Fresh subprocesses on this Windows machine; three repeats per size, lexically selected exposed OWASP testcode files at pinned revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. Inputs, interpreter/platform and all raw repetitions are recorded in [operations.json](operations.json).

| Files | Median wall time | Empirical p95 | Maximum process peak working set |
| ---: | ---: | ---: | ---: |
| 25 | 0.834 s | 0.914 s | 33.97 MiB |
| 100 | 1.288 s | 1.314 s | 38.85 MiB |
| 250 | 2.219 s | 2.237 s | 47.96 MiB |

All 9 runs completed within the 120-second limit; fingerprints and export sizes were consistent across each size's repetitions. Fresh-process wall times include startup; measured pipeline includes file loading, profiling, default SAST, normalization, correlation and JSON/HTML/SARIF generation. These samples contain no repository MCP configuration, so timing the correlation pass does not measure nonempty graph scalability. With three samples, empirical p95 is simply the maximum, not a reliable production-tail estimate. Caches are uncontrolled, not OS-cold. Memory includes interpreter/imports. These timings exclude live transport and SCA advisory lookup.

The real in-process API contract accepted ten queued/running jobs and rejected overflow with HTTP429, kept forty concurrent health requests responsive, drained nine successful jobs and one injected failure, redacted the secret from the failure response, exported four reports and accepted/completed a subsequent recovery job. Transport and scanner were controlled. Health timings are raw local test observations, not an Internet-service SLA.

Regression validation: **556 Python tests, 13 frontend tests, TypeScript and production build pass**. One existing dependency deprecation warning remains. The new checks cover scoring boundaries, error preservation, path containment and queue recovery. No target module, setup script, exploit, archive extraction, MCP command or application/browser/server was executed.

## Live all-module smoke failure

The [separately declared live smoke](LIVE-PROTOCOL.md) against the same frozen public commit fetched all 273 selected GitHub files, then failed in SAST with `TypeError: argument of type 'NoneType' is not iterable` at `scanner/python_analysis.py:388`. The first harness did not retain network receipts on exception; those measurements are unavailable, not invented. All four modules were requested, but the pipeline did not finish. [Preserved failure](live-selfscan-failure.json). This is a concrete operational blocker beyond the successful bounded tests. Fix it separately, retain this original outcome, and do not rebrand post-fix evaluation on these exposed cases as untouched evidence.

## Reproduce

From the repository root, with development/web dependencies and pinned synthetic/rule caches installed:

```powershell
# Download only published final-test paths and verify published byte hashes.
.venv\Scripts\python.exe -m scripts.evaluate_final_realcode fetch
.venv\Scripts\python.exe -m scripts.evaluate_final_realcode evaluate
.venv\Scripts\python.exe -m scripts.audit_final_evidence labels
.venv\Scripts\python.exe -m scripts.evaluate_operations
.venv\Scripts\python.exe -m pytest tests -q
cd frontend
npm ci
npm test
npm run build
```

Initial acquisition used GitHub connector base64 responses and verified blob hashes. `stage` consumes that ignored acquisition cache; subsequent reproductions use `fetch` with the published immutable receipts instead. `audit_final_evidence stage-baselines` creates the exact Python-rule inventory from the pinned rule checkout. Run Bandit over `.benchmark-cache/final-realcode/stage` with `--ignore-nosec --exit-zero -f json`; run Semgrep natively with the published flags and absolute staged input path. Save their raw outputs in `.benchmark-cache/final-realcode/{bandit,semgrep}.json`. Native SHA-256 inventory must match `baseline-inputs.json` in `native-verification.json`, then `audit_final_evidence baselines` collects results. CVE records are committed so label corroboration is offline/reproducible.

Runtime measurements are expected to vary; detector outcomes, input bytes and labels are the reproducibility targets. [Artifact hashes](artifact-hashes.json) use UTF-8 text normalized to LF for checkout portability.

## What is complete and what remains

Completed: external-record corroboration for all nine reserved cases, a frozen untouched-source first evaluation with matched baselines and preserved adverse outcomes, and bounded resource/API operational checks. The broad platform has not become complete through evaluation. Supported SAST flow improvements do not cover the authorization, crypto, protocol and nonframework-source semantics revealed here.

Still required: independent human source/alert adjudication, real-code MCP-edge validation, AI/agentic/SCA-specific accuracy, measured reviewer benefit, target-runtime/exploit validation where claimed, and deployment/load/history-retention evaluation. This local API stores job/results in memory and does not establish durable or bounded long-running history. Publication readiness, industry-grade coverage, novelty and acceptance remain unestablished. Next development should address the failure classes on development material, then evaluate a new independently labelled holdout; this exposed test must not be recycled as unseen evidence.
