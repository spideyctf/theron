# Research-readiness repair checkpoint

13 November 2026. Detector freeze: `bb9fb3092011aec3c5de0af4b28dea9fdc2b4715`, committed before the first real validation source fetch. This checkpoint repairs known false-positive behavior, clarifies unverified hash evidence, updates the research claims and records the first frozen real-code validation probes. It does not establish publication readiness.

## Precision repair

All six label-matched OWASP test false positives shared the same complete guard: reject a value unless it starts and ends with the same quote and contains no such quote in its interior. For the modeled string operations, an unchanged accepted value is a Python string literal or fails parsing; it cannot introduce an additional executable expression. The analyzer now recognizes this exact guard. It does not broadly sanitize quotes, remove input taint or excuse arbitrary eval/exec use.

The guard fact survives only supported control-flow paths and direct, unchanged local-name use. Assignments, augmented assignments, transformed sink expressions and local calls invalidate or fail to transfer the proof. Incomplete guards, different variables/slices, guards that merely continue, and shell sinks remain unsafe controls. A bounded enumeration parses original candidate strings with ast.parse; it never executes them. Prefer ast.literal_eval or a data parser in application code despite the recognized guard.

| Exposed split | TP | FN | FP | TN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Development | 202 | 77 | 9 | 449 | 95.73% | 72.40% | 82.45% |
| Validation | 77 | 7 | 0 | 164 | 100.00% | 91.67% | 95.65% |
| Test | 65 | 24 | 0 | 156 | 100.00% | 73.03% | 84.42% |

Test false positives decrease from six to zero with all 65 vulnerable matches preserved. All 1,230 cases, categories, labels and the file/CWE matching adapter are unchanged; all final synthetic OWASP runs have zero errors. These remain exposed tuning results, not an untouched holdout or individual-alert exploit precision. All preceding reports are preserved.

PySASTBench remains 93 TP / 26 FN / 4 FP / 116 TN with one unresolved label retained as an error: 78.15% recall and 95.88% label-matched precision. Fixed files still carry 17 alerts across 14 files, including 13 outside labelled matches. Nine are weak-hash configuration advisories; no alert or denominator was removed to improve a score.

## Developer audit of fifteen alerts

[alert-audit.json](alert-audit.json) records source hashes, old/new case outcomes and dispositions for all six code-injection false positives and all nine extra fixed-file hash alerts. This is a developer/assistant audit, not independent adjudication.

The hash usages include a template cache key, worker/plugin/prediction identifiers, content checksums and version metadata. Weak algorithms are observed, but security-sensitive use and exploitability are not established for these nine alerts. The hash rule now has advisory maturity, medium confidence, static-configuration evidence and the title “Weak hash selected; security use unverified.” It remains visible in JSON, HTML, SARIF and the frontend's maturity field. These are not nine confirmed extra vulnerabilities. No naming-based allowlist silently declares cache/checksum uses safe; context can still matter.

## First frozen real validation exposure

All nine cases originally assigned validation were selected before fetching source, including unsupported categories. No patch bodies, applications, setup scripts or payloads were executed. The [exposure ledger](validation-exposure.json) records 28 immutable source snapshots, their byte hashes and acquisition. GitHub connector base64 content was checked against Git blob hashes. Two Starlette connector failures were retained and resolved through immutable raw URLs; their declared function hashes subsequently matched.

[real-validation.json](real-validation.json) retains every case, source failure, finding and reference unit. Twenty-six snapshots pass **34 declared function-span hashes**. Two snapshots for CVE-2024-5823 fail their declared function hashes and remain errors; their source or metadata was not rewritten to make the check pass. Successful probes emit no findings or parse/budget notices. Consequently there are **zero vulnerable or patched reference-span match cases**. This is an adverse coverage observation, not validated real-world recall of zero or proof that patched files are clean.

| Validation case | Upstream CWE metadata | Frozen observation |
| --- | --- | --- |
| CVE-2019-16789, Waitress | 444 | No reference-span match |
| CVE-2020-25459, FATE | 668 | No reference-span match |
| CVE-2021-4315, psiTurk | 77 / 78 / 94 | No reference-span match |
| CVE-2022-36087, OAuthLib | 601 | No reference-span match |
| CVE-2023-29159, Starlette | 22 / 73 | No reference-span match |
| CVE-2024-21542, Luigi | 22 / 73 | No reference-span match |
| CVE-2024-48911, OpenCanary | 863 | No reference-span match |
| CVE-2024-5823, ChuanhuChatGPT | 610 | Two function-hash failures; one other snapshot probes quietly |
| CVE-2025-27154, Spotipy | 276 | No reference-span match |

The probe analyzes pinned full files separately, not whole repositories with dependencies or application callers. Upstream repair roles and broad CWE metadata are not independently validated SAST source/sink labels. No precision/recall denominator is manufactured from quiet files. No baseline was run on this real validation slice. Source exposure is now recorded explicitly; these nine cases may not be presented as untouched in a later tuning cycle. The original Step 2 ledger remains an immutable historical receipt. **The nine final real test cases remain closed.**

## Research claim repair and next gates

The research document's abstract now uses the current results and includes the adverse real validation outcome. It no longer calls the older 14/89 result current or says that no baseline experiments exist. A primary-source related-work table distinguishes existing CodeQL/Pysa taint analysis and VIPER-MCP handler-level analysis from Theron's limited declaration-to-file association. It does not claim a new taint algorithm, first MCP analyzer, confirmed exploitability, superiority or measured reviewer benefit.

Still open: reference-unit and hash-mismatch investigation, repository/caller context for real projects, real-validation baseline comparison, a systematic literature review, measured real-code correlation correctness or reviewer benefit, scale measurements and a full manuscript. The user declined external review; author/assistant review must be disclosed and not called independent. Keep the final test reserve closed while addressing these gates. If detector changes are informed by the newly exposed validation sources, classify them as development work and use another freeze for any later evaluation.

## Reproduction and verification

Use Python 3.12 and the same pinned corpora/cache from the preceding studies. For synthetic results, run scanner.owasp_benchmark with the unchanged split manifest for each split and scanner.benchmark for PySASTBench. For the real probes:

```powershell
.venv/Scripts/python.exe -m scripts.evaluate_real_validation --fetch
.venv/Scripts/python.exe -m pytest tests -q
```

The real evaluator rejects detector/rule changes against the freeze, checks the original metadata freeze, permits all and only the nine validation cases, verifies cached bytes and declared function spans, and preserves errors. The optional fetch flag retrieves missing public snapshots and rejects bytes differing from published hashes. Sources remain in the ignored cache rather than being redistributed. The exposure ledger provides pinned retrieval paths. Raw synthetic/real results, the alert audit and canonical artifact hashes are published alongside this document.

Local Python regression suite: **494 passed**, with one existing dependency deprecation warning. The app was not started. The unchanged frontend tests/build are covered by delivery CI. No independently labelled accuracy, new exploitable vulnerability or publication acceptance is claimed.
