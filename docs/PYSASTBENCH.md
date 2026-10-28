# PySASTBench-backed detection tuning

Reference: [Victor725/PySASTBench](https://github.com/Victor725/PySASTBench),
commit `3ad04b72c516d0533a5dc9c8042c9808e69e0f40`. Latest evaluation run: 2026-10-28.
The synthetic corpus has 120 labelled vulnerable/fixed pairs across six CWE categories.
The external checkout is ignored and not shipped or redistributed with Theron.
No benchmark applications, setup scripts, or third-party scanners were executed.

## Measured result

Default SAST rules only, with identical scoring before and after tuning:

| Measure | Initial | Previous tuning | October 9 | Current |
| --- | ---: | ---: | ---: | ---: |
| Labelled vulnerable variants detected | 8 | 26 | 28 | 33 |
| Labelled vulnerable variants missed | 111 | 93 | 91 | 86 |
| Fixed variants with matched alerts | 0 | 0 | 0 | 0 |
| Fixed variants without matched alerts | 120 | 120 | 120 | 120 |
| Unscorable vulnerable labels | 1 | 1 | 1 | 1 |
| Recall over scorable vulnerable variants | 6.72% | 21.85% | 23.53% | 27.73% |

| Labelled CWE | Detected / scorable vulnerable variants | Fixed variants with matched alerts |
| --- | ---: | ---: |
| 22: path traversal | 0 / 20 | 0 / 20 |
| 77: command injection (includes child CWE-78) | 9 / 19 | 0 / 20 |
| 79: XSS | 1 / 20 | 0 / 20 |
| 89: SQL injection | 6 / 20 | 0 / 20 |
| 94: code injection | 12 / 20 | 0 / 20 |
| 502: deserialization | 5 / 20 | 0 / 20 |

These are labelled synthetic-case results, **not** a claim of zero false positives in real projects.
The current run also has zero alerts anywhere in the 120 fixed files, not just within labelled spans.
Recall remains low. Default path traversal and stored-XSS coverage is absent in this evaluation.
The same corpus was inspected during tuning; it is not an independent held-out validation set.

## What changed

- October 28: preserve possible taint across branches, exception paths and loops instead of requiring both paths to agree or clearing all taint. Merge import resolutions and literal allowlists separately, honor terminating branches, and retain safe assignments in all continuing paths. This fixes independently reproduced misses and detects five more command-injection cases. Loop handling remains bounded, without a fixed-point data-flow analysis.
- Added exact SQLite connection/cursor resolution and input-to-statement detection, without treating arbitrary `.execute()` calls as SQL.
- Added selected request sources, JSON/string propagation, and typed FastAPI string-route inputs; numeric parameters/conversions are not assumed injectable text.
- Added bounded direct same-file helper/method argument propagation. Parameter names alone still do not establish attacker control.
- Added literal identifier allowlist handling, including rejecting guards; a benchmark false positive on a validated SQL column motivated this fix.
- Added independent miniature positive/negative tests for these patterns, argument binding, recursion limits, and benchmark scoring.
- Added resolved socket `recv()` flows, including context-manager bindings and same-file deserialization helpers. Arbitrary `.recv()` methods are not assumed to be network inputs.
- Added explicit HTML-response checks and selected Django request, HTTP-handler, and Tornado argument sources. Escaped values and explicit plain-text/JSON responses stay quiet in independent tests. Custom headers, positional response options, indirect framework inheritance, stored XSS, and context-specific escaping are not fully modelled.
- Added whole-fixed-file alert counts separately from label-matched metrics. This exposes unrelated alerts without claiming the corpus labels establish whether those alerts are true or false positives.

## Scoring and known dataset mismatch

`python -m scanner.benchmark` evaluates the SAST plugin and never imports corpus code.
For vulnerable variants, a finding must match the CSV CWE and fall within the labelled function's AST line span.
CWE-78 is accepted under the dataset's CWE-77 command-injection label; other categories are not interchangeable.
For fixed variants, the same function span is used where present. If that function was removed or renamed,
the entire fixed file is checked for the labelled CWE; this fallback is recorded in each case.
Unrelated alerts are retained as counts but are not counted as detections of the labelled defect.
`fixed_file_alerts` separately counts fixed files with any alert, total alerts, and alerts outside the label match.
Informational coverage notices are not vulnerability alerts. Missing files/targets and parse errors are separate errors.

`77_DS-14` labels `NetworkDiagnosticTool.run_diagnotstic`, but the actual method is `run_diagnostic`.
The evaluator does not silently correct this typo. That vulnerable variant remains unscorable and causes exit code 1.
Removed/renamed functions in fixed variants are normal remediation, not missing-label errors.

## Reproduce

From the project root:

```powershell
git clone https://github.com/Victor725/PySASTBench.git .benchmark-cache/PySASTBench
git -C .benchmark-cache/PySASTBench checkout 3ad04b72c516d0533a5dc9c8042c9808e69e0f40
python -m scanner.benchmark --dataset .benchmark-cache/PySASTBench --output .benchmark-cache/results.json
python -m pytest tests -q -p no:cacheprovider
```

The result includes the dataset revision, manifest hash, source hashes, per-case outcomes, and per-CWE metrics.
With this pinned dataset the benchmark exits 1 for the label mismatch described above; inspect `errors` rather than hiding it.
Experimental rules can be evaluated separately with `--include-experimental`; do not combine their metrics with default scans.
The ignored reference folder is excluded from ordinary local/GitHub scan collection.

Real-world CVE archives were not downloaded or evaluated. AI-specific flows, dependency advisory accuracy,
SBOM completeness, exploitability, and deployed websites are outside this synthetic benchmark's scope.
