# OWASP BenchmarkPython study — protocol frozen before validation/test

## Dataset and purpose

Source: [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython), revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, expected results v0.1. This is an external **synthetic** benchmark with 1,230 labelled cases in 14 categories. It is not real-world CVE validation or AI-specific ground truth. It extends the previously inspected PySASTBench development corpus with a different framework/style and more unsupported categories.

Upstream code is GPL-3.0. The external checkout, staged tool inputs and raw reports containing upstream source are ignored; no corpus code is bundled here. This folder contains label metadata, hashes and derived evaluation outcomes. Scanning parses code as text and does not start the benchmark server, import its modules, install its dependencies or execute exploits.

The [PySASTBench real-world CVE archive](https://zenodo.org/records/17936545) is a separate candidate: the published ZIP is about 6.2 GB, and its visible rights field does not supply a clear license. It was not downloaded/evaluated in this study. Verify licensing and inspect vulnerable/fixed commit metadata before including it in a paper. These OWASP results must not be substituted for real-world evidence.

We also reserved metadata for 70 Python cases from [ByteDance PatchEval-Verified](https://github.com/bytedance/PatchEval), revision `b43285cdde80cc04608d5f1178a330b740c91c2d`. Function bodies were hashed without inspection, and no images or exploits were run. [Reserve metadata](realworld-reserve.json). This repair corpus needs a source/sink and fix-label audit before SAST scoring; there is no current Theron result on it.

## Fixed split and exposure

Protocol: `theron-owasp-v3`. See [split.json](split.json) for the seed, all source/support/label hashes and assignments.

- Development: **737 cases**. Source and outcomes may be inspected and used for detector changes.
- Validation: **248 cases**. Run after freezing the detector; do not tune to validation outcomes in this study.
- Test: **245 cases**. Run once after the freeze and retain all outcomes, including poor categories.

Cases share 24 upstream route-template families. Families are connected if they also contain identical normalized ASTs; an entire connected component stays in one split. Constants/identifiers are normalized only for grouping, not to alter detector inputs. Groups are sorted by size and seeded hash and assigned to the largest remaining case-count deficit against 60/20/20 targets. No detector score is used to choose assignments. This is a **template/category-shift split**, not a stratified random test, and categories need not occur in every split.

`BenchmarkTest00001` was viewed during suitability review; its entire family is forced into development. The shared helper modules were inspected and are supplied to every split, which is a limitation on independence. Template similarities beyond our grouping can remain.

Two pilot split schemes were discarded **before detector changes**: normalized AST hashing alone did not group whole upstream templates; random template buckets left only eight test cases. Aggregate development scores from those pilot schemes were observed, but their source inspection was limited to the declared case/shared helpers. The current split was then fixed before improvement work. This exposure history is retained rather than describing the corpus as completely blind from acquisition onward.

## Tools and scoring

Theron uses default `sast` rules only, with experimental rules disabled. All labelled categories stay in the denominator, including unsupported weak hashes, weak randomness, trust boundaries, cookie flags and others. Do not headline a supported-category subset as overall accuracy.

Bandit **1.9.4** is installed in a separate ignored virtual environment. Scan exactly the same selected case files and shared helpers, with all default tests, all severity/confidence levels and `--ignore-nosec`. Exclude neither difficult files nor import warnings from the raw baseline output. Imports alone are not remapped into vulnerability matches.

Our adapter matches a labelled file and CWE; this is **not the official OWASP scorecard** and is not alert-level precision. Bandit rules whose own CWE is broader are mapped by documented semantics: B102/B307 to code injection (94), B303/B324 to weak hashes (328), B311 to weak randomness (330), and B313–B320 XML parser call checks to XXE (611). These mappings were fixed before validation/test. See [Bandit call checks](https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html) and [hashlib checks](https://bandit.readthedocs.io/en/latest/plugins/b324_hashlib.html). Broad XML checks can alert on safe parses too; retain those false positives rather than claiming precise XXE verification.

Unmatched alerts and parser/coverage errors are retained. A baseline parsing failure is an error, not a true negative. A same-CWE alert elsewhere in the file can still match the label, so manual source/sink adjudication is needed before making exploit-level claims. There are no source-line labels in this CSV.

The second baseline is **Semgrep Community Edition 1.185.0**, with the entire `python/` directory from `semgrep/semgrep-rules` revision `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`: 378 configured rules, 371 applicable/run rules. It runs in WSL Linux against exactly the same case/helper bytes, with local configuration, metrics/version checks disabled, `--no-git-ignore`, `--no-rewrite-rule-ids`, `--timeout 10` and two jobs. All metadata CWEs are considered. Insecure/weak hashing rule IDs with general CWE-327 also match the weak-hash category CWE-328; other ciphers do not. The mapping was specified before consuming Semgrep results.

Semgrep's separately downloaded rules remain under their [upstream rules license](https://semgrep.dev/legal/rules-license/). They are used only as a local evaluation baseline, not bundled, served, incorporated into Theron or copied into its detectors. Raw baseline reports containing corpus snippets remain ignored; only derived outcomes/hashes and environment pins are published. Detector code was frozen before downloading these rules.

## Ablations fixed before held-out evaluation

Use the same detector and cases with one feature disabled at a time:

1. `interprocedural`: disable known helper/method invocations and return propagation.
2. `local_imports`: omit the repository-local AST index, retaining same-file analysis.
3. `sanitizers`: disable context-specific safe flags; literal allowlists and other branch modelling remain active.

These switches are test/evaluation configuration; default product behavior keeps all features enabled. Original regression tests check that each switch affects its intended mechanism. An ablation need not improve every metric or have a measurable effect on this corpus. Record negative/neutral results too.

Scope partitioning and advisory deduplication are not measured by this SAST-only corpus; this study does not claim they reduce real-world review effort.

## Reproduction

From the Theron root, with Python 3.12:

```powershell
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git .benchmark-cache/BenchmarkPython
git -C .benchmark-cache/BenchmarkPython checkout f1291485808b66e20ddb6b01b10dc71b3df8c8ba
python -m scanner.owasp_benchmark --dataset .benchmark-cache/BenchmarkPython --manifest docs/evaluation/owasp-2026-11-12/split.json --split development --output .benchmark-cache/development.json

# Use an empty staging directory so no files from other splits remain.
python -m scanner.owasp_benchmark --dataset .benchmark-cache/BenchmarkPython --manifest docs/evaluation/owasp-2026-11-12/split.json --split test --stage-dir .benchmark-cache/bandit-test
python -m venv .benchmark-cache/bandit-venv
.benchmark-cache/bandit-venv/Scripts/python -m pip install bandit==1.9.4
.benchmark-cache/bandit-venv/Scripts/python -m bandit -r .benchmark-cache/bandit-test -f json -o .benchmark-cache/bandit-test.json --ignore-nosec --exit-zero
python -m scanner.owasp_benchmark --dataset .benchmark-cache/BenchmarkPython --manifest docs/evaluation/owasp-2026-11-12/split.json --split test --bandit-json .benchmark-cache/bandit-test.json --output .benchmark-cache/test-bandit.json

python -m scanner.owasp_benchmark --dataset .benchmark-cache/BenchmarkPython --manifest docs/evaluation/owasp-2026-11-12/split.json --split test --ablation interprocedural --output .benchmark-cache/test-no-calls.json
```

Use `.benchmark-cache/bandit-venv/bin/python` on Linux/macOS. Replace `interprocedural` with `local_imports` or `sanitizers` for the other ablations. Reuse the committed split instead of regenerating it after seeing outcomes. Do not execute corpus setup/run scripts.

For the Semgrep baseline, use Linux/WSL, install `semgrep==1.185.0` in an isolated environment and clone the pinned rules revision separately:

```bash
git clone https://github.com/semgrep/semgrep-rules.git .benchmark-cache/semgrep-rules
git -C .benchmark-cache/semgrep-rules checkout a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2
semgrep scan --config .benchmark-cache/semgrep-rules/python --metrics=off --disable-version-check --no-git-ignore --no-rewrite-rule-ids --timeout 10 --jobs 2 --json --output .benchmark-cache/semgrep-test.json .benchmark-cache/bandit-test
python -m scanner.owasp_benchmark --dataset .benchmark-cache/BenchmarkPython --manifest docs/evaluation/owasp-2026-11-12/split.json --split test --semgrep-json .benchmark-cache/semgrep-test.json --output .benchmark-cache/test-semgrep.json
python scripts/summarize_owasp.py
```

The baseline environments are recorded in `bandit-environment.txt` and `semgrep-environment.txt`. Native Linux temporary copies were used to avoid WSL/Windows filesystem overhead; input contents and complete scanned-file counts were checked. The before snapshot is archived from commit `34f6ab0` and scanned using the same new adapter with that snapshot's own scanner/rules imports; its source hash is recorded. Evaluation timing fields cover different stages and are not a runtime ranking.

To reconstruct that baseline without replacing your working tree, archive the trusted historical implementation and use the snapshot helper:

```powershell
git archive --format=tar --output=.benchmark-cache/before.tar 34f6ab0 scanner rules
python -c "import tarfile; tarfile.open('.benchmark-cache/before.tar').extractall('.benchmark-cache/before', filter='data')"
python scripts/evaluate_owasp_snapshot.py --snapshot-root .benchmark-cache/before --revision 34f6ab09075c02b5fd4debb3e3c355fdae78adb1 --dataset .benchmark-cache/BenchmarkPython --manifest docs/evaluation/owasp-2026-11-12/split.json --split test --output .benchmark-cache/test-before.json
```

Use Python 3.12 for these commands. The helper imports a trusted Theron implementation, never benchmark application modules. It does not automatically fetch or execute historical third-party software.

## Publication limits

This is an initial comparative study against two pinned baseline configurations, on a synthetic corpus with shared helpers and few coarse groups. CodeQL/Pysa comparisons, independent real-world/AI-specific holdouts, independent label adjudication and a reviewer study remain outstanding. Descriptive template-cluster bootstrap intervals are included in `summary.json`, with only six test clusters and explicit undefined resample counts. No significance or superiority claim is made. Docker was not running; Semgrep ran in the existing WSL environment instead. Single-run timings are not a controlled performance comparison. See [all results](RESULTS.md); validation/test are now exposed and cannot become fresh holdouts again after tuning to their outcomes.
