# Step 3 continuation: redirect evidence precision

13 November 2026. Starting checkpoint: `e6f71b7d5fcc388907943f428843358c18676faf`. This continues [the seven-case development audit](../development-2026-11-12/README.md). No new target source was downloaded, no reserved source was inspected, and the application was not started. The original source hashes and frozen partitions remain unchanged.

## What changed

The analyzer now distinguishes a value appearing in a redirect URL from observed input controlling its network origin. A bounded proof handles literal local-path/HTTP(S) prefixes, string concatenation, f-strings and literal-list joins. The input remains tainted for shell, SQL, filesystem and HTML checks.

Proofs are snapshots of local string assignments. All incoming branches must retain the proof; reassignment, changed query bases/separators, destructive string transformations and local function calls invalidate or discard it. Attribute/subscript setters are excluded because they can transform assigned values. Prefix removal, incomplete authorities and attacker-controlled leading components still produce candidates. The existing sanitizer ablation disables these proofs.

A recognized query separator (`'&' if '?' in base else '?'`) is tied to the specific, unchanged base value. When observed input only follows that separator but the configured base scheme/trust is unresolved, the result becomes **INFO / coverage-notice**, with source/sink evidence and an explicit request for context review. It does not become a proven-safe flow. This distinction matters for non-HTTP schemes and unresolved configuration/callers.

## Same-source development comparison

[Summary and changed records](summary.json), [new raw probe](after.json), [previous raw probe](../development-2026-11-12/after.json). All 14 file hashes match and all 18 declared function spans still match the original frozen metadata.

| Jupyter development snapshot | Previous experimental candidates | Current experimental output |
| --- | --- | --- |
| Vulnerable | URI redirect at line 862; configured URL/query join at 912 | URI candidate at 862; unknown-base notice at 912 |
| Patched | Slash-normalized redirect at line 867; configured URL/query join at 917 | Normalization candidate at 867; unknown-base notice at 917 |

Across all seven pairs, experimental vulnerability candidates decrease from **5 to 3**, with **2 explicit context-review notices** retained. Default output stays at one vulnerable-file path finding and no patched-file finding. Proposed target-flow matches remain 1/7 by default and 2/7 experimentally; one patched target still receives an experimental candidate. These are development-probe counts, not independently validated recall or alert precision. The two reclassified query joins were outside the labelled target function; they are not silently discarded or counted as true positives.

## Why slash normalization remains a review candidate

An original, offline control using Node **22.17.1** demonstrates that rooting a raw string after trimming `/` can leave a slash/backslash sequence whose parsed origin is another host. This follows browser-style URL parsing, which treats backslashes specially for HTTP(S). See the [WHATWG URL Standard](https://url.spec.whatwg.org/#relative-slash-state) and [Node WHATWG URL API documentation](https://nodejs.org/api/url.html#the-whatwg-url-api).

The [control receipts](url-controls.json) contain eight explicit URL vectors, one strip/root counterexample and 48 prefix/payload checks. They perform **zero network requests and execute no target application code**. This is a string/parser counterexample to a universal sanitizer claim. It does **not** establish whether a deployed Jupyter version accepts, rewrites, rejects or exposes that raw input through its framework/proxy/browser request path. The patched snapshot is not relabelled vulnerable. Its candidate stays experimental pending runtime/context and independent label review.

## Verification and reproduction

- **364 Python tests passed**, with the existing dependency deprecation warning.
- 39 original precision tests cover safe prefixes, unsafe authorities, stale facts, branch/scope behavior, property setters, source/sink traces, ablation and exported notice classification.
- Offline URL controls pass and now run in both Windows/Ubuntu CI jobs.
- [Default tuning regression](pysastbench-regression.json) remains **93 TP / 26 FN / 4 FP / 116 TN**, one unresolved label: recall **78.15%**, precision **95.88%**, F1 **86.11%**. Exit code 1 preserves that upstream label error. This corpus remains tuning evidence.

```powershell
python -m pytest tests -q -p no:cacheprovider
node scripts/check_redirect_origins.mjs
python -m scripts.probe_realworld_development --manifest docs/evaluation/realworld-2026-11-12/manifest.json --selection docs/evaluation/development-2026-11-12/selection.json --cache-root .benchmark-cache/realworld-step3 --output .benchmark-cache/realworld-step3/precision-recheck.json
python -m scanner.benchmark --dataset .benchmark-cache/PySASTBench --output .benchmark-cache/realworld-step3/tuning-recheck.json
```

These commands perform static analysis and offline controls; they do not start the web application or execute scanned projects. Source-cache preparation and baseline-worktree instructions remain in the earlier development report. The new probe records the current detector hash and preserves missing-file/hash errors.

Step 3's engineering precision increment is delivered. **Independent human labels, richer caller/framework context and the final research matching protocol remain open. Zero real-world cases have independent adjudication.** No new OWASP evaluation or real-world holdout score is claimed, and the correlation pilot has not started.
