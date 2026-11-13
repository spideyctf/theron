# Real-code validation: matched baselines and available context

13 November 2026. Detector frozen at `bb9fb3092011aec3c5de0af4b28dea9fdc2b4715`; no detector/rule changes were made. All nine previously exposed validation cases and all 28 pinned files are included. The nine final real test cases remain closed. This is static testing: no target modules, applications, setup scripts, dependencies or exploits were executed.

## Current metrics and assessment

| Exposed synthetic dataset/split | Precision | Recall | F1 | TP / FN / FP / TN |
| --- | ---: | ---: | ---: | --- |
| OWASP development | 95.73% | 72.40% | 82.45% | 202 / 77 / 9 / 449 |
| OWASP validation | 100.00% | 91.67% | 95.65% | 77 / 7 / 0 / 164 |
| OWASP test | 100.00% | 73.03% | 84.42% | 65 / 24 / 0 / 156 |
| PySASTBench | 95.88% | 78.15% | 86.11% | 93 / 26 / 4 / 116 |

These are good engineering regression results on exposed synthetic inputs. PySASTBench retains one unresolved label as an error. They are not independent real-world accuracy, certification, or proof that every individual alert is correct. The broader platform still lacks demonstrated real-code detection benefit.

## Real-code results

| Engine/configuration | Files covered | Total raw alerts | Scanner errors | Vulnerable reference-match cases | Patched reference-match cases |
| --- | ---: | ---: | ---: | ---: | ---: |
| Theron, isolated files | 28 | 2 | 0 | 0 | 0 |
| Theron, available grouped files | 28 | 2 | 0 | 0 | 0 |
| Bandit 1.9.4 | 28 | 74 | 0 | 0 | 1 |
| Semgrep CE 1.185.0, pinned Python rules | 28 | 90 | 0 | 0 | 0 |

**Do not read alert totals as confirmed vulnerabilities or the reference columns as accuracy.** The matching rule requires a reported start line within an original declared function span and an exact CWE from upstream metadata. Broad/mismatched CWE metadata, incomplete caller context and a repair location that is not a detection sink can prevent a match. No independently adjudicated source/sink units are available. Quiet patched files are not true negatives; the patched Bandit match is not automatically a false positive. No real-world precision, recall or superiority is claimed.

Theron's two alerts are medium-confidence weak-hash configuration advisories at lines 915/917 of the ChuanhuChatGPT modules/utils.py snapshots. Both files retain original function-hash errors for the labelled target; these advisories are not matches for the labelled CWE-610 issue and are not additional confirmed vulnerabilities.

Bandit's patched reference match is in CVE-2024-21542. Its guard and patch semantics require review before assigning a verdict. All unmatched alerts and rule/CWE/start/end metadata are retained. Semgrep INFO findings remain included rather than being confused with Theron's coverage notices. Compact published results omit third-party source snippets and scanner messages; raw baseline reports remain in the ignored cache.

## What the context test establishes

The grouped configuration supplies every available declared source file separately for each CVE, upstream role and revision: **18 groups**, with **7 available import candidates**. Roles and revisions never mix. The same frozen analyzer receives original repository-relative paths so its existing local-import resolution can operate.

This is available-file context, **not whole-repository analysis**. Unresolved import candidates include external/standard libraries and imported symbols, so their count is not a missing-local-module score. No additional detections appear in this grouping. The next useful experiment requires audited matching units and more complete repository/framework/caller context, not simply another run of the same isolated files. [Context inventory](context-inventory.json).

## Input and label integrity

- All 28 files match the previous validation exposure hashes. The total source size is 449,273 bytes.
- Bandit and Semgrep use the exact same bytes. Native Linux verification checks **365 files: 28 sources plus 337 YAML rule files**.
- Semgrep rules remain at `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`: 378 configured rules, 371 applicable rules run. Version, flags and environment differences are recorded in [environment.json](environment.json). There is no speed ranking across Windows and WSL.
- The original **two label/function-hash failures** remain unscorable for every engine, even though their raw files are scanned. They are separate from scanner errors.
- An AST function-span search finds no alternative exact hash matches for those references. It also cannot validate the one-line non-function reference in the fixed file. No original span/hash was rewritten, and no secondary score was manufactured. [Diagnostic](hash-diagnostic.json).

The [protocol](PROTOCOL.md) was recorded before these comparisons. The reference labels and validation source were already exposed; the final real test source remains closed. Author/assistant review is disclosed and is not independent adjudication.

## Reproduction

Use the same trusted Theron checkout/freeze, the cached validation files from the [previous exposure ledger](../research-repair-2026-11-13/validation-exposure.json), Bandit 1.9.4, Semgrep 1.185.0 and the pinned rules checkout. From the repository root on Windows:

```powershell
.venv/Scripts/python.exe -m scripts.evaluate_real_validation --fetch
.venv/Scripts/python.exe -m scripts.compare_real_validation stage
.benchmark-cache/bandit-venv/Scripts/python.exe -m bandit -r .benchmark-cache/real-comparison/stage/real-validation -f json -o .benchmark-cache/real-comparison/bandit.json --ignore-nosec --exit-zero
```

The stage command requires an empty stage directory. It creates an exact-byte inputs.tar in the comparison cache. On native Linux/WSL, use scripts/verify_real_stage.py with explicit archive, inventory, new target directory and receipt paths. The receipt belongs at CACHE/native-verification.json; the inventory is REPORT/input-provenance.json. The verifier extracts only into a new directory and checks every file hash.

Run the pinned Semgrep executable on NATIVE/real-validation with NATIVE/rules/python as its config, writing CACHE/semgrep.json. Set SEMGREP_ENABLE_VERSION_CHECK=0 and retain these flags:

```text
--metrics=off --disable-version-check --no-git-ignore --no-rewrite-rule-ids --timeout 10 --jobs 2 --json
```

Finally, from Windows:

```powershell
.venv/Scripts/python.exe -m scripts.compare_real_validation compare
.venv/Scripts/python.exe -m pytest tests -q
```

The comparison rejects changed detector/rules, metadata, source bytes, file coverage or missing native verification. Per-engine results, per-case reference outcomes, context inventory, environment and input hashes are published here. Canonical JSON hashes are recorded in artifact-hashes.json.

## Next work

Audit eligibility, source/sink locations and patch semantics for the four validation cases tagged with currently modelled CWE families (psiTurk, OAuthLib, Starlette and Luigi). Investigate the mismatched ChuanhuChatGPT references separately. Build bounded repository context for development work and document any newly exposed files. If this validation source guides detector changes, treat it as development exposure and declare another freeze. Do not open the final test reserve merely to obtain a better number.

The current conclusion is that real-code effectiveness remains unestablished. This comparison improves the evidence and reproducibility; it does not make the project paper-ready. **498 Python tests pass**, including controls for context isolation, baseline INFO retention and native line-ending integrity.
