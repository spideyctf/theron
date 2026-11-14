# Mechanism repairs, external pilot and current limitations

14 November 2026. Initial detector freeze `6eb6aee2e554c52a5f7519f0f7b6bed016f56f1a`; external pilot registration `22522ae`; final implementation/performance checkpoint `ab48e94d3f84ac6a8707a5d71285d05663dae997`. [Full project status and remaining gates](../../STATUS.md).

## Implemented increment

The analyzer now separates claims decoded from a compact token from the payload accepted by a resolved keyed JWS verifier. Returning the independent claims produces advisory evidence unless supported equality binds them to verified claims. Unknown/unverified decoding alone does not establish this mismatch. Finite public-key blacklists attached to HMAC key storage expose omitted recognized key formats, with extra guards or changed key values retaining uncertainty. Reassigned lists and shadowed builtins are not trusted guards.

Selected HTTP checks identify permissive integer parsing of framing lengths and a narrow unsupported-transfer-coding branch. They require resolved library/context evidence. A visible lexical rejection guard suppresses that specific anti-pattern; its entire accepted language and the full parser are not certified. General HTTP grammar, proxies and deployment behavior remain outside these checks.

Equivalent bounded branch states are merged to avoid wasting the path budget. Original controls cover aliases, terminating/nonterminating checks, payload identity, unrelated APIs, shadowing, unresolved helpers and ablations. **688 Python tests and 15 frontend tests pass; the frontend builds.** Seven backend-generated original findings cover new and existing obligation families through CLI/API/JSON/HTML/SARIF/frontend and remediation copy. No target application or discovered credential was executed/authenticated on the host.

## Exposed development result

The six earlier candidates were already inspected. The new implementation yields obligation candidates in five vulnerable mechanisms and none of their repaired units: open-object, python-jwt, python-jose, Waitress and Gunicorn. CVAT's custom parent-object IAM mechanism remains missed; its unrelated unresolved-policy notice remains on both revisions. Across the application files there are seven medium candidates and two informational notices. These are not confirmed deployment vulnerabilities.

Strict CNA-CWE/function matching yields **2/5** labelled vulnerable cases (Waitress and Gunicorn); python-jose lacks a CNA CWE. open-object's CWE-639 differs from the authorization candidate CWE-863, and python-jwt's CWE-290 differs from the signature-binding candidate CWE-347. Do not relabel these to inflate strict matches. [Default](default.json), [ablations](static-summary.json). The earlier [1/6 frozen semantic result](../obligations-2026-11-14/README.md) remains intact; this improvement is source-guided development, not held-out recall.

## New ten-project pilot

[Vul4Py](https://github.com/tabudz/vul4py/tree/f80f861012cb7b7cfeca7323be51d33e72eaf8f3) describes paired exploit and functional oracles. Its claim is not a local oracle success. We pinned the 100-row metadata and selected ten distinct repositories by SHA-256 ordering with a fixed seed, excluding raw repository names in the earlier declared real-code manifests. [Registration](vul4py-registration.json), [protocol](PROTOCOL.md). Selection did not use detector outcomes, mechanism eligibility or target source. A post-run canonical-alias audit found one Requests project overlap with CVE-2018-18074. The original ten cases remain; the fully project-separated subset contains nine cases, seven with CNA CWE labels, and has zero strict matches. [Overlap audit](vul4py/overlap-audit.json). This is a partition failure, not ten fully held-out projects. The selection guard now checks canonical aliases and refuses to replace an existing registration. Prior model training exposure is unknown.

All ten selected cases remain. Changed Python files and their first-parent revisions were retrieved after the freeze; added test files correctly have no vulnerable-parent counterpart. Tests and `tests.py`/`conftest.py` are excluded from application alert totals but retained as oracle/context receipts. [Source plan](vul4py-source-plan.json), [receipts](vul4py-source-receipts.json), [external CNA records](vul4py-cve-records.json).

**Result: zero strict CNA-CWE/repair-location matches in eight labelled cases; two cases have no CNA CWE and remain unscorable under that rule.** Twenty case/revision groups contain 46 application source snapshots. Ten whole-file alerts remain, five in each OctoPrint revision. There are zero scanner or unit-extraction errors. [Raw frozen pilot](vul4py/default.json). These adverse results are not whole-project recall: changed-file context is incomplete, and function/hunk spans are author-derived repair proxies rather than independently reviewed vulnerability locations. Quiet repaired units do not prove globally safe code.

| Selected case | Project | Strict result / runtime status |
| --- | --- | --- |
| CVE-2023-32309 | pymdown-extensions | No match; runtime not run |
| CVE-2025-53366 | MCP Python SDK | No match; runtime not run |
| CVE-2023-30608 | sqlparse | No match; runtime not run |
| CVE-2025-5120 | smolagents | No match; runtime not run |
| CVE-2021-28363 | urllib3 | CNA CWE missing; no strict score; runtime not run |
| CVE-2024-35195 | requests | No match; prior-project alias overlap; runtime not run |
| CVE-2017-16618 | owlmixin | CNA CWE missing; no strict score; runtime not run |
| CVE-2024-32977 | OctoPrint | No match; unrelated whole-file alerts retained; runtime not run |
| CVE-2024-34078 | html-sanitizer | No static match; upstream paired test reproduced |
| CVE-2024-55655 | sigstore-python | No match; runtime not run |

Pinned Bandit 1.9.4 and Semgrep CE 1.185.0 / rule revision `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` cover the same 46 byte-verified application files. They emit **54 / 100 alerts**, with zero reported errors. Their repair-function overlaps concern owlmixin and OctoPrint and are not automatically semantic matches. No accuracy or speed superiority is claimed. [Baseline inputs](vul4py/baseline-inputs.json), [results](vul4py/baselines.json), [native verification](vul4py/baseline-native-verification.json).

## Independent upstream behavior versus static detection

For html-sanitizer, the unmodified fixed-revision `SanitizerTestCase.test_normalize_early` and pre-existing `test_01_sanitize` run against each version inside the isolated runner. Vulnerable: **one security assertion fails, one functional test passes**. Fixed: **both pass**. The unsafe normalized HTML is compared as text, not rendered or executed. This is upstream-authored test evidence, not an author-invented exploit oracle. It reproduces behavior that Theron still misses. [Runtime logs](vul4py/runtime.json), [locked wheels](vul4py/runtime-dependencies.json).

The overlay uses unmodified target modules and the same fixed upstream test module. Sources/dependencies are read-only mounts; only ephemeral package symlinks and bounded temporary storage are created. The probe verifies absent host paths and blocked networking. The previous namespace runner's limits and shared-kernel/per-process resource caveats remain. Nine other pilot environments and all their complete functional/exploit suites remain unverified. A two-test success is not the full Vul4Py acceptance protocol or independent human review.

## Performance, regressions and preserved failures

Initial `6eb6aee` and import-gated `b4d979c` offline smokes both exceeded the **120-second wall deadline**. Preserve [initial failure](offline-selfscan-initial.json) and [first optimization failure](offline-selfscan-import-gate.json). The instrumented diagnostic took 305.93 seconds and recorded 315.6 million calls; it is not an ordinary throughput benchmark. [Profile summary](performance-diagnostic.json). The main hot path repeatedly built constant API-name sets in source queries. The final optimization constructs those sets once and does not cache state-dependent taint results.

[Payload equivalence](optimization-equivalence.json) checks all 32 case/revision groups from the six development cases and ten-project pilot against the original frozen output. Post-exposure performance/precision changes are not a new held-out detector result. [Latest bounded smoke](offline-selfscan.json) records its actual outcome and retains all coverage notices.

The final smoke **completes in 84.04 seconds wall time against the unchanged 120-second limit** (reported scan time 80.93 seconds), reading 273 of 275 selected pinned files across SAST/AI/agentic. Three application coverage notices, twelve context findings and two oversized-file notices remain. This is one bounded offline workload with SCA/network excluded, not production capacity or proof of a clean repository. The two timeouts above remain failures in the ledger.

All **1,470 exposed synthetic variant outcomes/alert counts remain unchanged**. OWASP development/validation/test recall is 72.40% / 91.67% / 73.03%; precision is 95.73% / 100% / 100%. PySASTBench is 78.15% recall / 95.88% precision, one unscorable vulnerable label, and 17 fixed-file alerts across 14 files. [Initial checkpoint](synthetic-summary.json), [final optimized replay](final-regression/synthetic-summary.json). None is new independent real-world accuracy.

## Reproduction

Use `6eb6aee` scanner/rules for the initial frozen development/pilot result, with the evaluation scripts and receipts from this checkpoint. `python -m scripts.evaluate_mechanisms` writes the separate exposed-development report. `python -m scripts.evaluate_vul4py_pilot` verifies Git blob IDs and SHA-256 receipts before parsing sources. Restore the receipt URLs at their pinned revisions into `.benchmark-cache/vul4py-pilot/<id>/<role>/<path>`; never substitute current upstream branches. No target imports are needed for static analysis.

`python -m scripts.compare_vul4py_baselines stage` prepares identical bytes, pinned rules and Bandit output. Extract its tar into `/tmp/theron-vul4py-baselines` in WSL using `tarfile.extractall(..., filter='data')`; run `compare_vul4py_baselines.py verify-native /tmp/theron-vul4py-baselines` there, then pinned Semgrep against staged `rules/python` and `sources` with the flags recorded in `baselines.json`. `python -m scripts.compare_vul4py_baselines compare` validates every target's membership.

For opt-in upstream runtime replay, download only the exact wheels in `vul4py/runtime-dependencies.json` into `/tmp/theron-vul4py-wheels`, verify their hashes and run `wsl -d kali-linux -- python3 /mnt/d/TheLobe/sem7/theron/scripts/run_vul4py_oracle.py`. No install/build hooks or target code run on the ordinary host. For the final implementation, `python -m scripts.check_mechanism_optimization` checks payload equivalence and timed smoke; `python -m scripts.check_final_mechanism_regressions` replays synthetic regression without repeating that smoke. Use the declared revision guard; do not bypass it and relabel results.

## Acceptance decision

Engineering delivery and four exposed detection gaps improved. Broad research readiness **is not complete**: fresh-code generalization, nine new runtime environments, CVAT authorization, independent location/alert review, a measured cross-layer contribution and general production validation remain open. The original and new adverse results stay visible. This is technical implementation and evaluation work, not a paper draft.
