# Step 5 protocol, declared before fresh outcomes

13 November 2026. Freeze the implementation at `36ee9eef341b561cb79f8f1c2edfbd9c7533187f`. Changes in this stage are evaluation tooling/tests and documentation only. No detector, correlation resolver, labels, matching rules or splits may be tuned after outcomes are seen. The app and scanned applications remain stopped.

## Evaluation tracks

1. **Exposed synthetic regression:** reuse the original pinned OWASP BenchmarkPython manifest, all 1,230 cases/categories and shared helpers. All three splits have already been exposed; none is a fresh holdout. Evaluate default Theron and the existing interprocedural/local-import/sanitizer ablations on identical bytes. Compare against previously pinned Bandit 1.9.4 and Semgrep CE 1.185.0/rules revision `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`. Existing baseline outputs may be reused only with source/manifest/report hash verification and explicit cached provenance; never describe cached runs as fresh measurements. Use the unchanged file/CWE adapter/mappings; retain unsupported categories, errors and unmatched alerts. Published older outcomes remain preserved.

   The existing PySASTBench tuning corpus may also be rerun as a regression, using its unchanged adapter and retaining its unresolved-label error. It is not a held-out study.
2. **Exposed real-code development comparison:** use only the seven preselected development CVEs and 14 source snapshots already reviewed in Step 3, without source downloads, application harnesses or execution. Compare per-file/default/experimental candidates with the same pinned baseline configurations. Retain all unrelated alerts and errors. Draft target sink locations exist for only part of this sample; helper-only cases need additional context. No independent precision/recall denominator exists, and patched files are not automatically clean. Record strict CWE + proposed sink-line matches separately from raw alerts. Baseline semantic CWE mappings remain the ones already used by the OWASP adapter.
3. **Correlation mechanism and cost:** rerun the nine original Step 4 controls with the pass enabled/disabled on identical findings/files. Verify original findings/context/summary unchanged, inspect group endpoints and unresolved outcomes, and measure the post-analysis pass separately with warm-up and repeated measurements. Bandit/Semgrep are component-code baselines, not MCP graph tools: graph results are not applicable, not zero-score failures. Original author-labelled controls are not independent real-code edge accuracy or a reviewer-time study.

## Integrity and reporting

- Verify frozen reserve membership and source function hashes. Keep all nine validation and nine test real-world candidates closed; do not stage or pass their snippets/source to tools.
- Pin tool versions, rules revision, implementation/adapter hashes, exact inputs and raw-report digests. Store raw baseline snippets only in the ignored cache; publish derived rule/CWE/line outcomes and hashes, not third-party bodies or credentials.
- Bandit scans all default tests/severity/confidence with `--ignore-nosec`. Semgrep uses local pinned Python rules, disabled metrics/version checks, no git-ignore filtering, ten-second rule timeout and two jobs. Static tools may parse text but target packages/scripts are never installed/imported/executed.
- Report single-run tool durations as environment-specific diagnostics, not a speed ranking. Repeated correlation-pass timings measure only that pass on tiny original controls.
- Retain adverse/neutral ablations. Synthetic template-cluster intervals are descriptive and do not establish real-code generalization. Report unknown/unadjudicated cases explicitly.
- Prepare a human review packet with exact revisions, sources, proposed matching units and blank independent judgements. Assistant-authored review drafts do not satisfy the independent-label gate.

Step 5 can deliver a reproducible engineering comparison now. Publication-level independent real-code/edge evaluation remains incomplete until an independent reviewer adjudicates eligible labels and the research matching protocol is accepted. No new numerical target is used to select cases or redefine success after outcomes.

Pre-run integrity finding: the old Windows baseline stage has extra carriage returns from text-mode staging. Cached raw report hashes match their old publications, but staged file bytes do not match the corpus. Therefore this stage will use fresh exact-byte stages and fresh baseline runs. The corpus, labels and matching adapter remain unchanged. Older file/CWE outcomes remain historical results with this provenance caveat; no claim about the effect on scores is made before rerunning.

Post-outcome diagnostic amendment: after nine Semgrep development outcomes changed, replay the old-stage bytes with the same tool/rules, and repeat old/exact bytes at an identical diagnostic target path. This tests staging as the cause without changing primary inputs, labels, detector or scoring. Diagnostic runs are excluded from the primary comparison; all outcomes are retained rather than selecting the preferred result.
