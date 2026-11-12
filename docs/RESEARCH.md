# Research direction and publication readiness

Assessment date: 12 November 2026. This is a study proposal with a preliminary abstract, not a submitted or peer-reviewed manuscript. No acceptance is guaranteed.

## Current assessment

Theron is a functioning research prototype: CLI and local web review, bounded Python analysis, commit-pinned evidence, advisory alias grouping and explicit application/context scopes are implemented. The [evaluation snapshot](evaluation/2026-11-12/README.md) reproduces 76.47% recall, 95.79% case-level precision and 85.05% F1 on a synthetic tuning corpus. Regression tests pass. These justify reporting an engineering artifact and preliminary evaluation.

They do not yet justify a competitive accuracy or industry-readiness claim. There is no held-out evaluation, same-protocol comparison with other scanners, measured triage benefit or systematic real-world alert adjudication. XSS recall is 10%. The benchmark does not measure AI-specific checks or dependency accuracy.

## Candidate contribution

Working title: **Theron: Evidence-Aware Static Security Review for Python and AI Applications**.

The research question should concern whether explicit source/sink evidence, sanitizer contexts and report scopes improve security review under bounded analysis. A combination of SAST, SCA, a dashboard and YAML rules is useful engineering, but integration alone is insufficient evidence of research novelty.

Taint analysis, interprocedural flow and source/sink models already exist in [CodeQL](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/) and [Pysa](https://pyre-check.org/docs/pysa-basics/). A literature review must establish the specific difference from prior systems. Treat the contribution below as a hypothesis until that review and evaluation are complete.

Potential contributions to test:

1. A bounded, inspectable analysis that treats model output as an explicit source and records evidence without executing scanned applications.
2. A reporting model that retains fixture/example evidence while separating application scope, uncertain credentials and dependency-version matches.
3. An empirical study of detection/triage tradeoffs, including failure modes and analysis-budget effects, with reusable evaluation artifacts.

## Research questions and experiments

| Question | Proposed experiment | Required outcomes |
| --- | --- | --- |
| RQ1: What is detection quality on unseen code? | Freeze detector/configuration; evaluate independently selected real-world vulnerable/fixed commits and an AI-specific holdout; prevent project/near-duplicate leakage | Per-CWE TP/FP/FN/TN, alert-level adjudication, unresolved cases and confidence intervals |
| RQ2: How does it compare with existing tools? | Run pinned Bandit and Semgrep configurations, plus CodeQL or Pysa where feasible, on the same snapshots, supported CWEs and budgets | Paired per-case results, feature/support differences, failures/timeouts, comparable precision/recall and runtime |
| RQ3: Which mechanisms account for changes? | Controlled ablations of interprocedural/import propagation, sanitizer contexts and AI source models; separately evaluate scope partitioning and alias grouping | Detection deltas, raw/unique/application/context alert counts and lost true positives |
| RQ4: Does the report help reviewers? | Blinded counterbalanced review tasks with and without traces/scope metadata, after appropriate institutional approval | Correct decisions, time to decision, disagreements and whether real findings in example paths are overlooked |
| RQ5: What are the cost and coverage limits? | Repeated cold/warm runs on a range of repository sizes, budgets and dependency conditions | Median/p95 wall time, peak memory, files analyzed/skipped, budget exhaustion and network contribution |

Bandit is a useful pattern-check baseline, not a direct substitute for a general interprocedural engine. Do not penalize a tool for intentionally unsupported CWEs without reporting that difference. Pin query packs, rule configurations, tool versions, revisions and timeouts. Do not compare scores copied from different papers or protocols as if they were head-to-head results.

## Evaluation design

- Keep PySASTBench as a disclosed development/tuning set. Its authors provide [synthetic and real-world dataset information](https://github.com/Victor725/PySASTBench); verify the real-world archive, license and labels before using it. Existing numbers are not real-world results.
- Choose holdout cases independently of Theron's current successes. Keep vulnerable/fixed versions and near-duplicates in the same split; freeze rules before evaluation. Record any later tuning and use another untouched set afterward.
- Cover both unsafe and safe AI-related patterns: model text reaching execution, safe structured dispatch, model loading, legitimate subprocess use and sanitizer combinations. Have independent reviewers establish labels from source and fixes; retain uncertainty and disagreements.
- Use a predefined source/sink or patch-level matching protocol. Report per-alert and per-case metrics separately. Preserve errors and whole-file alerts; do not discard hard cases or relabel upstream fixtures merely to improve scores.
- Treat path-based scope as a triage decision, not ground truth. Explicitly test real defects in examples/tests. Application-only precision cannot replace all-scope recall.
- Bootstrap by independent case pair or project rather than treating paired variants as unrelated observations. Use paired comparison tests where suitable. Publish uncertainty, effect sizes and failures, not just percentage improvements.
- For SCA, use independently labelled exact versions, alias sets and unresolved declarations. Compare inventory to known fixtures and report component precision/recall separately from vulnerability matching. A self-generated SBOM is not its own completeness oracle.

## Preliminary abstract

Static security tools can impose review costs when source evidence, dependency matches and demonstration code are presented with the same certainty. We present Theron, a local security review prototype for Python and AI application repositories. Theron combines bounded AST-based flow propagation, context-specific sanitizer handling and repository-local import analysis with dependency advisory matching and explicit report scopes. It preserves source/sink locations, advisory identities and contextual detections for inspection. On 119 scorable vulnerable variants and 120 fixed variants from the PySASTBench synthetic corpus, the current implementation detects 91 vulnerable variants and reports four label-matched fixed-case alerts, yielding 76.47% recall and 95.79% case-level precision. One additional vulnerable label is unresolved. These results come from a corpus inspected during development and do not establish held-out generalization. Stored XSS remains a major limitation. Independent baseline comparisons and reviewer studies are needed to evaluate the proposed detection and review benefits.

This abstract is accurate for the current snapshot, but a submission should replace preliminary gaps with completed experiments where relevant. Do not state superiority, novelty or user benefit as established facts.

## Paper structure

1. Problem and threat model: repository-level evidence for human review; explicit boundaries on exploitability and deployment.
2. Related work: Python SAST/taint engines, AI application security, advisory matching and alert triage.
3. Method: sources/sinks, propagation, sanitizer contexts, imports, budgets, scope handling and evidence schema; include pseudocode and examples.
4. Implementation and artifact: reproducible installation, versioned configurations and exported evidence.
5. Evaluation: datasets/splits, ground truth, baselines, ablations, runtime and optional reviewer study.
6. Results and failure analysis: raw counts, uncertainty, false positives/negatives, incomplete analyses and representative cases.
7. Threats to validity: tuning leakage, label quality, support differences, path heuristics, network variation and human judgement.
8. Availability, limitations and conclusion.

## Publication route

My assessment is that a tool/workshop paper is the most credible first target after the independent comparison and failure analysis. A full empirical research paper needs stronger novelty and validation. Check current calls after the study is ready instead of selecting a venue solely from its name or promising acceptance.

The [ICSE 2027 tool demonstration call](https://conf.researchr.org/track/icse-2027/icse-2027-demonstrations) is a useful example of expectations: novelty, soundness, usefulness, literature positioning, a video and an accessible artifact. Its 23 October 2026 submission deadline has already passed as of this assessment; it is not an available deadline to target now.

[JOSS submission criteria](https://joss.readthedocs.io/en/latest/submitting.html) currently require more than six months of public active development, demonstrated research use and open-source maintenance practices. The repository was created on 3 July 2026, so even continuous public availability since creation would not yet meet that duration. AI assistance must also be disclosed. Recheck the criteria before considering this route; repository age alone would not establish eligibility.

## Completion criteria before submission

- An advisor/subject expert agrees the claimed contribution differs from related work.
- Independent holdout results and fair baseline comparisons are complete, including safe near-misses and failure cases.
- Every empirical claim has a script, pinned configuration and accessible raw result.
- A release can be installed and evaluated by someone outside the team; record their feedback and fixes.
- Authors, affiliations, contributions, funding and AI assistance are accurately declared. Human authors review the entire code/evaluation/manuscript; AI does not satisfy authorship.
- Artifact/data licenses, any participant approval and release permissions are resolved.
- The selected venue's current scope, formatting, anonymity and submission rules are checked.

No participant study, baseline experiment, independent label review, publication, external adoption or acceptance is claimed by this plan.
