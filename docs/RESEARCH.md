# Research direction and publication readiness

Assessment date: 12 November 2026. This is a study proposal with a preliminary abstract, not a submitted or peer-reviewed manuscript. No acceptance is guaranteed.

## Broader platform direction

The agreed project goal is now a unified, evidence-driven security analysis and verification platform spanning application code, dependencies, secrets, infrastructure, AI pipelines and agents. The [platform contract](PLATFORM.md) defines current/experimental/planned coverage, evidence requirements, the first correlation pilot and the ranked implementation backlog. The present implementation and measurements below cover only part of that target.

Working project/research title: **Theron: A Unified Security Analysis and Verification Platform for AI-Enabled and Agentic Software Systems**. The platform is broad; research claims must identify and measure a specific cross-layer benefit. The existing abstract below describes the completed prototype study and is not yet an abstract for an implemented full-platform contribution.

## Current assessment

Theron is a functioning research prototype: CLI and local web review, bounded Python analysis, commit-pinned evidence, advisory alias grouping and explicit application/context scopes are implemented. The [earlier evaluation snapshot](evaluation/2026-11-12/README.md) was followed by an [OWASP study](evaluation/owasp-2026-11-12/RESULTS.md), with pinned Bandit/Semgrep baselines, a grouped synthetic split and three ablations. OWASP test recall rose from 3.37% to 15.73%, but validation recall is zero and both baseline tools detect more held-out vulnerable cases. The original PySASTBench tuning recall is now 77.31%. This contrast is central evidence, not something to hide behind the stronger tuning score.

These results do not justify an overall competitive-accuracy or industry-readiness claim. A synthetic template/category-shift holdout and same-protocol baselines now exist; independent real-world/AI-specific evaluation, measured triage benefit and systematic alert adjudication remain missing. XSS recall on the original tuning benchmark is still 10%. Neither synthetic benchmark measures AI-specific checks or dependency accuracy.

## Progress on the three priorities

| Priority | Completed in this iteration | Next requirement |
| --- | --- | --- |
| Fair baseline comparisons | Bandit 1.9.4 and Semgrep CE 1.185.0, pinned Python rule revision, same input splits, explicit CWE mappings, all categories and errors retained | Add independent adjudication and compare on real projects; broader tool/config sensitivity |
| Untouched evaluation | Detector frozen before 248 validation and 245 test cases; template groups kept together; exposure history disclosed | The results are now exposed. Use a new real-world/AI-specific holdout for future generalization claims |
| Ablations | Three feature switches, independent regression tests, all split outcomes and cluster bootstrap summaries published | Test mechanisms on a corpus with relevant flows; neutral held-out ablations do not prove benefit |

The test split has only six coarse template groups and shared helpers, so it is not a substitute for a project-level real-world study. Those results remain attached to the frozen detector. The subsequent Step 3 increment below changes framework modeling; the exposed OWASP result does not establish held-out performance for that newer code.

## Reserved real-world target

The [ByteDance PatchEval-Verified repository](https://github.com/bytedance/PatchEval) is a promising next source. We pinned revision `b43285cdde80cc04608d5f1178a330b740c91c2d` and reserved metadata for **70 Python cases** out of 230 entries. See [realworld-reserve.json](evaluation/owasp-2026-11-12/realworld-reserve.json). At reservation, function bodies were hashed programmatically but not inspected; no images or exploits were run. The Step 3 development-source exposure is recorded below. The repository has an Apache-2.0 license; upstream target projects retain their own terms.

This is a repair benchmark, so it needs a SAST adapter and label audit first. Audit patch URLs, identify vulnerable/fixed snapshots and labelled sinks, deduplicate by project/CVE/code against development data, then freeze a project-separated final split before inspecting held-out source. The upstream documentation warns that reference patches may not satisfy every strengthened PoC; do not automatically label every fixed function clean. This reserve has no Theron accuracy result yet. Pulling every Docker image is unnecessary for the planned static-first assessment.

**Step 2 metadata checkpoint:** [audit, protocol and frozen manifest](evaluation/realworld-2026-11-12/README.md) now cover all 70 cases in 48 project components. Partitions are 26 development, 9 validation, 9 test and 26 development-only because of prior metadata exposure. All 310 metadata queries resolve. Exact code hashes and project/fork identities informed grouping; semantic duplicates and source/patch label correctness remain unverified. No target source was displayed or detector run, and zero cases are scorable. Next, adjudicate development source before changing detectors; independently adjudicate reserved labels without exposing them to tuning.

**Step 3 development checkpoint:** [source review, raw probes and precision gate](evaluation/development-2026-11-12/README.md). Seven preselected development cases yielded 14 source snapshots and 18 matching function hashes. Default probe target matches remain 1/7; experimental redirects add a vulnerable match and a patched-code match, so they remain opt-in. General Tornado request-body/inheritance changes improve the previously inspected tuning corpus to 93 TP / 26 FN / 4 FP / 116 TN (78.15% recall). This is development evidence; no independent real-world denominator or publication claim follows. Source/patch exposure is recorded, and reserved source remains closed. B02 independent adjudication and redirect precision are still pending.

## Candidate contribution

**Step 4 engineering checkpoint:** [MCP configuration-to-code correlation pilot](evaluation/correlation-2026-11-13/README.md) now provides report-local relationships, unresolved reasons and consistent exports/UI. Nine original controls and same-input disabling preserve all original findings and severity counts. This demonstrates bounded integration only; independently labelled real-code edges, applicable comparisons and measured incremental benefit are still required for research claims.

The [13 November redirect-precision follow-up](evaluation/redirect-precision-2026-11-13/README.md) preserves the same source sample and frozen splits. Two query-only experimental candidates become explicit unknown-base notices; fixed-origin proofs have adversarial original controls and a sanitizer ablation check. A slash/backslash parser counterexample justifies retaining an experimental normalization candidate, without proving runtime reachability or relabelling the patched snapshot. Tuning results remain unchanged. These are engineering/development observations; independent adjudication and application context remain necessary.

The proposed platform contribution is whether combining supported code, configuration, dependency and agent evidence identifies additional actionable risks or improves review decisions compared with the component tools/outputs alone. This is not yet demonstrated. The first planned pilot links an explicitly configured local Python entrypoint to a supported dangerous code flow, preserving unknown runtime exposure and privileges.

Source/sink evidence, sanitizer contexts and report scopes remain component research questions within that broader goal. A combination of SAST, SCA, a dashboard and YAML rules is useful engineering, but integration alone is insufficient evidence of research novelty. Novelty and benefit of the correlation method need related-work review and independent evaluation.

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

Static security tools can impose review costs when source evidence, dependency matches and demonstration code are presented with the same certainty. We present Theron, a local security review prototype combining bounded Python flow analysis, context-specific sanitizer handling and explicit report scopes. After changes developed on an OWASP BenchmarkPython development split, a frozen detector identified 14 of 89 vulnerable test cases and matched five of 156 fixed cases, compared with three vulnerable detections and five fixed-case matches before the changes. Pinned Bandit and Semgrep configurations detected more vulnerable test cases, while Theron had fewer fixed-case matches. Validation recall was zero. On the previously inspected PySASTBench tuning corpus, recall was 77.31%, demonstrating a substantial gap between the tuning score and the broader synthetic evaluation. Three controlled ablations were neutral on the held-out splits. The study reports limitations, failure modes and reproducible artifacts; real-world/AI-specific holdouts and measured reviewer benefits remain future work.

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
