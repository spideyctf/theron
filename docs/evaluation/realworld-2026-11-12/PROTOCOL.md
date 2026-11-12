# Step 2: real-world metadata audit and split protocol

Declared 12 November 2026, before patch/source inspection and detector changes for this stage. Starting Theron checkpoint: `c56c8d59d58abf7a822a6e083837d8a1d3c7add3`.

## Inputs and exposure boundary

- PatchEval-Verified revision `b43285cdde80cc04608d5f1178a330b740c91c2d`, metadata SHA-256 `65e873923d738221389ed32408c4f5fa75882ea07609c500761207d013da0f62`.
- The existing reserve has 70 Python CVEs across 48 declared repositories. The upstream metadata also contains 105 vulnerable and 138 fixed function-location records, often using abbreviated revision IDs.
- Metadata fields, source paths/spans and hashes may be inspected. Snippet strings may be hashed programmatically for integrity/exact-duplicate checks, without displaying their contents. No detector runs, patch bodies, repository source downloads, application imports, images or exploits are permitted in this step.
- GitHub queries are restricted to repository metadata, Git commit objects, or a one-entry commit listing for revision resolution. Commit bodies/files/patch endpoints are not used. Stored responses omit messages, people and source bodies; they retain identifiers, parent/tree SHAs, dates and repository/license metadata.

The audit checks metadata suitability, not vulnerability truth. A verified commit reference does not prove that a claimed vulnerable function is vulnerable or a claimed fixed version is safe.

Metadata-only recovery before freezing: concatenated older CSV repository fields are split into validated GitHub identities, retaining every recovered identity and the original field hash. When direct abbreviated-revision lookup fails, a unique prefix in already verified same-project commit graphs may identify a candidate, which must then resolve through its full Git commit object. Ambiguity remains unresolved; choosing the first patch parent is prohibited. Both recovery strategies are logged without opening target source.

## Metadata gates, declared before outcomes

1. Confirm the raw metadata hash and each reserve entry's CVE, repository, patch references and function-field digests.
2. Validate CVE syntax, Python language, GitHub repository/reference syntax and local function path/span structure. Keep every input entry in the audit, including failures.
3. Resolve repository aliases and abbreviated revisions where GitHub metadata permits. Pin full SHA/tree/parent identifiers and preserve unresolved references rather than guessing.
4. Record patch references that point outside the declared canonical project. Multiple patches, merge commits, differing function/fix revisions or unchanged snippets require context review; do not invent a unique vulnerable/fixed pair from the first parent.
5. Record declared source locations and snippet digests without publishing snippet bodies. Label correctness, source-to-sink semantics, code reachability, patch completeness and near-duplicate semantic similarity remain pending Step 3/independent review.
6. Record repository license metadata separately. A repository SPDX field is not a full per-file/third-party licensing audit. Unknown licenses do not become permission to redistribute target source.

## Overlap and grouping

Compare CVE IDs and canonical project identities against the pinned PySASTBench real-world metadata, whose identifiers have already been exposed. Treat matching projects conservatively as development-only even though those real-world source archives were not evaluated. Compare exact normalized snippet hashes within the new reserve, and against already inspected PySASTBench synthetic/OWASP Python source units. Normalize line endings, trailing whitespace and common indentation only; do not run a detector or claim semantic clone detection.

Use connected components for shared project identities, shared canonical patch commit references, shared CVEs or matching nonempty snippet hashes. Vulnerable and fixed records for a case stay together. Any overlap-contaminated component is development-only. A component with a metadata-blocked member stays outside the clean final pool until reviewed; preserve all reasons and counts.

Exact snippets can occur in different contexts. These conservative groups prevent exact code copies spanning splits; they do not establish that every grouped case has the same vulnerability. Unchanged or duplicated functions are review flags, not automatic claims that a label is wrong.

## Frozen assignment rule

Seed: `theron-realworld-2026-11-12-v1`.

Among clean metadata-candidate components, assign whole components toward **60% development / 20% validation / 20% test by case count**, sorting descending by component size with seeded SHA-256 tie-breaking, then placing each into the split with the largest remaining count deficit. Never use detector outputs, apparent detectability or desired headline scores to select cases. Record actual project/component counts because large groups can prevent exact proportions.

Other partitions are `development_only` for contamination and `quarantine` for unresolved metadata, with per-case reasons. They are retained but not silently added to or removed from a scored denominator. Clean assignments remain **candidates pending source/label adjudication**, not automatically scorable cases.

Freeze the input/overlap hashes, resolved metadata evidence, policy version, assignments and membership digest before opening development source. Any later correction creates a versioned amendment with reasons; it must not quietly redraw an exposed test set. Final evaluation requires independent label adjudication and declared matching units.

## Step 2 outputs and completion

- Reproducible audit/split script and original miniature tests.
- A metadata-only manifest covering all 70 inputs, with stable groups, partitions, full or unresolved references, exposure/overlap reasons and pending work.
- A concise audit report and an exposure/freeze ledger, with no new detection-accuracy claim.
- Updated roadmap/research links and a documentation/data-preparation checkpoint.

Step 2 does not inspect development patches, fix a detector or score the reserve. Those belong to the next approved step. Network failures, unresolved aliases/revisions, missing paths or uncertain labels remain visible.
