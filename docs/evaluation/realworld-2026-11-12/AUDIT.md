# Step 2 metadata audit

This is metadata preparation, not a vulnerability-label validation or an accuracy result. No target source/patch bodies were displayed, and no detector or target application was run.

Input: 70 Python CVEs; 48 declared repositories; 48 resolved canonical repositories; 48 connected groups.

| Partition | Cases | Groups | Role |
| --- | ---: | ---: | --- |
| development | 26 | 20 | Eligible for subsequent development-source audit |
| validation | 9 | 9 | Reserved, labels still pending |
| test | 9 | 9 | Reserved final candidates, labels still pending |
| development_only | 26 | 10 | Prior exposure/overlap; no independent holdout credit |
| quarantine | 0 | 0 | Blocked metadata component; retained for review |

**Scorable cases: 0.** All labels require source/patch and independent adjudication before scoring. Do not treat fixed snippets as clean negatives.

## Metadata blockers

No direct metadata blockers were found; semantic label and file-availability checks remain pending.

## Prior exposure and data quality

- `prior_project_or_fork_root_metadata_exposed`: 26 cases directly match; component membership can extend the development-only restriction.
- `prior_cve_metadata_exposed`: 8 cases directly match; component membership can extend the development-only restriction.
- 36 older CSV rows contained recoverable concatenated repository URLs. Each recovery is recorded with its field hash; 62 prior project identities were considered.
- Project aliases/fork roots and shared patch/snippet identities are grouped conservatively. Exact hashes are not semantic near-duplicate detection.

## Pending review flags

- `multiple_patch_references_require_context_review`: 17 cases.
- `patch_merge_or_root_requires_revision_review`: 12 cases.
- `repository_license_requires_review`: 7 cases.

## Freeze and remaining gates

Membership SHA-256: `875e8e2b4938dfbdb7a6dab6d624f12a2a28d4029741892fefcf260d391c1367`.

Unresolved older project identities: 0; unrecoverable prior project fields: 0; earlier corpus unit-parse failures: 0.
File existence at the declared revisions, function spans, vulnerability semantics, fix completeness, per-file licensing and semantic near-duplicates remain unverified.
Any later correction must preserve this snapshot and document a versioned amendment; do not silently redraw an exposed holdout.

Next step: inspect only the development partition for source/patch label audit. Reserved source remains closed to detector tuning. No detection improvement is claimed by this preparation step.
