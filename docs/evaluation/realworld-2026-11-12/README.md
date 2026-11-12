# Frozen real-world metadata preparation

Step 2 checkpoint, 12 November 2026. Start with [AUDIT.md](AUDIT.md), the [protocol](PROTOCOL.md), [manifest](manifest.json) and [freeze ledger](FREEZE.json). This is not a detection evaluation.

| Partition | Cases | Purpose |
| --- | ---: | --- |
| Development | 26 | Source/label audit and subsequent detector development |
| Validation | 9 | Reserved candidates; no detector tuning on their source |
| Test | 9 | Reserved final candidates |
| Development only | 26 | Prior project/CVE metadata exposure; no independent holdout credit |
| Quarantine | 0 | No unresolved metadata components |

All 70 entries remain represented across 48 project components. The cache resolves 100 repository queries and 210 commit-reference queries. Commit resolution does not verify file existence or vulnerability truth. **Zero cases are currently independently adjudicated or scorable.** No target source/patch body was displayed, and no target code, image, exploit or detector was run for this stage.

Pending review includes 17 cases with multiple patch references, 12 with merge/root patch context, and seven with unknown repository license metadata; counts can overlap. Full per-file licensing remains pending for every project.

## Reproduction

Use Python 3.12 and the development environment from the repository README. Input corpora are intentionally excluded from this repository:

- PatchEval-Verified metadata at `b43285cdde80cc04608d5f1178a330b740c91c2d`, raw hash recorded in the manifest.
- PySASTBench at `3ad04b72c516d0533a5dc9c8042c9808e69e0f40`: `RealworldDataset.csv` and previously inspected `SyntheticDataset`.
- OWASP BenchmarkPython at `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`: previously inspected `testcode` and `helpers`.

With these cached at the paths below, reproduce offline from the committed, filtered GitHub metadata:

```powershell
python -m scanner.realworld_audit `
  --reserve docs/evaluation/owasp-2026-11-12/realworld-reserve.json `
  --raw-metadata .benchmark-cache/patcheval-verified-metadata.json `
  --prior-csv .benchmark-cache/PySASTBench/RealworldDataset.csv `
  --github-metadata docs/evaluation/realworld-2026-11-12/github-metadata.json `
  --prior-corpus pysastbench-synthetic=.benchmark-cache/PySASTBench/SyntheticDataset `
  --prior-corpus owasp-testcode=.benchmark-cache/BenchmarkPython/testcode `
  --prior-corpus owasp-helpers=.benchmark-cache/BenchmarkPython/helpers `
  --output-dir docs/evaluation/realworld-2026-11-12 --freeze
```

An identical rebuild reports a match and writes nothing. Changed inputs or altered frozen JSON fail before writing; amendments require a new versioned output directory and reasons. JSON hashes use canonical sorted-key serialization, independent of checkout line endings. Git preserves this checkpoint, including the scripts and protocol.

For a **new metadata snapshot**, first run the preparation command without `--github-metadata`, `--prior-corpus` or `--freeze`, using a new output directory. Fetch its generated query list through an existing `gh` login:

```powershell
python -m scripts.fetch_realworld_metadata --queries NEW_DIRECTORY/queries.json --cache NEW_DIRECTORY/github-metadata.json
```

Then run the complete preparation command against that new cache/output directory. Live metadata can change; it does not replace the frozen evidence. The fetcher allows repository metadata, Git commit objects and one-entry commit listings only. It strips messages, people, source and patch fields before caching. Tokens are not stored. The initial snapshot used the GitHub connector with `gh api` for redirected repositories; both transports produce the same sanitized schema.

Two abbreviated revisions required unique-prefix recovery from already verified same-project commit graphs, followed by full Git-object verification. The evidence keys and full-object endpoint are retained in the cache/manifest. No revision was inferred by choosing a patch's first parent. Thirty-six older CSV rows contained concatenated repository URLs; conservative recovery retained all 62 prior project identities before overlap assignment.

`inputs.json` contains metadata and snippet hashes, `queries.json` the allowlisted retrieval plan, `github-metadata.json` sanitized responses, and `prior-unit-index.json` exact hashes/location identifiers from already inspected corpora. No new target snippets are redistributed. Exact hashing cannot rule out semantic near-duplicates; independently reviewed source/patch labels are required before accuracy claims.
