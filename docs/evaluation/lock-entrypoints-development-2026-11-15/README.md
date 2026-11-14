# Lock inventory and package entrypoint checkpoint

15 November 2026. Implementation `34ce50d`. **859 Python tests, 21 frontend tests and the production frontend build pass.** One existing FastAPI/Starlette dependency deprecation warning remains. No AI service or new runtime dependency is required.

## Supported contracts

The collector/profiler recognize `uv.lock`. SCA reads schema version 1, revisions 0–3. Unique unconditional entries with supported exact versions from the public PyPI registry are eligible for OSV. This is a locked inventory, including optional/development/platform packages, not a selected installed environment.

Multiple variants, package resolution markers, unsupported version spellings and non-PyPI/local sources remain unresolved. Malformed/future schemas produce notices. Exact same-directory manifest pins conflicting with a lock entry generate a notice and block that lock version. Manifest ranges remain visible rather than being silently treated as synchronized. Findings retain lock/source digests and installation/environment/reachability limits; SBOM components retain the inventory basis. Existing OSV pagination, aliases, failures and advisory digests remain supported.

`uv run COMMAND` resolves collected `[project.scripts]` under the supported setuptools build contract and ordinary flat/`src` layout. Disabled project packaging, custom backends/layouts, missing/ambiguous modules, decorated/reassigned/async callables and relevant environment overrides remain unknown.

`uvx PACKAGE==VERSION` and `uvx --from PACKAGE==VERSION COMMAND` require consistent collected `.dist-info/METADATA`, `entry_points.txt` console script and `RECORD` evidence for the exact version and module. These are artifact claims, not authenticated installation/import-path proof. Unpinned external packages remain unknown.

Package client bindings support `.vscode/mcp.json` / `servers` at the workspace root and project `.mcp.json` / `mcpServers` with an inferred project-root binding. Arbitrary working directories/wrapper options, remote HTTP, absolute interpreters, `python -m` and other client semantics remain outside these contracts. No command is executed.

Package resolutions expose callable/source hashes and a metadata relationship in groups. Grouping tools in the entrypoint module does not prove its callable starts them. Correlation adds no vulnerability count or severity. The frontend exposes entrypoint evidence, lock inventory limits and lock provenance; JSON/SARIF/HTML retain evidence.

References: [Python entrypoint specification](https://packaging.python.org/en/latest/specifications/entry-points/), [uv universal resolution](https://docs.astral.sh/uv/concepts/resolution/), [uv metadata and lock format stability](https://docs.astral.sh/uv/reference/internals/metadata/). Future unsupported lock revisions fail visibly.

## Real-source development replay

The **already exposed** Office Word snapshot `a3bbbb6d6167e68cf855d73ef7dc6cd8cfbfedba` was extended with its unchanged original `uv.lock`, Git blob `baa64d413c5a190c8c6dbef30754b59195612c31` (85,820 bytes). All 31 collected blobs/lengths verified. No target code was installed, imported or executed.

| Measurement | Result |
| --- | ---: |
| Lock inventory package rows | 39 |
| Supported exact PyPI inventory versions | 37 |
| Completed unique live OSV queries | **37 / 37** |
| Advisory-group candidate findings | **26 across 10 package names** |
| Resolved MCP configurations / groups | **0 / 0** |
| Correlation preserves original findings | Yes |

Advisory candidates: starlette 7, cryptography 6, mcp 5, anyio 2; one each for certifi, h11, idna, lxml, pygments and python-dotenv. These are locked version/advisory matches, **not 26 validated application vulnerabilities**. Installation, target environment, affected functions and exploitation were not verified. Two unsupported lock rows, manifest ranges and the absolute MCP launch remain limitations.

The original [frozen pilot](../real-correlation-2026-11-15/README.md) stays unchanged: it did not collect this previously unsupported format and made zero OSV queries. This follow-up demonstrates development compatibility/advisory coverage, not a new cross-layer research benefit. These projects are development-exposed; fresh registered evaluation remains required.

## Checks and artifacts

Controls cover exact queries; private/Git sources; markers and variants; malformed/future schemas; conflicting pins and directory boundaries; script/distribution metadata; ambiguous modules and callable changes; unsupported launch overrides. CLI tests cover collection, lock/SBOM delivery and JSON/SARIF/HTML entrypoint evidence. Frontend tests cover hashes/limits and inventory interpretation.

An initial UI assertion matched two copies of a hash and was scoped to the evidence panel. The build caught one non-UTF-8 character introduced while editing; it was repaired and the build passed. Neither failure was a scanner outcome.

[Source receipts](source-receipts.json), [results and SBOM](results.json), [complete OSV query records](osv-records.json). Reproduce with `.venv/Scripts/python.exe -m scripts.evaluate_lock_development`, using the verified ignored blob cache. Live OSV records may change; this archive preserves the checkpoint.

Next: broaden supported contracts with counterexamples, freeze another implementation and evaluate new projects with externally supported edge labels and reviewer tasks. Unseen-project accuracy and publication readiness remain unestablished.
