# Frozen real-repository correlation pilot

15 November 2026. Implementation `b8ec32f`; selection committed in `8ecedb2` before source collection; protocol/frame registered in `9d8c006`. Scanner code stayed unchanged.

**Three repositories, 126 verified files, seven unresolved configuration declarations and zero correlation groups.** The combined mode has not demonstrated additional correct discoveries or better review decisions here. This adverse result is preserved alongside the successful authored controls.

| Pinned repository | Python / total files | Config declarations | Groups | Observed outcome |
| --- | ---: | ---: | ---: | --- |
| blazickjp/arxiv-mcp-server | 84 / 87 | 2 | 0 | `uvx` package launch; unresolved dependency ranges; one test-source call-analysis budget notice |
| figma/mcp-server-guide | 5 / 9 | 4 | 0 | Three HTTP declarations and one config without a supported direct Python command; no supported dependency declarations parsed |
| GongRzhe/Office-Word-MCP-Server | 27 / 30 | 1 | 0 | Machine-specific absolute interpreter/script paths; ranges and unpinned dependencies |

All original Git blob hashes, lengths and SHA-256 digests verified. Four correlation input projections completed per repository. Full correlation on/off preserved original findings and application vulnerability counts. There were **zero vulnerability candidates**, three unresolved-version notices, one missing-declarations notice and one test-source analysis-budget notice. Zero alerts do not establish safety; MCP arguments were not promoted into taint sources.

The **35 parsed manifest declaration tuples** (25 arxiv, ten Office Word, including optional/test dependencies and duplicate names across manifests) provide **zero supported exact versions**. Therefore **zero OSV requests were made**; the empty archive is not evidence of clean dependencies. No collected distribution records support ownership attribution. Unsupported lock formats and unknown installed environments remain gaps.

## Source adjudication

This is assistant source review, not independent human labelling:

- **Observed:** arxiv's `.mcp.json` and `mcp.json` launch `uvx` with the package name `arxiv-mcp-server`, rather than directly identifying a collected script.
- **Observed:** Figma's `.mcp.json`, `mcp.json` and `figma-power/mcp.json` describe HTTP endpoints. `.antigravity-plugin/mcp_config.json` lacks a supported direct Python command. Collected Python examples do not establish the remote implementation.
- **Observed:** Office Word's `mcp-config.json` points into an author's absolute checkout/virtual-environment paths. The existence or equivalence of that installation is unknown.
- **Supported inference:** resolver refusal agrees with the frozen direct-Python contract. No declaration was converted into a fabricated local tool or installed vulnerable package.
- **Unknown:** runtime launch/dispatch, installed versions, ownership, affected-function reachability, vulnerabilities and reviewer benefit.

There are no emitted relationships to adjudicate: edge precision and false-association rates are undefined. Seven unresolved declarations are compatibility outcomes, not seven vulnerability false negatives. Abstention alone cannot establish correctness. The resolver additionally requires `.vscode/mcp.json` with `servers`; mapping-key acceptance alone would not solve these wrapper, HTTP and absolute-path cases.

## Selection and execution accounting

The registered query returned 30 metadata records. The first-12 probe limit produced three eligible repositories rather than the maximum five: seven lacked eligible configurations and two exceeded the Python file budget. All outcomes remain in `selection.json`. No replacement population was sought. This is a targeted compatibility sample, not a representative population or independently labelled accuracy benchmark.

The original wrapper parse did not resolve the framework alias `jlowin/fastmcp`. A repository-ID redirect audit subsequently identifies `PrefectHQ/fastmcp`; it falls outside the first 12, so the exclusion changes no probes. The original registration and audit amendment remain published. Recorded-name exclusions cannot prove absence of all historical exposure.

The first driver accidentally dropped `module=coverage` during SAST projection, causing arxiv's preservation assertion to fail. `initial-driver-attempt.json` retains this. The driver was repaired to retain coverage notices, then rerun on identical sources and unchanged scanner code. The default host Python lacked `cvss`; the completed run used the existing project `.venv`.

Ablations project the same normalized SAST/SCA findings by module and vary correlation inputs; detection is not independently rerun per projection. Missing configurations yielding no groups is expected by construction, not a recall benefit. No target packages were installed, imported or executed.

## Next development gates

1. Add package-launch contracts for `uvx`/`uv run` and `python -m`, backed by entrypoint metadata and manifest/lock evidence. Do not guess scripts from package spelling.
2. Resolve exact versions from explicitly supported lock schemas such as `uv.lock`, preserving marker/environment ambiguity and provenance; query OSV on resolved versions rather than lower bounds.
3. Broaden client configuration placement with explicit working-directory/path rules. Remote endpoints and absolute environment paths need implementation evidence before local attribution.
4. Retain budget/unknown outcomes. Freeze the revised implementation and register another project-separated reserve before source inspection, with external edge labels and reviewer tasks measuring correct decisions.

These repositories are now development-exposed. Later improvements on them cannot count as fresh confirmation of the contribution.

## Artifacts and reproduction

[Protocol](PROTOCOL.md), [registration](registration.json), [search frame](search-metadata.json), [selection](selection.json), [alias audit](framework-alias-audit.json), [source receipts](source-receipts.json), [results](results.json), [OSV archive](osv-responses.json), [first attempt](initial-driver-attempt.json).

Run `.venv/Scripts/python.exe -m scripts.evaluate_real_correlation` from the repository root with the ignored source cache populated from receipt repository/revision/path tuples. The driver verifies the frozen scanner, original blobs/lengths, complete collection and finding/count preservation. Raw source stays in the ignored cache; published results contain derived evidence. Live advisory results can change on later repetitions; retain this archived run.

This increment changes evaluation tooling and documentation only. The previous **823 Python tests, 19 frontend tests and passing frontend build** remain historical checkpoint checks, not newly rerun results here.
