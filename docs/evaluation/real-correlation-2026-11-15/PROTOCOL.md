# Registered real-repository correlation pilot

15 November 2026 (Asia/Calcutta). Scanner/UI implementation freeze: `b8ec32f` (tool-path implementation `7b99d5c`). No scanner, collector or attribution changes are made in response to this pilot's source/results. Any subsequent repairs are development work and require a separate reserve.

## Selection before source inspection

1. Query GitHub repository metadata once using `mcp server language:Python stars:>100`, page 1, 30 results. Preserve returned metadata and ordering. If that search fails, retain the error; do not silently replace the population.
2. Normalize repository names and exclude Theron, the Python SDK and FastMCP framework repositories, plus repositories appearing in previous evaluation JSON repository fields. Preserve the exclusion inventory. Renamed aliases are checked against canonical GitHub repository metadata when available; any unresolved overlap remains disclosed.
3. Sort the remaining frame by canonical full repository name. Inspect Git tree metadata for at most the first 12 candidates. Pin each default branch through its Git ref before reading any source. Retain failed probes, truncated trees and missing configurations.
4. Select at most the first five candidates with a Python source file and a configuration filename in Theron's existing MCP allowlist. Limit the collected selection to 150 Python files, ten MCP configuration files, 1.5 MB of Python source in aggregate and 500,000 bytes per input file. Oversized/unsupported candidates remain documented, not silently replaced beyond the registered 12 probes. This is a targeted small-repository compatibility pilot, not a representative or random sample.
5. Collect unchanged eligible Python source, recognized MCP JSON configurations, supported Python manifests and available `.dist-info/METADATA`/`RECORD` files using the existing file/exclusion policy. Do not create client configurations, rewrite launch commands, synthesize package metadata or pin unresolved versions. Verify original Git blob and SHA-256 hashes. Archive raw source only in the ignored cache; publish receipts and redacted/derived evidence.

## Evaluation

Run the frozen SAST/SCA analysis, normalization and correlation on the same collected snapshots. Query public OSV only for the scanner's supported exact declarations; archive raw advisory responses, timestamps and failures. Never install/import target packages or execute declared MCP commands.

Record code-only, dependency-only, code/dependencies without client configuration, and combined input modes. In a separate full on/off check, require identical original findings and vulnerability counts. Report declaration resolution, supported handlers, imported calls, metadata-backed versus spelling-only package links, advisory matches and every unresolved/unsupported/budget outcome. Missing evidence is not safety, and configuration absence in an ablation is not a vulnerability false negative.

Review emitted links against pinned configuration/source locations and available package/advisory evidence. Label observed source facts, supported inferences, contradicted links and unknowns separately. No affected-function, installed environment, runtime dispatch or exploitation is asserted from package/version matching. This is assistant source adjudication; independent human labels and reviewer-decision/time measurements are absent. Do not derive independent accuracy labels from Theron's own output.

Publish selection shortfalls and adverse results. This pilot can reveal actual compatibility/attribution gaps and supported associations. It cannot alone establish a research advantage, independent edge precision, new vulnerabilities or publication readiness.
