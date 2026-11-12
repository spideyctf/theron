# Step 4: MCP configuration-to-code correlation pilot

13 November 2026. Starting checkpoint: `0756ce361ab611729ca7f9c06d15cd1c27a906f0`. Implements B03 from the [platform contract](../../PLATFORM.md). Step 3's independent-label and runtime-context requirements remain open. The application was not started and reserved source was not opened.

## Supported claim and boundary

**A collected configuration declares a local Python entrypoint, and that file contains an existing supported static flow finding.** This experimental association does not establish client acceptance, startup/callback reachability, network exposure, authentication, effective privileges or exploitability. Groups add no findings, vulnerability counts, combined severity or confidence boost.

The resolver supports VS Code editor-managed `.vscode/mcp.json` with a `servers` object, explicit `type: "stdio"`, a bare `python`/`python3`/`python3.N` name (including `.exe` variants), optional `-u`/`-B`, and a direct `.py` argument. Workspace binding is inferred from the directory containing `.vscode`, using the documented default or a `${workspaceFolder}`-anchored cwd/path. Runtime binding remains unverified. [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration#standard-io-stdio-servers).

Other recognized MCP filenames/maps remain inspectable with unresolved client semantics. A project variable available inside a spawned Claude server is not necessarily expanded in launcher arguments; this pilot does not guess. [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp#option-3-add-a-local-stdio-server).

Wrappers/shells, module/inline execution, remote or explicitly disabled declarations, missing stdio type, dynamic/absolute/outside paths, case collisions, unavailable targets and malformed/duplicate-key JSON retain reasons. JSONC, YAML, arbitrary environment expansion, absolute interpreter paths and cross-file sinks are unsupported. A resolved declaration without an eligible finding is not labelled safe.

## Evidence and integration

Additive report fields preserve the current findings and summary:

- `correlation_enabled`: whether the pass ran.
- `correlation_resolutions`: config file, JSON pointer, candidate file, scope, state/classification/reason and group references.
- `correlation_groups`: report-local IDs, original finding fingerprints, scope, maturity, relationships and limitations. Relationships retain endpoints, supporting locations and observed/inferred classification. Flow edges preserve original confidence/maturity and source/sink evidence.

Only supported static-flow rule IDs with collected, valid source/sink locations qualify. The sink must be in the exact resolved entrypoint. Unrelated files, notices, pattern-only results and malformed/unavailable traces cannot support an edge. Test/example provenance remains contextual; multiple declarations referring to one finding do not increase its vulnerability count.

The pass follows normalization/partitioning in local and GitHub scans. Collection makes a narrow exception for `.vscode/mcp.json`; other editor files and explicit excludes remain filtered. Local symlinks/outside-root files and GitHub symlink blobs are not treated as target code. No command, scanned module or credential is executed/authenticated. Raw environment values and unrelated launcher arguments are omitted from correlation metadata.

JSON, HTML, SARIF run properties, terminal output and web API exports carry the same metadata. The **MCP links** frontend tab displays groups, referenced findings, source/sink links, classifications, scopes, limitations and every resolution outcome. Complete evidence remains inspectable; older and disabled reports have distinct explanations. A backend-generated shared fixture tests frontend agreement.

## Original controls and ablation

[Nine original controls](original-controls.json) retain input hashes, expected/actual groups, reasons and same-input disabled comparisons. [Example report](example-report.json) is an original unit fixture: repository identity and commit are placeholders, not a real GitHub result.

| Control | Enabled groups | Disabled groups | Outcome |
| --- | ---: | ---: | --- |
| Direct Python + supported flow | 1 | 0 | Config pointer → exact file → original finding/trace |
| Safe entrypoint | 0 | 0 | Resolved; no eligible flow evidence |
| Unrelated unsafe file | 0 | 0 | Original finding retained without fabricated relationship |
| Missing target | 0 | 0 | Unresolved |
| Wrapper | 0 | 0 | Unsupported |
| Ambiguous cwd | 0 | 0 | Unresolved |
| Unknown client's config | 0 | 0 | Explicit unknown |
| Case-colliding paths | 0 | 0 | Ambiguous |
| Example entrypoint | 1, example scope | 0 | Context finding; zero application vulnerabilities |

Every comparison retains identical original findings, context findings and summary counts. This validates the mechanism and count separation, **not independent real-code edge accuracy, detection recall or triage benefit**. Step 3's tuning metrics remain unchanged; no real-world holdout was evaluated here.

Verification: **417 Python tests**, **11 frontend tests**, TypeScript/production build and offline URL controls pass. The 53 correlation tests cover collectors, CLI/GitHub/API paths, no execution, unresolved cases, exports, privacy, scope, uncertainty and disabling the pass. Three frontend tests render the shared backend report and exercise evidence, source links, old/disabled/unresolved states, the live-report tab and original finding inspection.

## Reproduction

Supported declaration in `.vscode/mcp.json`:

```json
{"servers":{"local":{"type":"stdio","command":"python","args":["${workspaceFolder}/server.py"]}}}
```

Scanning reads this as text; it does not launch the declaration. Actual client acceptance/operation needs separate review.

```powershell
python -m pytest tests/test_correlation.py -q -p no:cacheprovider
python -m pytest tests -q -p no:cacheprovider
cd frontend
npm test
npm run build
```

Disable via CLI `--no-correlation`, `correlation_enabled: false` in `theron.yml`, or API scan input `"correlation_enabled": false`. Original findings and severity thresholds remain unchanged. No running application is required for these checks.

Step 4's engineering pilot is complete. Step 5 still requires applicable baselines, declared matching/adjudication and evaluation of claimed incremental benefit. This checkpoint does not establish paper readiness.
