# Application evidence and MCP source bindings

15 November 2026. Core implementation `71e6c88`, followed by frontend evidence tests and replay provenance updates. **882 Python tests, 23 frontend tests and production build pass.** One existing FastAPI/Starlette dependency deprecation warning remains.

## Advisory review: what was actually checked

All 26 archived Office Word lock-inventory advisory candidates were replayed against the same 31 verified inputs, including 27 Python files. The advisory archive was reused without new network queries. Source parsing completed for all 27 files, with no syntax failures or file-limit truncation. Candidate fingerprints/counts and correlation finding payloads were preserved.

| Source observation | Advisory candidates |
| --- | ---: |
| Direct package API calls observed in application source | **7** |
| No direct package usage observed | **19** |
| Affected behavior confirmed by this replay | **0** |
| Application vulnerabilities confirmed by this replay | **0** |

The seven are one lxml, five MCP SDK and one python-dotenv advisory matches. They are not seven validated vulnerabilities:

- The lxml source observations contain 47 syntactic calls, including XML construction/serialization and `fromstring`. The archived advisory concerns default behavior of `iterparse` and `ETCompatXMLParser`; those APIs were not observed among the direct calls. Transitive parser use remains unknown.
- The five MCP SDK matches share 54 observed `ToolAnnotations` constructor calls. Those constructors do not demonstrate affected transport/request processing. The application also contains configurable stdio, SSE and streamable-HTTP launch paths through FastMCP. The effective transport, SDK behavior, authentication/session/security configuration and installed versions were not verified.
- The python-dotenv observation is `load_dotenv`. Its archived advisory concerns environment-file writer APIs `set_key`/`unset_key` under additional filesystem conditions. That affected operation was not observed directly.
- The other 19 remain unresolved for application applicability. Missing direct imports/calls cannot exclude transitive dependencies, dynamic dispatch or other deployments, so they are not labelled false positives or removed.

[Per-candidate condition review](condition-review.json) retains all 26 identities, required behavior, source interpretation and next validation. This is assistant source/advisory assessment, not independent labels. [Machine-readable observations](results.json) include imports/calls, locations/scopes, hashes, coverage and explicit unverified flags. Source/advisory archive digests bind the replay inputs.

The production SCA path now attaches these bounded source observations to dependency findings. It supports unique collected distribution-record claims, explicit common import-name contracts and weaker same-name candidates. Local module shadowing and observed binding replacement prevent confident API attribution. Examples/tests remain separate from application usage. Calls are syntactic observations, including potentially unreachable branches; they do not establish affected-function use. The frontend displays the status, locations, limits and full evidence. Severity/counts are unchanged by this interpretation pass.

## HTTP and absolute-path launches

Theron now accepts explicit implementation mappings through local `theron.yml` or the scan API's `mcp_bindings` list. Each requires the exact configuration pointer, repository-relative Python implementation, configuration/source SHA256 digests, launch kind and a reason. Only the supplied collected files are inspected; endpoints are not contacted and commands are not executed.

Valid mappings produce **`source_bound`**, not verified runtime identity. Missing sources, digest changes, mismatched launch kinds and disabled declarations remain unresolved. HTTP endpoints may refer to implementations outside the repository; an explicit mapping is a supplied claim, not proof that a deployed server uses that code. Absolute-path mapping does not prove that the original machine or virtual environment matches the collected snapshot.

The exposed Office Word absolute launch was mapped to its same-named collected `word_mcp_server.py` by an explicit assistant source-review claim. The declaration is now `source_bound`, but still generates **zero tool groups**: the thin entry script delegates to imported setup and nested tool registration beyond the present registration contract. No detector/source was changed to manufacture groups. The original frozen pilot and its seven unresolved declarations remain unchanged historical evidence. Figma's remote service has not been assigned an invented local implementation.

Example mapping structure (replace placeholders with text digests from the files actually collected):

```yaml
mcp_bindings:
  - config_file: mcp-config.json
    pointer: /mcpServers/word-document-server
    kind: absolute-python
    entrypoint: word_mcp_server.py
    config_sha256: <64 lowercase hexadecimal characters>
    entrypoint_sha256: <64 lowercase hexadecimal characters>
    reason: Explain the evidence supporting this implementation mapping.
```

Use `kind: http` for an explicitly mapped HTTP/SSE declaration. The same required fields apply. Hashes cover scanner input **text encoded as UTF-8**, not necessarily the original byte representation: account for the collector's newline/decoding behavior. For a local scan, compute from `Path(path).read_text(encoding='utf-8', errors='replace').encode('utf-8')`. Validate against the report's source-text provenance. Duplicate mappings and invalid paths/schema are rejected in config/API validation.

## Unpinned external packages

An unpinned `uvx PACKAGE` can produce a **`candidate`** only when a unique consistent version/entrypoint is supported by collected distribution metadata and file records. It retains the collected candidate version, ownership basis, hashes and a warning that launch-time selection can differ. Conflicting versions or absent metadata remain unknown. Theron does not query an index and pretend its current latest release is the installed version, and does not pin or rewrite the user's launch.

Original controls verify the candidate case and version conflicts. This does not newly resolve arxiv's real declaration: that snapshot lacks the required distribution metadata. HTTP and absolute bindings also have positive/negative controls, including disabled declarations, stale hashes, traversal, Windows paths, invalid API requests and CLI delivery. Frontend checks distinguish candidates, explicit bindings and runtime verification.

## Remaining validation

This increment performs source-level applicability review and introduces explicit evidence paths for difficult launches. It does **not** complete deployed application or protocol verification. The next steps are a matching isolated environment, effective transport/authentication/version evidence, transitive affected-API tracing and focused affected/repaired functional checks. A fresh registered project reserve and independent relationship/reviewer evaluation remain necessary for a research benefit claim. No broad publication-readiness claim follows from this checkpoint.

Reproduce with `.venv/Scripts/python.exe -m scripts.evaluate_application_context`, using the previous verified ignored blob cache and archived OSV records. No target package is imported/executed and no endpoint is contacted. Historical results remain intact.
