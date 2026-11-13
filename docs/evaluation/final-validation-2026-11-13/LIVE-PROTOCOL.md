# Additional live transport smoke test

Declared after collecting the final static outcomes, before this smoke run. This is an operational extension, not a new accuracy experiment or a retrospective change to final-test matching.

Run the same frozen detector against public `spideyctf/theron` at `4c166e0b179e1ff10a3a432e2bd439765b601a81`, with all four default modules, real GitHub retrieval and real OSV queries. Record snapshot, modules, file/coverage counts, application/context findings separately, SBOM unresolved versions, wall time, process peak memory and network status/duration metadata. Do not store authentication headers or tokens. Export JSON, HTML and SARIF to the ignored cache. No target application, browser/server, setup script or MCP command executes. Use spideyctf only. Retain failures and incomplete coverage; a single self-scan does not establish accuracy or production capacity.
