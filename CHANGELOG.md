# Changelog

## Unreleased

### Added
- Normalised `Finding` model with a stable fingerprint shared by every adapter.
- Adapter framework with availability checks, a JSON subprocess runner and a registry.
- Adapters: ghostrecon, ghostdlp, and generic SARIF ingest (ghostmap first).
- Correlation: dedupe by fingerprint, chain by shared asset, lift escalating chains.
- GhostLM triage note per chain with a heuristic fallback when the model is offline.
- Engine that selects available adapters, runs them in parallel and isolates failures.
- Markdown, JSON and HTML reports.
- CLI (`ghostsoc scan`, `ghostsoc adapters`) and an MCP server (`ghostsoc-mcp`).
