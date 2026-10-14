# ghostsoc

Autonomous security analyst that drives the [ghostsuite](https://github.com/joemunene-by/ghostsuite)
tools, correlates their findings across tools, and writes one ranked report.

Every ghostsuite tool finds something and emits it into the void. ghostsoc is the
layer that thinks across them. It runs the right scanners for a target, normalises
every tool's output into one findings model, chains findings that share an asset
into attack paths, lifts the severity of chains that genuinely escalate, and writes
a single report a human or an agent can act on.

## How it works

```
adapters        normalise       correlate                 reason        report
ghostrecon  ->  Finding    ->   dedupe by fingerprint  -> triage per -> md / json
ghostdlp        objects         chain by shared asset     chain          / html
ghostmap                        lift escalating chains    (GhostLM or
(any SARIF tool)                                           fallback)
```

The one idea that makes this more than a wrapper: **correlation**. A leaked
credential is a High on its own. A leaked credential on a host a recon pass already
flagged as a reachable service is a different animal, the key unlocks something you
can get to. When findings on one asset span two of *exposure*, *secret* and *vuln*,
ghostsoc raises the chain a severity band and says why.

## Install

```
pip install -e .          # core, no third-party deps
pip install -e .[mcp]     # add the MCP server
pip install -e .[dev]     # tests and lint
```

ghostsoc shells out to the ghostsuite tools. It only runs the ones it finds on your
PATH and quietly skips the rest, so a partial install still produces a report.

## Use

```
ghostsoc adapters                      # what is wired in and what is installed
ghostsoc scan api.example.com          # markdown report to stdout
ghostsoc scan ./repo --format json     # json for a pipeline
ghostsoc scan api.example.com --format html --out report.html
ghostsoc scan api.example.com --only ghostrecon,ghostdlp
```

### Adapters

| adapter    | tool       | input      | categories             | output |
|------------|------------|------------|------------------------|--------|
| ghostrecon | ghostrecon | host       | recon, attack-surface  | json   |
| ghostdlp   | ghostdlp   | path, host | data-leak, secrets     | json   |
| ghostmap   | ghostmap   | url        | web, dast              | sarif  |
| *any*      | *any*      | *varies*   | *sast, dast, ...*      | sarif  |

Any suite tool that emits SARIF 2.1.0 plugs in as a four-line `SarifAdapter`
subclass. More first-class adapters (ghostsbom, ghostcloud, ghostchain) are next.

## A worked example

Two tools, two findings, one host:

```
ghostrecon: open service on api.example.com:8080   (MEDIUM, attack-surface)
ghostdlp:   leaked database credential             (HIGH,   data-leak)
```

Report:

```
## 1. api.example.com

**CRITICAL** · ghostdlp, ghostrecon

ghostrecon found exposed service and ghostdlp found leaked database credential on the same asset.

> A leaked secret sits on an asset that is reachable from outside. Treat it as an
> active foothold: rotate the credential and close the exposure before anything else.

- **HIGH** ghostdlp: leaked database credential
- **MEDIUM** ghostrecon: exposed service
```

Neither tool would have told you this on its own.

## Drive it from an agent

```
ghostsoc-mcp
```

Exposes `scan_target(target, only=None)` and `list_adapters()` over MCP. Point
GhostLM, Claude, or any MCP client at it and the agent runs the suite and reads
back correlated chains with a triage note on each.

## Layout

```
ghostsoc/
  findings.py     the one Finding shape every adapter normalises into
  adapters/       one module per tool, plus generic SARIF ingest
  correlate.py    dedupe by fingerprint, chain by shared asset, lift escalations
  reason.py       GhostLM triage note per chain, heuristic fallback offline
  engine.py       select adapters, run in parallel, correlate, isolate failures
  report.py       markdown, json and html renderers
  cli.py          ghostsoc scan / adapters
  mcp_server.py   the MCP surface
```

## Status

Early. Core pipeline (adapters, correlation, reasoning, reports, CLI, MCP) works.
Next: more first-class adapters, a YAML policy gate reusing secure-mcp, and a
coverage view once ghostrange lands. See the roadmap in the issues.

## License

MIT
