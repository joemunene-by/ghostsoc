# ghostsoc

Autonomous security analyst that drives the [ghostsuite](https://github.com/joemunene-by/ghostsuite)
tools, correlates their findings across tools, and writes one ranked report.

Every ghostsuite tool finds something and emits it into the void. ghostsoc is
the layer that thinks across them: it runs the right scanners for a target,
normalises every tool's output into one findings model, chains findings that
share an asset into attack paths, dedupes, ranks by real exploitability, and
writes a single report a human can act on.

Status: early. The findings model and adapter framework come first, then
correlation, then the reasoning and MCP layers.

## License

MIT
