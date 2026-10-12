"""Expose ghostsoc over MCP so an agent can drive the suite and read the result.

This is the "autonomous analyst" surface: an agent calls scan with a target, gets
back correlated chains with a triage note on each, and decides what to do. The
heavy lifting still lives in engine and correlate; this is a thin shell over them.

Run: ghostsoc-mcp  (needs the mcp extra: pip install ghostsoc[mcp])
"""

from __future__ import annotations

from ghostsoc.adapters import all_adapters
from ghostsoc.engine import scan


def build_server():
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("ghostsoc")

    @server.tool()
    def list_adapters() -> list[dict]:
        """List the ghostsuite adapters and whether each tool is installed."""
        return [
            {"name": a.name, "categories": list(a.categories), "available": a.available()}
            for a in all_adapters()
        ]

    @server.tool()
    def scan_target(target: str, only: list[str] | None = None) -> dict:
        """Run the available adapters against a target, correlate, and return ranked chains.

        target: a host, url or path, depending on which adapters apply.
        only: optional list of adapter names to run instead of all.
        """
        return scan(target, only=only).to_dict()

    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
