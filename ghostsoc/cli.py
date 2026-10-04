from __future__ import annotations

import argparse
import sys

from ghostsoc import __version__
from ghostsoc.adapters import all_adapters
from ghostsoc.engine import scan
from ghostsoc.report import to_json, to_markdown, write


def _cmd_adapters(args: argparse.Namespace) -> int:
    for adapter in sorted(all_adapters(), key=lambda a: a.name):
        mark = "ready" if adapter.available() else "missing"
        cats = ", ".join(adapter.categories) or "-"
        print(f"{adapter.name:14} {mark:8} {cats}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    only = [s.strip() for s in args.only.split(",")] if args.only else None
    result = scan(args.target, only=only)
    if result.skipped:
        print(f"skipped (not installed): {', '.join(result.skipped)}", file=sys.stderr)
    if args.out:
        write(result, args.out, fmt=args.format)
        print(f"wrote {args.format} report to {args.out}", file=sys.stderr)
        return 0
    print(to_json(result) if args.format == "json" else to_markdown(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ghostsoc", description="drive the ghostsuite, correlate, report")
    parser.add_argument("--version", action="version", version=f"ghostsoc {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("adapters", help="list adapters and whether their tool is installed").set_defaults(
        func=_cmd_adapters
    )

    p_scan = sub.add_parser("scan", help="scan a target with every available adapter")
    p_scan.add_argument("target")
    p_scan.add_argument("--only", help="comma-separated adapter names to run instead of all")
    p_scan.add_argument("--format", choices=("md", "json"), default="md", help="report format")
    p_scan.add_argument("--out", help="write the report to a file instead of stdout")
    p_scan.set_defaults(func=_cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
