"""CLI entrypoint for promptfence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import audit, format_text, load_prompt, load_tools


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="promptfence",
        description=(
            "Offline defensive linter for agent system prompts and tool manifests. "
            "Scores fence gaps: missing refusal language, over-broad obedience, "
            "injection weakness, unbounded shell hints, and privileged tools without bounds."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "prompt",
        nargs="?",
        type=Path,
        help="Path to a system prompt / agent instruction file (txt/md).",
    )
    p.add_argument(
        "--text",
        help="Audit this prompt string instead of a file.",
    )
    p.add_argument(
        "--tools",
        type=Path,
        help="Optional JSON tool manifest (OpenAI/Anthropic-ish list or {tools:[...]}).",
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="N",
        help="Exit 1 if fence_score is strictly below N (useful in CI).",
    )
    p.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit 1 if any high-severity finding is present.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        prompt = load_prompt(args.prompt, args.text)
        tools = load_tools(args.tools)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"promptfence: {exc}", file=sys.stderr)
        return 2

    source = str(args.prompt) if args.prompt else ("--text" if args.text is not None else "")
    report = audit(prompt, tools, source=source)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(format_text(report))

    if args.fail_on_high and any(f.severity == "high" for f in report.findings):
        return 1
    if args.fail_under is not None and report.fence_score < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
