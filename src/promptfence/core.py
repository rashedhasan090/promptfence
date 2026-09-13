"""Core audit logic for promptfence."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .rules import PROMPT_RULES, Finding, lint_tools


@dataclass
class Report:
    fence_score: int
    findings: list[Finding] = field(default_factory=list)
    prompt_bytes: int = 0
    tool_count: int = 0
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fence_score": self.fence_score,
            "prompt_bytes": self.prompt_bytes,
            "tool_count": self.tool_count,
            "source": self.source,
            "findings": [asdict(f) for f in self.findings],
            "summary": {
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "warn": sum(1 for f in self.findings if f.severity == "warn"),
                "info": sum(1 for f in self.findings if f.severity == "info"),
            },
        }


def _score(findings: list[Finding]) -> int:
    # Deduct by rule weight; clamp 0..100. High findings also floor the score.
    weights = {r.rule_id: r.weight for r in PROMPT_RULES}
    # Tool findings weights
    tool_weights = {"TF001": 5, "TF002": 20, "TF003": 2, "TF004": 8}
    score = 100
    seen: set[str] = set()
    for f in findings:
        if f.rule_id in seen:
            # repeat tool findings cost less after the first of that id
            score -= max(1, (tool_weights.get(f.rule_id) or weights.get(f.rule_id, 5)) // 3)
        else:
            score -= weights.get(f.rule_id, tool_weights.get(f.rule_id, 5))
            seen.add(f.rule_id)
    high = sum(1 for f in findings if f.severity == "high")
    if high >= 3:
        score = min(score, 40)
    elif high == 2:
        score = min(score, 55)
    elif high == 1:
        score = min(score, 75)
    return max(0, min(100, score))


def load_prompt(path: Path | None, text: str | None) -> str:
    if text is not None:
        return text
    if path is None:
        raise ValueError("Provide a prompt path or --text")
    return path.read_text(encoding="utf-8")


def load_tools(path: Path | None) -> list[dict]:
    if path is None:
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        if "tools" in raw and isinstance(raw["tools"], list):
            return raw["tools"]
        if "functions" in raw and isinstance(raw["functions"], list):
            return raw["functions"]
        # single tool object
        return [raw]
    if isinstance(raw, list):
        return raw
    raise ValueError("tools file must be a JSON list or an object with tools/functions")


def audit(prompt: str, tools: list[dict] | None = None, source: str = "") -> Report:
    findings: list[Finding] = []
    for rule in PROMPT_RULES:
        hit = rule.check(prompt)
        if hit is not None:
            findings.append(hit)
    tool_list = tools or []
    findings.extend(lint_tools(tool_list))
    return Report(
        fence_score=_score(findings),
        findings=findings,
        prompt_bytes=len(prompt.encode("utf-8")),
        tool_count=len(tool_list),
        source=source,
    )


def format_text(report: Report) -> str:
    lines = [
        f"promptfence report — fence_score={report.fence_score}/100",
        f"source: {report.source or '(stdin/text)'}",
        f"prompt_bytes={report.prompt_bytes}  tools={report.tool_count}",
        f"findings: high={sum(1 for f in report.findings if f.severity=='high')} "
        f"warn={sum(1 for f in report.findings if f.severity=='warn')} "
        f"info={sum(1 for f in report.findings if f.severity=='info')}",
        "",
    ]
    if not report.findings:
        lines.append("No fence gaps detected by the current rule pack.")
        return "\n".join(lines) + "\n"
    for f in report.findings:
        lines.append(f"[{f.severity.upper()}] {f.rule_id}: {f.message}")
        if f.evidence:
            lines.append(f"  evidence: {f.evidence}")
        if f.suggestion:
            lines.append(f"  fix: {f.suggestion}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
