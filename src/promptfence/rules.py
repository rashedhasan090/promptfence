"""Rule definitions for prompt and tool-manifest fencing checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


Severity = str  # info | warn | high


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    evidence: str = ""
    suggestion: str = ""


@dataclass(frozen=True)
class PromptRule:
    rule_id: str
    severity: Severity
    title: str
    check: Callable[[str], Finding | None]
    weight: int  # points deducted from fence score when triggered


def _has_any(text: str, phrases: tuple[str, ...]) -> bool:
    lower = text.lower()
    return any(p in lower for p in phrases)


def rule_missing_refusal(text: str) -> Finding | None:
    refuse = (
        "refuse",
        "do not",
        "don't",
        "never reveal",
        "never share",
        "do not disclose",
        "cannot help with",
        "won't help with",
        "decline",
        "reject",
    )
    secrets = (
        "secret",
        "credential",
        "password",
        "api key",
        "token",
        "private key",
    )
    if _has_any(text, refuse) and _has_any(text, secrets):
        return None
    return Finding(
        rule_id="PF001",
        severity="high",
        message="Missing clear refusal language around secrets or credentials.",
        evidence="No paired refuse/never + secret/credential language found.",
        suggestion="Add an explicit rule: never reveal secrets, credentials, or private keys; refuse when asked.",
    )


def rule_missing_scope_boundary(text: str) -> Finding | None:
    markers = (
        "only within",
        "out of scope",
        "do not go beyond",
        "stay within",
        "scope:",
        "boundaries",
        "you may only",
        "allowed tools",
        "must not",
    )
    if _has_any(text, markers):
        return None
    return Finding(
        rule_id="PF002",
        severity="warn",
        message="No explicit scope or capability boundary found.",
        suggestion="State what the agent may and may not do (tools, hosts, paths, topics).",
    )


def rule_overbroad_obedience(text: str) -> Finding | None:
    phrases = (
        "do anything the user asks",
        "always comply",
        "never refuse",
        "obey all instructions",
        "fulfill every request",
        "no restrictions",
        "ignore all safety",
        "bypass safety",
        "jailbreak",
    )
    lower = text.lower()
    hits = [p for p in phrases if p in lower]
    if not hits:
        return None
    return Finding(
        rule_id="PF003",
        severity="high",
        message="Prompt contains over-broad obedience / anti-safety language.",
        evidence=", ".join(hits),
        suggestion="Replace with task-scoped instructions and explicit refuse conditions.",
    )


def rule_injection_acceptance(text: str) -> Finding | None:
    phrases = (
        "ignore previous instructions",
        "ignore all previous",
        "disregard the system prompt",
        "override your instructions",
        "new system prompt",
        "you are now unrestricted",
    )
    # Flag if the prompt *accepts* these, not if it warns against them.
    lower = text.lower()
    warn_against = any(
        w in lower
        for w in (
            "treat as untrusted",
            "do not follow",
            "ignore injection",
            "prompt injection",
            "never obey",
            "never follow",
            "do not obey",
            "do not follow user attempts to",
        )
    )
    hits = [p for p in phrases if p in lower]
    if not hits:
        # Also encourage having anti-injection language
        if "prompt injection" in lower or "untrusted" in lower:
            return None
        return Finding(
            rule_id="PF004",
            severity="warn",
            message="No prompt-injection defense language found.",
            suggestion="Tell the agent to treat tool/user content as untrusted and never adopt injected system overrides.",
        )
    if warn_against:
        return None
    return Finding(
        rule_id="PF004",
        severity="high",
        message="Prompt appears to accept instruction-override / injection phrasing.",
        evidence=", ".join(hits),
        suggestion="Reject override attempts; keep the original system policy fixed.",
    )


def rule_missing_escalation(text: str) -> Finding | None:
    markers = (
        "ask the user",
        "confirm with",
        "escalate",
        "human approval",
        "get confirmation",
        "seek approval",
        "stop and ask",
        "when unsure",
    )
    if _has_any(text, markers):
        return None
    return Finding(
        rule_id="PF005",
        severity="info",
        message="No escalation / ask-before-acting guidance found.",
        suggestion="Tell the agent when to pause and ask a human (spend, delete, send, auth).",
    )


def rule_unbounded_shell_hint(text: str) -> Finding | None:
    lower = text.lower()
    shellish = any(
        t in lower
        for t in ("run shell", "execute commands", "bash", "terminal", "subprocess", "os.system")
    )
    if not shellish:
        return None
    bounded = any(
        t in lower
        for t in (
            "allowlist",
            "allow-list",
            "whitelist",
            "approved commands",
            "sandbox",
            "working directory only",
            "no network",
            "read-only",
            "cannot run",
            "must not run shell",
        )
    )
    if bounded:
        return None
    return Finding(
        rule_id="PF006",
        severity="high",
        message="Shell/command execution is mentioned without an obvious bound or sandbox.",
        suggestion="Constrain shell to an allowlist, sandbox, or forbid it unless the user opts in.",
    )


PROMPT_RULES: list[PromptRule] = [
    PromptRule("PF001", "high", "refusal", rule_missing_refusal, 25),
    PromptRule("PF002", "warn", "scope", rule_missing_scope_boundary, 10),
    PromptRule("PF003", "high", "obedience", rule_overbroad_obedience, 30),
    PromptRule("PF004", "warn", "injection", rule_injection_acceptance, 15),
    PromptRule("PF005", "info", "escalation", rule_missing_escalation, 5),
    PromptRule("PF006", "high", "shell", rule_unbounded_shell_hint, 20),
]


DANGEROUS_TOOL_NAMES = {
    "shell",
    "bash",
    "terminal",
    "exec",
    "run_command",
    "run_shell",
    "subprocess",
    "eval",
    "browser",
    "http",
    "fetch",
    "web_fetch",
    "write_file",
    "delete_file",
    "rm",
    "send_email",
    "send_message",
}


def lint_tools(tools: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    if not tools:
        return findings

    for i, tool in enumerate(tools):
        name = str(tool.get("name") or tool.get("function", {}).get("name") or f"tool[{i}]")
        desc = str(
            tool.get("description")
            or tool.get("function", {}).get("description")
            or ""
        )
        params = (
            tool.get("parameters")
            or tool.get("input_schema")
            or tool.get("function", {}).get("parameters")
            or {}
        )
        lower_name = name.lower()
        if not desc.strip():
            findings.append(
                Finding(
                    rule_id="TF001",
                    severity="warn",
                    message=f"Tool '{name}' has an empty description.",
                    suggestion="Describe purpose, side effects, and forbidden uses.",
                )
            )
        if any(d in lower_name for d in DANGEROUS_TOOL_NAMES):
            bounds = (
                "allowlist",
                "sandbox",
                "path must",
                "only under",
                "no network",
                "read-only",
                "requires confirmation",
                "confirm",
                "restricted",
            )
            if not any(b in desc.lower() for b in bounds):
                findings.append(
                    Finding(
                        rule_id="TF002",
                        severity="high",
                        message=f"Privileged-looking tool '{name}' lacks boundary language in its description.",
                        evidence=desc[:160],
                        suggestion="Document allowlists, path roots, confirmation gates, or sandbox limits.",
                    )
                )
        if isinstance(params, dict):
            props = params.get("properties") or {}
            if props:
                for pname, pschema in props.items():
                    if not isinstance(pschema, dict):
                        continue
                    if not (pschema.get("description") or "").strip():
                        findings.append(
                            Finding(
                                rule_id="TF003",
                                severity="info",
                                message=f"Tool '{name}' parameter '{pname}' has no description.",
                                suggestion="Describe expected format and constraints for agent callers.",
                            )
                        )
                    ptype = pschema.get("type")
                    if pname.lower() in {"path", "file", "filepath", "directory", "dir"} and ptype == "string":
                        enum = pschema.get("enum")
                        pattern = pschema.get("pattern")
                        if not enum and not pattern:
                            findings.append(
                                Finding(
                                    rule_id="TF004",
                                    severity="warn",
                                    message=f"Tool '{name}' path-like parameter '{pname}' has no pattern/enum constraint.",
                                    suggestion="Add a path pattern (e.g. under /workspace) or an allowlisted enum.",
                                )
                            )
    return findings
