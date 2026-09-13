# promptfence

**Offline defensive linter for agent system prompts and tool manifests.**

`promptfence` scores how well an agent instruction file is *fenced*: refusal
language around secrets, scope boundaries, prompt-injection resistance,
escalation cues, and whether privileged tools declare real limits.

It is **not** a red-team exploit kit and does **not** generate jailbreaks. It only
flags missing defensive language and unbounded tool descriptions so you can
harden agents before you ship them.

## Why it is novel

Most prompt "linters" chase style or token count. Daily tools already on this
account cover diffs (`diffintent`), secret masking (`hushdiff`), execution
surface maps (`rippleguard`), and auth graphs (`aegispath`). `promptfence` sits
in a different niche: a portable **fence score** for the *policy text + tool
schema* pair that actually steers an LLM agent, with CI-friendly exit codes.

## Install

Requires Python 3.10+.

```sh
python -m pip install "git+https://github.com/rashedhasan090/promptfence.git"
promptfence --version
```

Or from a checkout:

```sh
python -m pip install -e .
```

## Quick demo

```sh
# Loose agent + unbounded shell tool -> low fence score
promptfence examples/loose_agent.md --tools examples/tools_risky.json

# Scoped agent + bounded read tool -> high fence score
promptfence examples/fenced_agent.md --tools examples/tools_bounded.json --fail-under 80

# JSON for scripts / CI
promptfence examples/loose_agent.md --format json --fail-on-high
```

Example loose output (abbreviated):

```text
promptfence report - fence_score=20/100
[HIGH] PF001: Missing clear refusal language around secrets or credentials.
[HIGH] PF003: Prompt contains over-broad obedience / anti-safety language.
[HIGH] PF006: Shell/command execution is mentioned without an obvious bound or sandbox.
[HIGH] TF002: Privileged-looking tool 'run_shell' lacks boundary language in its description.
```

## Rules (v0.1)

| ID | Severity | Checks |
| --- | --- | --- |
| PF001 | high | Refusal language around secrets/credentials |
| PF002 | warn | Explicit scope / capability boundary |
| PF003 | high | Over-broad obedience / anti-safety phrasing |
| PF004 | warn/high | Prompt-injection defense (or acceptance) |
| PF005 | info | Escalation / ask-before-acting guidance |
| PF006 | high | Shell/exec mentions without sandbox/allowlist |
| TF001-TF004 | info-high | Empty tool/param descriptions; privileged tools without bounds; unconstrained path params |

## CLI

```text
promptfence [PROMPT_FILE] [--text STR] [--tools MANIFEST.json]
            [--format text|json] [--fail-under N] [--fail-on-high]
```

Exit codes: `0` ok, `1` failed threshold / high finding, `2` usage/IO error.

## Tests

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

## License

MIT (c) 2026 Rashed Hasan
