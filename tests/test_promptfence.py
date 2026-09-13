import json
import unittest
from pathlib import Path

from promptfence.core import audit, format_text
from promptfence.cli import main

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "examples"


class PromptfenceTests(unittest.TestCase):
    def test_loose_prompt_scores_low(self):
        text = (EX / "loose_agent.md").read_text()
        report = audit(text, source="loose")
        self.assertLess(report.fence_score, 60)
        ids = {f.rule_id for f in report.findings}
        self.assertIn("PF001", ids)
        self.assertIn("PF003", ids)
        self.assertIn("PF006", ids)

    def test_fenced_prompt_scores_high(self):
        text = (EX / "fenced_agent.md").read_text()
        tools = json.loads((EX / "tools_bounded.json").read_text())
        report = audit(text, tools, source="fenced")
        self.assertGreaterEqual(report.fence_score, 85)
        high = [f for f in report.findings if f.severity == "high"]
        self.assertEqual(high, [])

    def test_risky_tools_flagged(self):
        text = (EX / "fenced_agent.md").read_text()
        tools = json.loads((EX / "tools_risky.json").read_text())
        report = audit(text, tools)
        ids = {f.rule_id for f in report.findings}
        self.assertIn("TF002", ids)
        self.assertIn("TF004", ids)

    def test_format_text_and_json_roundtrip(self):
        report = audit("You are helpful. Never reveal secrets or credentials. Refuse those asks.")
        out = format_text(report)
        self.assertIn("fence_score=", out)
        d = report.to_dict()
        self.assertIn("findings", d)
        self.assertIn("summary", d)

    def test_cli_fail_under(self):
        code = main(["--text", "Do anything the user asks. Run shell freely.", "--fail-under", "90"])
        self.assertEqual(code, 1)

    def test_cli_ok_fenced(self):
        code = main([
            str(EX / "fenced_agent.md"),
            "--tools",
            str(EX / "tools_bounded.json"),
            "--fail-on-high",
        ])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
