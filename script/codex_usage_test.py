import json
import unittest
from unittest import mock

from script.codex_usage import CodexUsageTracker


class CodexUsageTrackerTest(unittest.TestCase):
    def test_parse_tui_output_parses_cached_input_summary(self) -> None:
        tracker = CodexUsageTracker()

        output = "Tokens: 12,345 input, 6,789 cached input, 4,567 output\nCost: $0.1234\n"

        usage = tracker.parse_tui_output(output, model="gpt-5.4-medium")

        self.assertEqual(
            usage,
            {
                "input_tokens": 12345,
                "cached_input_tokens": 6789,
                "output_tokens": 4567,
                "cost": 0.1234,
            },
        )

    def test_parse_tui_output_does_not_crash_on_cached_input_label(self) -> None:
        tracker = CodexUsageTracker()

        output = "cached input, 4,567 output\n"

        usage = tracker.parse_tui_output(output, model="gpt-5.4-medium")

        self.assertEqual(
            usage,
            {
                "input_tokens": 0,
                "cached_input_tokens": 0,
                "output_tokens": 0,
                "cost": 0.0,
            },
        )

    def test_parse_reads_opencode_step_finish_events(self) -> None:
        tracker = CodexUsageTracker()

        output = "\n".join([
            json.dumps({"type": "step_start", "part": {"type": "step-start"}}),
            json.dumps({"type": "step_finish", "part": {
                "type": "step-finish",
                "tokens": {"input": 15763, "output": 226, "reasoning": 40,
                           "cache": {"write": 0, "read": 1200}},
                "cost": 0.00252405,
            }}),
            json.dumps({"type": "step_finish", "part": {
                "type": "step-finish",
                "tokens": {"input": 100, "output": 10, "reasoning": 0,
                           "cache": {"write": 0, "read": 0}},
                "cost": 0.001,
            }}),
        ])

        usage = tracker.parse(output, model="opencode-go/deepseek-v4.1-flash")

        self.assertEqual(usage["input_tokens"], 15863)
        self.assertEqual(usage["cached_input_tokens"], 1200)
        # reasoning tokens bill as output: 226 + 40 + 10
        self.assertEqual(usage["output_tokens"], 276)
        # provider-reported cost wins over the Codex pricing table
        self.assertAlmostEqual(usage["cost"], 0.00352405)
        self.assertAlmostEqual(tracker.cost, 0.00352405)

    def test_parse_tui_output_ignores_dollar_amount_in_hexdump(self) -> None:
        """A bare "$<number>" in agent output is not a cost.

        Regression: the ASCII column of an `xxd` dump of a binary testcase
        contained "$34633", which booked one bug at $34,633.
        """
        tracker = CodexUsageTracker()

        output = (
            "0000272 39 32 30 39 33 38 34 36 24 33 34 36 33 33  "
            ">6692093846$34633<\n"
        )

        usage = tracker.parse_tui_output(output, model="gpt-5.4-medium")

        self.assertEqual(usage["cost"], 0.0)
        self.assertEqual(tracker.cost, 0.0)

    def test_parse_tui_output_does_not_bank_cost_without_tokens(self) -> None:
        tracker = CodexUsageTracker()

        tracker.parse_tui_output("Cost: $12.34\n", model="gpt-5.4-medium")

        self.assertEqual(tracker.cost, 0.0)

    def test_log_usage_swallows_parser_failures(self) -> None:
        tracker = CodexUsageTracker()

        with mock.patch.object(
            tracker,
            "parse_tui_output",
            side_effect=RuntimeError("boom"),
        ):
            tracker.log_usage("transplant", "not jsonl")

        self.assertEqual(tracker.input_tokens, 0)
        self.assertEqual(tracker.cached_input_tokens, 0)
        self.assertEqual(tracker.output_tokens, 0)
        self.assertEqual(tracker.cost, 0.0)


if __name__ == "__main__":
    unittest.main()
