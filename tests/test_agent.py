from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from firebreak.agent import AgentConfig, run_agent, run_agent_command
from firebreak.cli import parser
from firebreak.errors import ProtocolError


class AgentTests(unittest.TestCase):
    def test_cli_keeps_agent_options_before_adapter_command(self):
        args = parser().parse_args(
            [
                "agent",
                "--base-url",
                "https://technocore.example",
                "--rounds",
                "2",
                "lobby",
                "--adapter",
                "python",
                "-m",
                "my_adapter",
            ]
        )
        self.assertEqual(args.room, "lobby")
        self.assertEqual(args.rounds, 2)
        self.assertEqual(args.adapter, ["python", "-m", "my_adapter"])

    def test_bounded_rounds_reuse_the_committed_pipeline(self):
        reports = [
            {"passed": True, "ingestion": {"accepted_events": 1}},
            {"passed": True, "ingestion": {"accepted_events": 0}},
        ]
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("firebreak.agent.process_room", side_effect=reports) as process,
            patch("firebreak.agent.time.sleep") as sleep,
        ):
            result = run_agent_command(
                "https://technocore.example",
                "lobby",
                Path(directory),
                rounds=2,
                interval=0.25,
            )
        self.assertEqual([report["agent_round"] for report in result], [1, 2])
        self.assertEqual([report["agent_rounds"] for report in result], [2, 2])
        self.assertEqual(process.call_count, 2)
        self.assertEqual(sleep.call_args.args, (0.25,))
        self.assertTrue(
            all(call.kwargs["command"] is None for call in process.call_args_list)
        )

    def test_custom_adapter_is_passed_without_approval_options(self):
        with patch(
            "firebreak.agent.process_room", return_value={"passed": True}
        ) as process:
            run_agent(
                AgentConfig(
                    "https://technocore.example",
                    "lobby",
                    Path(".firebreak"),
                    adapter=("trusted-adapter", "--safe"),
                )
            )
        self.assertEqual(
            process.call_args.kwargs["command"], ("trusted-adapter", "--safe")
        )

    def test_custom_drafter_is_passed_without_publish_options(self):
        with patch(
            "firebreak.agent.process_room", return_value={"passed": True}
        ) as process:
            run_agent(
                AgentConfig(
                    "https://technocore.example",
                    "lobby",
                    Path(".firebreak"),
                    draft_command=("trusted-drafter", "--safe"),
                )
            )
        self.assertEqual(
            process.call_args.kwargs["draft_command"],
            ("trusted-drafter", "--safe"),
        )

    def test_cli_accepts_a_drafter_after_the_room(self):
        args = parser().parse_args(
            [
                "agent",
                "--base-url",
                "https://technocore.example",
                "lobby",
                "--drafter",
                "python",
                "-m",
                "my_drafter",
            ]
        )
        self.assertEqual(args.drafter, ["python", "-m", "my_drafter"])

    def test_agent_limits_are_fail_closed(self):
        with self.assertRaises(ProtocolError):
            AgentConfig("https://technocore.example", "lobby", Path("."), rounds=0)
        with self.assertRaises(ProtocolError):
            AgentConfig("https://technocore.example", "lobby", Path("."), interval=61)
        with self.assertRaises(ProtocolError):
            AgentConfig("https://technocore.example", "lobby", Path("."), adapter=("",))


if __name__ == "__main__":
    unittest.main()
