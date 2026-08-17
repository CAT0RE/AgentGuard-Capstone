import json
import unittest

from agentguard.agent_scenarios import AGENT_SCENARIOS, build_offline_scenario
from agentguard.detectors.base import Detector
from agentguard.models import EventKind, Finding
from agentguard.monitor import SecurityMonitor
from agentguard.providers import ModelTurn, OpenAIResponsesProvider, ReplayProvider, function_turn
from agentguard.runner import MonitoredAgentRunner
from agentguard.sandbox import ToolSandbox


class RunnerTests(unittest.TestCase):
    def run_scenario(self, scenario_id):
        scenario, provider, sandbox = build_offline_scenario(scenario_id)
        preauthorized = set(scenario.preauthorized_tools)
        runner = MonitoredAgentRunner(provider, monitor=SecurityMonitor(), sandbox=sandbox)
        result = runner.run(
            scenario.user_intent,
            allowed_tools=scenario.allowed_tools,
            authorized_destinations=scenario.authorized_destinations,
            authorization_resolver=lambda _call, monitor_name: monitor_name in preauthorized,
        )
        return scenario, result, sandbox

    def test_all_offline_agent_scenarios_reach_expected_status(self):
        for scenario_id in AGENT_SCENARIOS:
            with self.subTest(scenario=scenario_id):
                scenario, result, _sandbox = self.run_scenario(scenario_id)
                self.assertEqual(result.status, scenario.expected_status)

    def test_injected_tool_output_is_not_returned_to_model(self):
        _scenario, result, sandbox = self.run_scenario("injected_email")
        self.assertEqual(result.status, "blocked")
        self.assertEqual([item["monitor_name"] for item in sandbox.executions], ["email.read"])
        self.assertFalse(sandbox.world.outbox)
        self.assertTrue(any(item["kind"] == "tool_result" for item in result.interventions))

    def test_verify_decision_quarantines_tool_output(self):
        class VerifyToolResult(Detector):
            name = "verify_fixture"

            def analyze(self, event, state):
                if event.kind != EventKind.TOOL_RESULT:
                    return []
                return [
                    Finding(
                        detector=self.name,
                        category="fixture",
                        title="Verification required",
                        description="Fixture evidence",
                        severity=50,
                        confidence=0.8,
                        evidence="fixture",
                        recommendation="Verify",
                    )
                ]

        provider = ReplayProvider([function_turn("c-verify", "email_read", {"id": "m-safe"})])
        monitor = SecurityMonitor(detectors=[VerifyToolResult()])
        runner = MonitoredAgentRunner(provider, monitor=monitor, sandbox=ToolSandbox())
        result = runner.run("Read the safe message", allowed_tools=["email.read"])
        self.assertEqual(result.status, "verify")
        self.assertEqual(len(result.executed_tools), 1)
        self.assertTrue(any(item["kind"] == "tool_result" for item in result.interventions))

    def test_scope_escalation_has_no_side_effect(self):
        _scenario, result, sandbox = self.run_scenario("scope_escalation")
        self.assertEqual(result.status, "blocked")
        self.assertFalse(sandbox.executions)
        self.assertIn("draft.tmp", sandbox.world.files)

    def test_error_does_not_propagate_into_transfer(self):
        _scenario, result, sandbox = self.run_scenario("error_to_transfer")
        self.assertEqual(result.status, "blocked")
        self.assertEqual([item["monitor_name"] for item in sandbox.executions], ["bank.lookup"])
        self.assertFalse(sandbox.world.transfers)

    def test_authorized_send_executes_only_expected_recipient(self):
        _scenario, result, sandbox = self.run_scenario("authorized_send")
        self.assertEqual(result.status, "completed")
        self.assertEqual(sandbox.world.outbox[0]["to"], "supervisor@university.edu")

    def test_max_turn_budget_stops_loop(self):
        provider = ReplayProvider([function_turn(f"c-{index}", "email_read", {"id": "m-safe"}) for index in range(5)])
        runner = MonitoredAgentRunner(provider, sandbox=ToolSandbox(), max_turns=2)
        result = runner.run("Read m-safe repeatedly", allowed_tools=["email.read"])
        self.assertEqual(result.status, "max_turns")
        self.assertEqual(result.turns, 2)


class OpenAIProviderTests(unittest.TestCase):
    def test_responses_payload_and_function_parsing(self):
        captured = {}

        def transport(url, headers, body, timeout):
            captured.update(url=url, headers=headers, payload=json.loads(body), timeout=timeout)
            return {
                "output": [
                    {
                        "type": "function_call",
                        "call_id": "call-42",
                        "name": "email_read",
                        "arguments": '{"id":"m-safe"}',
                    }
                ]
            }

        provider = OpenAIResponsesProvider("test-model", api_key="test-key", transport=transport)
        tools = ToolSandbox().schemas(["email.read"])
        turn = provider.respond(input_items=[{"role": "user", "content": "read"}], tools=tools, instructions="safe")
        self.assertEqual(turn.function_calls[0].arguments, {"id": "m-safe"})
        self.assertEqual(captured["url"], "https://api.openai.com/v1/responses")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer test-key")
        self.assertFalse(captured["payload"]["parallel_tool_calls"])
        self.assertFalse(captured["payload"]["store"])
        self.assertTrue(captured["payload"]["tools"][0]["strict"])
        self.assertFalse(captured["payload"]["tools"][0]["parameters"]["additionalProperties"])

    def test_missing_api_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "OPENAI_API_KEY"):
            OpenAIResponsesProvider("test-model", api_key="")

    def test_output_text_fallback(self):
        provider = OpenAIResponsesProvider(
            "test-model",
            api_key="test-key",
            transport=lambda *_args: {
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "finished"}],
                    }
                ]
            },
        )
        turn = provider.respond(input_items=[], tools=[], instructions="safe")
        self.assertEqual(turn.text, "finished")


if __name__ == "__main__":
    unittest.main()
