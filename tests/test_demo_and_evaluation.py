import unittest
from pathlib import Path

from agentguard.demo import SCENARIOS, run_scenario
from agentguard.evaluation import build_monitor, evaluate_file, load_cases
from agentguard.monitor import SecurityMonitor
from agentguard.server import Application


ROOT = Path(__file__).resolve().parents[1]


class DemoTests(unittest.TestCase):
    def test_every_scenario_runs(self):
        for scenario_id in SCENARIOS:
            with self.subTest(scenario=scenario_id):
                result = run_scenario(SecurityMonitor(), scenario_id)
                self.assertTrue(result["trace_id"])
                self.assertGreaterEqual(result["max_risk_score"], 0)

    def test_attack_scenarios_are_halted(self):
        for scenario_id, scenario in SCENARIOS.items():
            if scenario.expected_unsafe:
                with self.subTest(scenario=scenario_id):
                    result = run_scenario(SecurityMonitor(), scenario_id)
                    self.assertTrue(result["halted"])


class EvaluationTests(unittest.TestCase):
    def test_dataset_loads_and_has_both_classes(self):
        cases = load_cases(ROOT / "benchmarks" / "cases.jsonl")
        self.assertGreaterEqual(len(cases), 20)
        self.assertEqual({case["label"] for case in cases}, {"safe", "unsafe"})

    def test_full_monitor_outperforms_no_monitor(self):
        result = evaluate_file(ROOT / "benchmarks" / "cases.jsonl", ["none", "full"])
        self.assertGreater(result["profiles"]["full"]["metrics"]["f1"], result["profiles"]["none"]["metrics"]["f1"])

    def test_legacy_profile_keeps_original_detector_set(self):
        names = [detector.name for detector in build_monitor("full_v1").detectors]
        self.assertEqual(
            names,
            ["prompt_injection", "tool_policy", "sensitive_dataflow", "error_propagation", "sequence_anomaly"],
        )
        self.assertNotIn("structural_injection", names)

    def test_full_profile_enables_v2_detectors(self):
        names = [detector.name for detector in build_monitor("full").detectors]
        self.assertIn("structural_injection", names)
        self.assertIn("goal_alignment", names)


class ApplicationTests(unittest.TestCase):
    def test_agent_api_application_runs_offline_scenario(self):
        app = Application(ROOT / "benchmarks" / "cases.jsonl")
        scenarios = app.agent_scenarios()["scenarios"]
        self.assertGreaterEqual(len(scenarios), 5)
        result = app.run_agent({"scenario_id": "injected_email", "policy": "balanced"})
        self.assertEqual(result["status"], "blocked")
        self.assertIn(result["trace_id"], app.runs)


if __name__ == "__main__":
    unittest.main()
