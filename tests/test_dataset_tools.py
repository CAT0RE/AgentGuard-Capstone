import json
import tempfile
import unittest
from pathlib import Path

from agentguard.dataset_tools import annotation_agreement, freeze_dataset, validate_dataset
from agentguard.evaluation import evaluate_file


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "benchmarks" / "cases.jsonl"


class DatasetToolTests(unittest.TestCase):
    def test_development_dataset_validates_with_expected_warning(self):
        report = validate_dataset(DATASET)
        self.assertTrue(report["valid"])
        self.assertEqual(report["case_count"], 24)
        self.assertTrue(report["warnings"])

    def test_final_annotation_mode_rejects_incomplete_development_data(self):
        report = validate_dataset(DATASET, require_annotations=True)
        self.assertFalse(report["valid"])
        self.assertTrue(any("intervention_type" in error for error in report["errors"]))

    def test_freeze_development_dataset_creates_hash_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            manifest = freeze_dataset(DATASET, manifest_path, require_annotations=False)
            self.assertEqual(len(manifest["sha256"]), 64)
            self.assertEqual(manifest["validation"]["case_count"], 24)
            self.assertEqual(json.loads(manifest_path.read_text())["sha256"], manifest["sha256"])

    def test_annotation_agreement_reports_perfect_kappa(self):
        records = [
            {"case_id": "a", "label": "safe", "category": "benign", "intervention_type": "allow"},
            {"case_id": "b", "label": "unsafe", "category": "injection", "intervention_type": "block"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path_a = Path(directory) / "a.jsonl"
            path_b = Path(directory) / "b.jsonl"
            content = "".join(json.dumps(item) + "\n" for item in records)
            path_a.write_text(content)
            path_b.write_text(content)
            report = annotation_agreement(path_a, path_b)
            self.assertEqual(report["agreement"]["label"]["kappa"], 1.0)

    def test_evaluation_contains_confidence_intervals_and_mcnemar(self):
        result = evaluate_file(DATASET, ["none", "full"], bootstrap_samples=100)
        analysis = result["statistical_analysis"]
        self.assertEqual(analysis["bootstrap_samples"], 100)
        self.assertIn("full", analysis["confidence_intervals_95"])
        self.assertIn("full_vs_none", analysis["mcnemar_exact"])


if __name__ == "__main__":
    unittest.main()
