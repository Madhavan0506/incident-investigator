from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from incident_agent.agent import investigate
from incident_agent.evidence import Corpus
from incident_agent.evaluate import evaluate


DEMO = Path(__file__).resolve().parents[1] / "demo"


class EvaluationTest(unittest.TestCase):
    def setUp(self):
        self.corpus = Corpus(DEMO / "corpus")
        self.cases = DEMO / "cases"

    def test_fixture_evaluation_covers_outcomes_and_permissions(self):
        result = evaluate(self.corpus, self.cases)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["case_count"], 7)
        self.assertEqual(result["diagnosis_accuracy"], 1.0)
        self.assertEqual(result["evidence_support_rate"], 1.0)
        self.assertEqual(result["permission_checks_passed"], result["permission_checks_total"])
        self.assertEqual(result["paid_cost_usd"]["mean_per_case"], 0.0)
        self.assertEqual(sum(case["outcome"] == "unresolved" for case in result["cases"]), 3)

    def test_changed_citation_text_fails_evidence_support(self):
        def with_altered_excerpt(case, corpus, *, model=None):
            report = investigate(case, corpus)
            if case.id == "checkout-db":
                report["sources"][0]["text"] += "\nAltered evidence"
            return report

        with patch("incident_agent.evaluate.investigate", side_effect=with_altered_excerpt):
            result = evaluate(self.corpus, self.cases)

        self.assertFalse(result["passed"])
        self.assertEqual(result["diagnosis_accuracy"], 1.0)
        self.assertEqual(result["evidence_support_rate"], 6 / 7)

    def test_model_evaluation_requires_model_retrieval_provenance(self):
        def with_only_verifier_audit(case, corpus, *, model=None):
            return investigate(case, corpus)

        with patch("incident_agent.evaluate.investigate", side_effect=with_only_verifier_audit):
            result = evaluate(self.corpus, self.cases, model=object())

        self.assertFalse(result["passed"])
        self.assertEqual(result["diagnosis_accuracy"], 1.0)
        self.assertEqual(result["evidence_support_rate"], 3 / 7)

    def test_runbook_example_inside_code_fence_does_not_change_grounding(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "corpus"
            copytree(DEMO / "corpus", root)
            runbook = root / "runbooks" / "checkout.md"
            text = runbook.read_text(encoding="utf-8")
            runbook.write_text(text.replace(
                "## DNS resolution for the payment dependency",
                "```text\nDiagnosis: Explanation omitted\nSignals: SAMPLE_EVENT\n```\n\n"
                "## DNS resolution for the payment dependency",
            ), encoding="utf-8")
            result = evaluate(Corpus(root), self.cases)

        self.assertTrue(result["passed"], result)


if __name__ == "__main__":
    unittest.main()
