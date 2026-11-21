import json
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

from incident_agent.agent import Case, investigate
from incident_agent.evidence import Corpus
from incident_agent.review import ReviewError, ReviewStore, render_markdown


DEMO = Path(__file__).resolve().parents[1] / "demo"


def demo_case(name):
    return Case.from_dict(json.loads((DEMO / "cases" / f"{name}.json").read_text(encoding="utf-8")))


def call(name, **arguments):
    return {"function": {"name": name, "arguments": arguments}}


class ScriptedModel:
    model = "test-model"

    def __init__(self, choice, *, requests=None):
        self.requests = requests
        self.choice = choice
        self.input_tokens = 0
        self.output_tokens = 0
        self.messages = []

    def complete(self, messages, tools):
        self.messages = list(messages)
        self.input_tokens += 10
        self.output_tokens += 3
        if self.requests is not None:
            requests, self.requests = self.requests, None
            return {"role": "assistant", "content": "", "tool_calls": requests}
        return {"role": "assistant", "content": json.dumps(self.choice)}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.corpus = Corpus(DEMO / "corpus")
        self.case = demo_case("checkout-db")
        self.default_report = investigate(self.case, self.corpus)
        self.choice = {
            "runbook_id": self.default_report["runbook_source_id"],
            "log_ids": [finding["source_id"] for finding in self.default_report["findings"]],
        }

    def test_model_calls_read_only_tools_and_cites_returned_sources(self):
        model = ScriptedModel(self.choice, requests=[
            call("approve_report"),
            call("search_logs", query="", service="identity"),
            call("search_runbooks", query="database connection"),
            call("search_logs", query="DB_POOL_EXHAUSTED"),
            call("search_logs", query="DB_ACQUIRE_TIMEOUT"),
        ])
        report = investigate(self.case, self.corpus, model=model)
        self.assertEqual(report["diagnosis"], self.default_report["diagnosis"])
        self.assertEqual(report["findings"], self.default_report["findings"])
        self.assertEqual(report["metrics"]["denied_tool_calls"], 2)
        self.assertEqual(report["metrics"]["output_tokens"], 6)
        self.assertNotIn("expected", model.messages[1]["content"])
        self.assertEqual(
            ["error" in json.loads(message["content"]) for message in model.messages if message["role"] == "tool"],
            [True, True, False, False, False],
        )

    def test_model_cannot_cite_unretrieved_or_incorrect_evidence(self):
        models = [
            ScriptedModel(self.choice),
            ScriptedModel({"runbook_id": self.choice["runbook_id"], "log_ids": ["logs/checkout.jsonl:L3"]}, requests=[
                call("search_runbooks", query=""), call("search_logs", query=""),
            ]),
        ]
        for model in models:
            with self.subTest(model=model):
                report = investigate(self.case, self.corpus, model=model)
                self.assertEqual(report["outcome"], "unresolved")
                self.assertIsNone(report["next_step"])

    def test_model_cannot_select_a_diagnosis_when_evidence_conflicts(self):
        model = ScriptedModel({
            "runbook_id": self.choice["runbook_id"], "log_ids": ["logs/checkout.jsonl:L13", "logs/checkout.jsonl:L14"],
        }, requests=[call("search_runbooks", query="database connection"), call("search_logs", query="DB_POOL")])
        report = investigate(demo_case("checkout-conflicting"), self.corpus, model=model)
        self.assertEqual(report["outcome"], "unresolved")
        self.assertIn("multiple distinct diagnoses", report["reason"])

    def test_approval_requires_matching_digest_and_is_bound_to_draft(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "review.sqlite3"
            store = ReviewStore(path)
            draft = store.save(self.default_report)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(ReviewError, "pending"):
                store.get(draft["id"], approved_only=True)
            with self.assertRaisesRegex(ReviewError, "differs"):
                store.decide(draft["id"], "0" * 64, "Synthetic reviewer", approve=True)
            approved = store.decide(draft["id"], draft["digest"], "Synthetic reviewer", approve=True)
            self.assertEqual(store.get(draft["id"], approved_only=True), approved)
            self.assertIn("Review status **approved**", render_markdown(approved))
            with self.assertRaisesRegex(ReviewError, "already approved"):
                store.decide(draft["id"], draft["digest"], "Synthetic reviewer", approve=False)
            with sqlite3.connect(path) as database:
                database.execute("UPDATE drafts SET payload = ? WHERE id = ?", ("{}", draft["id"]))
            with self.assertRaisesRegex(ReviewError, "integrity"):
                store.get(draft["id"], approved_only=True)

    def test_rejected_draft_cannot_be_exported_or_approved(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = ReviewStore(Path(temporary) / "review.sqlite3")
            draft = store.save(self.default_report)
            store.decide(draft["id"], draft["digest"], "Synthetic reviewer", approve=False)
            with self.assertRaisesRegex(ReviewError, "rejected"):
                store.get(draft["id"], approved_only=True)
            with self.assertRaisesRegex(ReviewError, "already rejected"):
                store.decide(draft["id"], draft["digest"], "Synthetic reviewer", approve=True)

    def test_render_escapes_terminal_control_characters(self):
        self.default_report["sources"][0]["text"] += "\n\x1b[2J"
        self.default_report["case"]["symptom"] += "\x1b[2J"
        with tempfile.TemporaryDirectory() as temporary:
            store = ReviewStore(Path(temporary) / "review.sqlite3")
            report = render_markdown(store.save(self.default_report))
        self.assertNotIn("\x1b", report)
        self.assertIn(r"\u001b[2J", report)


if __name__ == "__main__":
    unittest.main()
