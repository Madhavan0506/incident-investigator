from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from .agent import Case, investigate
from .evaluate import evaluate
from .evidence import Corpus
from .local_model import LocalModel, ModelError
from .review import ReviewStore, render_markdown, visible_text


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Investigate incidents from local logs and runbooks.")
    parser.add_argument("--db", type=Path, default=Path(".incidents.sqlite3"), help="local draft and review database")
    commands = parser.add_subparsers(dest="command", required=True)

    draft = commands.add_parser("draft", help="investigate an incident and save a pending report")
    draft.add_argument("--case", required=True, type=Path, help="incident JSON file")
    evaluation = commands.add_parser("evaluate", help="score an investigation engine on labeled cases")
    evaluation.add_argument("--cases", required=True, type=Path, help="directory of labeled incident JSON files")
    for command in (draft, evaluation):
        command.add_argument("--corpus", required=True, type=Path, help="directory containing logs/ and runbooks/")
        command.add_argument("--ollama-model", help="opt in to a preinstalled local Ollama model with function calling")

    show = commands.add_parser("show", help="read a draft and its review status")
    show.add_argument("draft_id")
    show.add_argument("--json", action="store_true", help="include the structured report and audit trail")

    for name in ("approve", "reject"):
        decision = commands.add_parser(name, help=f"{name} a specific draft after reviewing it")
        decision.add_argument("draft_id")
        decision.add_argument("--digest", required=True, help="full SHA-256 digest displayed on the draft")
        decision.add_argument("--reviewer", required=True, help="reviewer's name for the local audit record")

    export = commands.add_parser("export", help="print an approved Markdown report")
    export.add_argument("draft_id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store = ReviewStore(args.db)
    try:
        if args.command in ("draft", "evaluate"):
            corpus = Corpus(args.corpus)
            model = LocalModel(args.ollama_model) if args.ollama_model else None
            if args.command == "evaluate":
                results = evaluate(corpus, args.cases, model=model)
                print(json.dumps(results, indent=2))
                return 0 if results["passed"] else 1
            case = Case.from_dict(json.loads(args.case.read_text(encoding="utf-8")))
            print(render_markdown(store.save(investigate(case, corpus, model=model))), end="")
        elif args.command == "show":
            entry = store.get(args.draft_id)
            if args.json:
                print(json.dumps(entry, indent=2))
            else:
                print(render_markdown(entry), end="")
        elif args.command == "export":
            print(render_markdown(store.get(args.draft_id, approved_only=True)), end="")
        else:
            entry = store.decide(args.draft_id, args.digest, args.reviewer, approve=args.command == "approve")
            print(f"Draft {entry['id']} {entry['status']}.")
        return 0
    except (ValueError, OSError, ModelError, sqlite3.Error) as exc:
        print(f"Error: {visible_text(str(exc))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
