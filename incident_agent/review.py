from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from uuid import uuid4


_SCHEMA = """
CREATE TABLE IF NOT EXISTS drafts (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    digest TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    draft_id TEXT PRIMARY KEY REFERENCES drafts(id),
    digest TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('approved', 'rejected')),
    decided_at TEXT NOT NULL
);
"""
_ENTRY = """
SELECT drafts.id, created_at, drafts.digest, payload,
       decisions.digest AS decision_digest, reviewer, status, decided_at
FROM drafts LEFT JOIN decisions ON drafts.id = decisions.draft_id
WHERE drafts.id = ?
"""


class ReviewError(ValueError):
    """A draft or review failed an approval check."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(payload: str) -> str:
    return sha256(payload.encode("utf-8")).hexdigest()


class ReviewStore:
    def __init__(self, path: Path):
        self.path = path

    def _open(self, *, create: bool = False) -> sqlite3.Connection:
        if create:
            try:
                descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        elif not self.path.is_file():
            raise ReviewError(f"Review database does not exist: {self.path}")
        connection = sqlite3.connect(self.path)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(_SCHEMA)
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def save(self, report: dict) -> dict:
        payload = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        draft_id = uuid4().hex
        with closing(self._open(create=True)) as connection, connection:
            connection.execute("INSERT INTO drafts VALUES (?, ?, ?, ?)", (draft_id, _now(), _digest(payload), payload))
        return self.get(draft_id)

    def get(self, draft_id: str, *, approved_only: bool = False) -> dict:
        with closing(self._open()) as connection:
            entry = self._read(connection, draft_id)
        if approved_only and entry["status"] != "approved":
            raise ReviewError(f"Export requires approval. This draft is {entry['status']}.")
        return entry

    def decide(self, draft_id: str, digest: str, reviewer: str, *, approve: bool) -> dict:
        reviewer = reviewer.strip()
        if not reviewer or len(reviewer) > 100 or not reviewer.isprintable():
            raise ReviewError("Reviewer must contain 1 to 100 printable characters")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReviewError("Provide the full SHA-256 digest shown with the draft")
        status = "approved" if approve else "rejected"
        with closing(self._open()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            entry = self._read(connection, draft_id)
            if entry["status"] != "pending":
                raise ReviewError(f"This draft is already {entry['status']}")
            if not compare_digest(digest, entry["digest"]):
                raise ReviewError("Review digest differs from the stored draft digest")
            connection.execute(
                "INSERT INTO decisions (draft_id, digest, reviewer, status, decided_at) VALUES (?, ?, ?, ?, ?)",
                (draft_id, digest, reviewer, status, _now()),
            )
        return self.get(draft_id)

    @staticmethod
    def _read(connection: sqlite3.Connection, draft_id: str) -> dict:
        row = connection.execute(_ENTRY, (draft_id,)).fetchone()
        if row is None:
            raise ReviewError(f"Unknown draft ID {draft_id!r}")
        if _digest(row["payload"]) != row["digest"]:
            raise ReviewError("Stored draft failed the SHA-256 integrity check")
        if row["status"] is not None and row["decision_digest"] != row["digest"]:
            raise ReviewError("Stored decision does not match the draft digest")
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "digest": row["digest"],
            "status": row["status"] or "pending",
            "reviewer": row["reviewer"],
            "decided_at": row["decided_at"],
            "report": json.loads(row["payload"]),
        }


def visible_text(value: str) -> str:
    return "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in value)


def _inline(value: str) -> str:
    text = visible_text(value.replace("\n", " ").replace("\r", " "))
    return re.sub(r"([\\`*_{}\[\]()<>#+!|])", r"\\\1", text)


def render_markdown(entry: dict) -> str:
    report = entry["report"]
    case = report["case"]
    lines = [
        f"# Incident report for {_inline(case['id'])}",
        "",
        f"- Review status **{entry['status']}**",
        f"- Draft ID `{entry['id']}`",
        f"- Draft SHA-256 `{entry['digest']}`",
        f"- Service {_inline(case['service'])}",
        f"- Incident window `{case['start']}` through `{case['end']}` (inclusive)",
        f"- Investigation engine {_inline(report['engine'])}",
    ]
    if entry["reviewer"]:
        lines.append(f"- Reviewed by {_inline(entry['reviewer'])} at `{entry['decided_at']}`")
    lines.extend([
        "",
        "## Reported symptom",
        "",
        f"{_inline(case['symptom'])}",
        "",
        "## Diagnosis",
        "",
        _inline(report["diagnosis"] or "Unresolved"),
        "",
        _inline(report["reason"]),
    ])
    if report["findings"]:
        lines.extend(["", "## Corroborating signals", ""])
        for finding in report["findings"]:
            lines.append(f"- {_inline(finding['signal'])} · {_inline(finding['source_id'])}")
    if report["next_step"]:
        lines.extend([
            "", "## Suggested next step for the responder", "",
            _inline(report["next_step"]), "", f"Runbook {_inline(report['runbook_source_id'])}",
        ])
    lines.extend(["", "## Source excerpts", ""])
    if not report["sources"]:
        lines.append("The investigation retrieved no source excerpts for this case.")
    for source in report["sources"]:
        details = " · ".join(source.get(field, "") for field in ("timestamp", "level") if source.get(field))
        reference = f"**{_inline(source['id'])}**"
        lines.extend([reference + (f" · {_inline(details)}" if details else ""), ""])
        lines.extend(f"    {visible_text(line)}" for line in source["text"].split("\n"))
        lines.append("")
    metrics = report["metrics"]
    lines.extend([
        "", "## Investigation metrics", "",
        f"- Latency {metrics['latency_ms']:.3f} ms",
        f"- Paid API cost ${metrics['paid_cost_usd']:.2f}",
        f"- Tool calls {metrics['tool_calls']} ({metrics['denied_tool_calls']} denied)",
        f"- Model tokens {metrics['input_tokens']} input, {metrics['output_tokens']} output",
    ])
    return "\n".join(lines) + "\n"
