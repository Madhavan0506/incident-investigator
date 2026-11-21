"""Score incident drafts against independently labeled local fixtures."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from statistics import mean, median
from time import perf_counter

from .agent import Case, PermissionDenied, ScopedTools, investigate
from .evidence import Corpus, Source, markdown_text_lines, parse_timestamp


ALLOWED_TOOL_KINDS = {"search_logs": "log", "search_runbooks": "runbook"}
VERIFIER_TOOL_KINDS = {"verify_signal": "log", "verify_runbooks": "runbook"}
EVENT_CODE = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}"


def _load_cases(cases_dir: Path) -> list[tuple[Case, dict]]:
    fixtures = []
    seen = set()
    for path in sorted(cases_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            case = Case.from_dict(payload)
            expected = payload["expected"]
            diagnosis = expected["diagnosis"]
            signals = expected["signals"]
            if diagnosis is not None and (not isinstance(diagnosis, str) or not diagnosis.strip()):
                raise ValueError("expected diagnosis must be nonempty text or null")
            if not isinstance(signals, list) or not all(map(_is_signal, signals)):
                raise ValueError("expected signals must be a list of event codes")
            if len(signals) != len(set(signals)) or (diagnosis is not None) != bool(signals):
                raise ValueError("expected signals must be distinct and present for a diagnosis")
            observed_signals = expected.get("observed_signals", [])
            if not isinstance(observed_signals, list) or not all(map(_is_signal, observed_signals)):
                raise ValueError("expected observed_signals must be a list of event codes")
            competing = expected.get("competing_diagnoses", [])
            if not isinstance(competing, list) or any(
                not isinstance(label, str) or not label.strip() for label in competing
            ):
                raise ValueError("expected competing_diagnoses must be a list of diagnosis labels")
            if competing and (len(set(competing)) < 2 or diagnosis is not None):
                raise ValueError("expected competing diagnoses require an unresolved result and distinct labels")
            if case.id in seen:
                raise ValueError(f"duplicate case ID {case.id!r}")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid evaluation fixture {path}: {exc}") from exc
        seen.add(case.id)
        fixtures.append((case, expected))
    if not fixtures:
        raise ValueError(f"No JSON evaluation fixtures found in {cases_dir}")
    return fixtures


def _is_signal(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(EVENT_CODE, value) is not None


def _in_scope(source: Source, case: Case) -> bool:
    if source.service != case.service:
        return False
    if source.kind == "runbook":
        return True
    if source.kind != "log" or source.timestamp is None:
        return False
    return parse_timestamp(case.start) <= parse_timestamp(source.timestamp) <= parse_timestamp(case.end)


def _check_tool_audit(
    report: dict, corpus: Corpus, case: Case
) -> tuple[set[str], set[str], bool]:
    retrieved = set()
    verified = set()
    denied = 0
    for entry in report["tool_audit"]:
        tool = entry["tool"]
        source_ids = entry.get("source_ids", [])
        if entry["result"] == "denied" and not source_ids:
            denied += 1
            continue
        expected_kind = ALLOWED_TOOL_KINDS.get(tool) or VERIFIER_TOOL_KINDS.get(tool)
        if entry["result"] != "allowed" or expected_kind is None or len(source_ids) != len(set(source_ids)):
            return retrieved, verified, False
        if tool in ALLOWED_TOOL_KINDS and len(source_ids) > entry["limit"]:
            return retrieved, verified, False
        for source_id in source_ids:
            source = corpus.get(source_id)
            if source is None or source.kind != expected_kind or not _in_scope(source, case):
                return retrieved, verified, False
            if tool == "verify_signal" and not _contains_event(source, entry["query"]):
                return retrieved, verified, False
        if tool in ALLOWED_TOOL_KINDS:
            retrieved.update(source_ids)
        else:
            verified.update(source_ids)
    return retrieved, verified, denied == report["metrics"]["denied_tool_calls"]


def _contains_event(source: Source, event: str) -> bool:
    if source.kind != "log" or not _is_signal(event):
        return False
    if source.event:
        return source.event == event
    return re.match(rf"\s*{re.escape(event)}:?(?:\s|$)", source.text) is not None


def _runbook_fields(source: Source) -> dict:
    if source.kind != "runbook":
        return {}
    fields = {}
    for _, line in markdown_text_lines(source.text.split("\n")):
        key, _, value = line.partition(":")
        if key in {"Diagnosis", "Signals", "Next step"} and value.strip():
            if key in fields:
                return {}
            fields[key] = value.strip()
    if "Signals" in fields:
        fields["Signals"] = {signal.strip() for signal in fields["Signals"].split(",")}
    return fields


def _check_evidence(
    report: dict, corpus: Corpus, case: Case, expected: dict, evidence_ids: set[str]
) -> bool:
    sources = {}
    for citation in report["sources"]:
        source_id = citation["id"]
        source = corpus.get(source_id)
        if (
            source is None
            or source_id in sources
            or source_id not in evidence_ids
            or source.as_dict() != citation
            or not _in_scope(source, case)
        ):
            return False
        sources[source_id] = source

    signals = set()
    for finding in report["findings"]:
        signal = finding["signal"]
        source = sources.get(finding["source_id"])
        if source is None or not _contains_event(source, signal):
            return False
        signals.add(signal)

    diagnosis = report["diagnosis"]
    next_step = report["next_step"]
    runbook_id = report["runbook_source_id"]
    if report["outcome"] == "unresolved":
        if diagnosis is not None or next_step is not None or runbook_id is not None:
            return False
        logs = [source for source in sources.values() if source.kind == "log"]
        if not all(
            any(_contains_event(source, signal) for source in logs)
            for signal in expected.get("observed_signals", [])
        ):
            return False
        competing = set(expected.get("competing_diagnoses", []))
        if not competing:
            return True
        fields = [_runbook_fields(source) for source in sources.values() if source.kind == "runbook"]
        backed = {
            entry["Diagnosis"] for entry in fields
            if "Diagnosis" in entry and entry.get("Signals")
            and all(any(_contains_event(source, signal) for source in logs) for signal in entry["Signals"])
        }
        return competing <= backed
    if report["outcome"] != "supported" or not diagnosis or not next_step or not runbook_id:
        return False

    runbook = sources.get(runbook_id)
    if runbook is None or runbook.kind != "runbook":
        return False
    fields = _runbook_fields(runbook)
    if diagnosis == expected["diagnosis"] and signals != set(expected["signals"]):
        return False
    return (
        fields.get("Diagnosis") == diagnosis
        and fields.get("Next step") == next_step
        and fields.get("Signals") == signals
    )


def _permission_probes(corpus: Corpus, case: Case) -> list[dict]:
    probes = [
        ("retrieve_incident_logs", "search_logs", {"query": "", "limit": 1}, "allowed"),
        ("retrieve_runbooks", "search_runbooks", {"query": "", "limit": 1}, "allowed"),
        ("override_log_service", "search_logs", {"query": "", "service": "other-service"}, "denied"),
        ("override_log_start", "search_logs", {"query": "", "start": "2020-01-01T00:00:00Z"}, "denied"),
        ("override_log_end", "search_logs", {"query": "", "end": "2099-01-01T00:00:00Z"}, "denied"),
        ("override_runbook_service", "search_runbooks", {"query": "", "service": "other-service"}, "denied"),
        ("override_runbook_path", "search_runbooks", {"query": "", "path": "outside.json"}, "denied"),
        ("oversized_log_query_limit", "search_logs", {"query": "", "limit": 100000}, "denied"),
        ("invoke_internal_runbook_verifier", "verify_runbooks", {}, "denied"),
        ("invoke_internal_signal_verifier", "verify_signal", {"query": "TEST_EVENT"}, "denied"),
        ("unlisted_file_read", "read_file", {"path": "outside.json"}, "denied"),
        ("publish_report", "publish_report", {}, "denied"),
        ("approve_report", "approve_report", {}, "denied"),
    ]
    results = []
    for name, tool, arguments, expected in probes:
        scoped = ScopedTools(corpus, case)
        try:
            scoped.call(tool, arguments)
            observed = "allowed"
        except PermissionDenied:
            observed = "denied"
        audit_report = {
            "tool_audit": scoped.audit,
            "metrics": {"denied_tool_calls": int(observed == "denied")},
        }
        _, _, audit_ok = _check_tool_audit(audit_report, corpus, case)
        audited = len(scoped.audit) == 1 and scoped.audit[0]["result"] == observed and audit_ok
        results.append({
            "probe": name, "expected": expected, "observed": observed,
            "passed": observed == expected and audited,
        })
    return results


def evaluate(corpus: Corpus, cases_dir: Path, *, model=None) -> dict:
    """Measure diagnosis, citation support, permission enforcement, time, and paid cost."""
    fixtures = _load_cases(cases_dir)
    case_results = []
    for case, expected in fixtures:
        started = perf_counter()
        report = investigate(case, corpus, model=model)
        elapsed_ms = (perf_counter() - started) * 1000
        retrieved, verified, permissions_held = _check_tool_audit(report, corpus, case)
        evidence_ids = retrieved if model is not None and report["outcome"] == "supported" else retrieved | verified
        diagnosis = expected["diagnosis"]
        expected_outcome = "supported" if diagnosis is not None else "unresolved"
        case_results.append({
            "case_id": case.id,
            "engine": report["engine"],
            "expected_diagnosis": diagnosis,
            "diagnosis": report["diagnosis"],
            "outcome": report["outcome"],
            "diagnosis_correct": diagnosis == report["diagnosis"] and expected_outcome == report["outcome"],
            "evidence_supported": _check_evidence(report, corpus, case, expected, evidence_ids),
            "permissions_held": permissions_held,
            "search_tool_calls": sum(
                entry["result"] == "allowed" and entry["tool"] in ALLOWED_TOOL_KINDS
                for entry in report["tool_audit"]
            ),
            "latency_ms": elapsed_ms,
            "paid_cost_usd": report["metrics"]["paid_cost_usd"],
            "input_tokens": report["metrics"]["input_tokens"],
            "output_tokens": report["metrics"]["output_tokens"],
        })

    probes = _permission_probes(corpus, fixtures[0][0])
    case_count = len(case_results)
    correct = sum(result["diagnosis_correct"] for result in case_results)
    supported = sum(result["evidence_supported"] for result in case_results)
    scoped = sum(result["permissions_held"] for result in case_results)
    permission_passes = sum(result["passed"] for result in probes)
    durations = sorted(result["latency_ms"] for result in case_results)
    costs = [result["paid_cost_usd"] for result in case_results]
    return {
        "passed": correct == supported == scoped == case_count
        and permission_passes == len(probes)
        and all(cost == 0 for cost in costs),
        "case_count": case_count,
        "diagnosis_accuracy": correct / case_count,
        "evidence_support_rate": supported / case_count,
        "cases_with_permissions_held": scoped,
        "permission_checks_passed": permission_passes,
        "permission_checks_total": len(probes),
        "latency_ms": {
            "mean": mean(durations),
            "median": median(durations),
            "p95": durations[math.ceil(0.95 * case_count) - 1],
            "max": durations[-1],
        },
        "paid_cost_usd": {"total": sum(costs), "mean_per_case": mean(costs)},
        "cases": case_results,
        "permission_checks": probes,
    }
