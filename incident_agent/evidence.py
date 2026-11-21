"""Read-only lexical retrieval over local application logs and runbooks."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
from typing import Iterable, Iterator, Optional


_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_TOKEN = re.compile(r"[^\W_]+(?:[_-][^\W_]+)*")
_TITLE = re.compile(r"^ {0,3}#(?:[ \t]+|$)")
_SECTION = re.compile(r"^ {0,3}##(?:[ \t]+|$)")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_SERVICE = re.compile(r"^ {0,3}Service:[ \t]*(.+?)\s*$")
_STOP_WORDS = frozenset("a an and are as at by for from in is it of on or the to was were with".split())


def parse_timestamp(value: str) -> datetime:
    """Parse a timestamp with a UTC offset at up to microsecond precision."""
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError("Expected an RFC 3339 timestamp with a UTC offset and up to six fractional digits")
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise ValueError("Invalid RFC 3339 date or time") from error


@dataclass(frozen=True)
class Source:
    id: str
    kind: str
    path: str
    line_start: int
    line_end: int
    text: str
    service: Optional[str] = None
    timestamp: Optional[str] = None
    level: Optional[str] = None
    event: Optional[str] = None

    def as_dict(self) -> dict:
        return {key: value for key, value in asdict(self).items() if value is not None}


def log_supports_signal(source: Source, signal: str) -> bool:
    """Match a structured event or a leading event code in a log message."""
    if source.kind != "log" or not signal.strip():
        return False
    if source.event:
        return source.event == signal
    parts = source.text.split(maxsplit=1)
    return bool(parts and parts[0] in (signal, f"{signal}:"))


class Corpus:
    """Index a fixed snapshot of UTF-8 JSON Lines logs and Markdown runbooks."""

    def __init__(self, root: Path):
        self._root = Path(root).resolve()
        if not self._root.is_dir():
            raise ValueError(f"Evidence root must be a directory: {self._root}")
        self._sources: dict[str, Source] = {}
        self._terms: dict[str, Counter[str]] = {}
        self._logs: dict[str, list[tuple[datetime, Source]]] = defaultdict(list)
        self._runbooks: dict[str, list[Source]] = defaultdict(list)

        for path in self._files("logs", "*.jsonl"):
            self._load_logs(path)
        for service_logs in self._logs.values():
            service_logs.sort(key=lambda entry: entry[0])
        for path in self._files("runbooks", "*.md"):
            self._load_runbook(path)

    def get(self, source_id: str) -> Optional[Source]:
        return self._sources.get(source_id)

    def search_logs(self, query: str, *, service: str, start: str, end: str, limit: int) -> list[Source]:
        return self._rank(list(self._scoped_logs(service, start, end)), query, limit)

    def search_runbooks(self, query: str, *, service: str, limit: int) -> list[Source]:
        return self._rank(self._runbooks.get(service, []), query, limit)

    def runbooks_for_service(self, service: str) -> list[Source]:
        return list(self._runbooks.get(service, ()))

    def find_log_signal(self, signal: str, *, service: str, start: str, end: str) -> Optional[Source]:
        return next(
            (source for source in self._scoped_logs(service, start, end) if log_supports_signal(source, signal)),
            None,
        )

    def _scoped_logs(self, service: str, start: str, end: str) -> Iterator[Source]:
        start_time = parse_timestamp(start)
        end_time = parse_timestamp(end)
        if start_time > end_time:
            raise ValueError("Log search start must precede or equal its end")
        for timestamp, source in self._logs.get(service, ()):
            if timestamp > end_time:
                break
            if timestamp >= start_time:
                yield source

    def _files(self, name: str, pattern: str) -> Iterator[Path]:
        directory = self._root / name
        if directory.is_symlink():
            raise ValueError(f"Evidence directory may not be a symbolic link: {directory}")
        if not directory.exists():
            return
        if not directory.is_dir():
            raise ValueError(f"Expected an evidence directory: {directory}")
        for path in sorted(directory.glob(pattern)):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Expected a regular evidence file: {path}")
            yield path

    def _index(self, source: Source, terms: Iterable[str]) -> None:
        self._sources[source.id] = source
        self._terms[source.id] = Counter(terms)

    def _load_logs(self, path: Path) -> None:
        relative = path.relative_to(self._root).as_posix()
        for number, line in enumerate(_read_lines(path), start=1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise ValueError("Expected a JSON object")
                timestamp = _required_text(data, "timestamp")
                service = _required_text(data, "service").strip()
                level = _required_text(data, "level").strip()
                message = _required_text(data, "message", allow_blank=True)
                event = None if data.get("event") is None else _required_text(data, "event", allow_blank=True)
                instant = parse_timestamp(timestamp)
            except ValueError as error:
                raise ValueError(f"{relative}:{number}: {error}") from error

            excerpt = f"{message}\nEvent: {event}" if event else message
            source = Source(
                id=f"{relative}:L{number}",
                kind="log",
                path=relative,
                line_start=number,
                line_end=number,
                text=excerpt,
                service=service,
                timestamp=timestamp,
                level=level,
                event=event,
            )
            self._logs[service].append((instant, source))
            self._index(source, _tokens(f"{level}\n{excerpt}"))

    def _load_runbook(self, path: Path) -> None:
        lines = _read_lines(path)
        relative = path.relative_to(self._root).as_posix()
        visible = list(markdown_text_lines(lines))
        headings = [index for index, line in visible if _SECTION.match(line)]
        preamble_end = headings[0] if headings else len(lines)
        preamble = [line for index, line in visible if index < preamble_end]
        services = [match.group(1).strip() for line in preamble if (match := _SERVICE.match(line))]
        if len(services) != 1 or not services[0]:
            raise ValueError(f"{relative}: expected one 'Service: <name>' line before the first section")
        service = services[0]

        preamble_has_guidance = any(
            line.strip() and not _SERVICE.match(line) and not _TITLE.match(line) for line in preamble
        )
        starts = ([0] if preamble_has_guidance else []) + headings
        for start, end in zip(starts, starts[1:] + [len(lines)]):
            while start < end and not lines[start].strip():
                start += 1
            while end > start and not lines[end - 1].strip():
                end -= 1
            anchor = f"L{start + 1}" if start + 1 == end else f"L{start + 1}-L{end}"
            source = Source(
                id=f"{relative}:{anchor}",
                kind="runbook",
                path=relative,
                line_start=start + 1,
                line_end=end,
                text="\n".join(lines[start:end]),
                service=service,
            )
            self._runbooks[service].append(source)
            self._index(source, _tokens(source.text))

    def _rank(self, candidates: list[Source], query: str, limit: int) -> list[Source]:
        if type(limit) is not int or limit < 1:
            raise ValueError("Search limit must be a positive integer")
        if not isinstance(query, str):
            raise ValueError("Search query must be text")
        if not query.strip():
            return candidates[:limit]
        query_terms = set(_tokens(query))
        if not candidates or not query_terms:
            return []

        term_counts = [self._terms[source.id] for source in candidates]
        lengths = [sum(counts.values()) for counts in term_counts]
        average_length = sum(lengths) / len(lengths) or 1.0
        document_frequency = Counter(
            term for counts in term_counts for term in query_terms.intersection(counts)
        )
        weights = {
            term: math.log1p((len(candidates) - count + 0.5) / (count + 0.5))
            for term, count in document_frequency.items()
        }
        ranked: list[tuple[float, Source]] = []
        for source, counts, length in zip(candidates, term_counts, lengths):
            norm = 1.2 * (0.25 + 0.75 * length / average_length)
            score = math.fsum(
                weights[term] * counts[term] * 2.2 / (counts[term] + norm)
                for term in sorted(query_terms.intersection(counts))
            )
            if score > 0:
                ranked.append((score, source))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [source for _, source in ranked[:limit]]


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").split("\n")
    except UnicodeError as error:
        raise ValueError(f"Evidence file must be UTF-8: {path}") from error


def _required_text(data: dict, key: str, *, allow_blank: bool = False) -> str:
    value = data.get(key)
    if not isinstance(value, str) or (not allow_blank and not value.strip()):
        requirement = "text" if allow_blank else "non-empty text"
        raise ValueError(f"{key} must be {requirement}")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"{key} contains invalid Unicode") from error
    return value


def _tokens(value: str) -> Iterator[str]:
    for token in _TOKEN.findall(value.casefold()):
        if token not in _STOP_WORDS:
            yield token
        if "_" in token or "-" in token:
            yield from (part for part in re.split(r"[_-]", token) if part not in _STOP_WORDS)


def markdown_text_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    """Yield zero-based line indexes and text outside fenced Markdown blocks."""
    fence = ""
    for index, line in enumerate(lines):
        match = _FENCE.match(line)
        if fence:
            if match and match.group(1).startswith(fence) and not match.group(2).strip():
                fence = ""
        elif match:
            fence = match.group(1)
        else:
            yield index, line
