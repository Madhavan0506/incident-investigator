# Evidence-Grounded Agent for Incident Investigation

This Python CLI investigates a service incident from local application logs and Markdown runbooks. It produces a draft with file and line citations, then requires a reviewer to approve that exact draft before export. The default investigator runs offline on Python 3.9+ with the standard library.

## Run offline by default

Run these commands from the project directory. The default uses local rules and requires only Python 3.9 or newer.

```sh
python3 -m incident_agent draft --corpus demo/corpus --case demo/cases/checkout-db.json
python3 -m incident_agent evaluate --corpus demo/corpus --cases demo/cases
```

Review the diagnosis, quoted evidence and suggested action. Copy the draft ID and SHA-256 digest displayed at the top of the report. Set the shell variables below to those values and your reviewer name.

```sh
DRAFT_ID='paste the draft ID'
DIGEST='paste the draft SHA-256 digest'
REVIEWER='your name'

python3 -m incident_agent show "$DRAFT_ID"
python3 -m incident_agent approve "$DRAFT_ID" --digest "$DIGEST" --reviewer "$REVIEWER"
python3 -m incident_agent export "$DRAFT_ID" > incident-report.md
```

Use `reject` with the same arguments to record a rejection. Each decision is final for that draft. Run `draft` again after correcting inputs. The `show --json` command includes the tool audit and full source snapshots. The default review database is `.incidents.sqlite3`. Use `--db PATH` before the subcommand to select a different database. The reviewer name is self-entered and access is governed by local filesystem permissions.

## Use your own evidence

Place UTF-8 `*.jsonl` files in `logs/` and UTF-8 `*.md` files in `runbooks/` under a corpus directory. Each JSONL record needs `timestamp`, `service`, `level` and `message` strings. Prefer an `event` field for a machine-generated event code. When `event` is absent or empty, the first token of `message` can serve as the event code, with an optional trailing colon. Event codes are case-sensitive.

```json
{"timestamp":"2026-01-15T09:00:00Z","service":"checkout","level":"ERROR","event":"DB_POOL_EXHAUSTED","message":"Connection pool has zero idle connections."}
```

Each runbook declares one `Service:` before its `##` sections. Within a diagnostic section, use three plain metadata lines. A section can also contain ordinary operational guidance.

```markdown
# Checkout incident runbook

Service: checkout

## Database connection pool

Diagnosis: Checkout database connection pool saturation
Signals: DB_POOL_EXHAUSTED, DB_ACQUIRE_TIMEOUT
Next step: Review connection checkout durations with the database on-call.
```

The case JSON supplies the service and an inclusive time window. Both timestamps need an RFC 3339 UTC offset, such as `Z` or `+01:00`.

```json
{
  "id": "checkout-db",
  "service": "checkout",
  "symptom": "Checkout returned HTTP 503 while acquiring database connections.",
  "start": "2026-01-15T09:00:00Z",
  "end": "2026-01-15T09:06:00Z"
}
```

The verifier checks every diagnostic section for the service against the scoped logs. A supported diagnosis needs each required event code and one distinct corroborated diagnosis. Incomplete or competing evidence yields an unresolved report. The draft records the matched excerpts and the runbook's advisory next step for human review. The investigator has read-only access to evidence and no remediation or publishing tools.

## Opt in to Ollama tool calling

Install Ollama, then start the server on loopback with cloud features disabled. The tested setup used Ollama 0.40.17 and the free Qwen3 4B Instruct model. The adapter checks for native tool support and explicit `:local` model references. [Ollama installation](https://ollama.com/download) · [Ollama cloud controls](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features) · [Qwen3 4B Instruct](https://ollama.com/library/qwen3:4b-instruct)

```sh
OLLAMA_HOST=127.0.0.1:11434 OLLAMA_NO_CLOUD=1 ollama serve
```

For an existing workspace-local installation, start the server from the project directory with `OLLAMA_HOST=127.0.0.1:11434 OLLAMA_NO_CLOUD=1 OLLAMA_MODELS="$PWD/.ollama-local/models" .ollama-local/bin/ollama serve`. Use `.ollama-local/bin/ollama` for the pull command if the CLI is outside your `PATH`.

In a second terminal, download the model once and run either command from the project directory.

```sh
OLLAMA_HOST=127.0.0.1:11434 ollama pull qwen3:4b-instruct
python3 -m incident_agent draft --corpus demo/corpus --case demo/cases/checkout-db.json --ollama-model qwen3:4b-instruct
python3 -m incident_agent evaluate --corpus demo/corpus --cases demo/cases --ollama-model qwen3:4b-instruct
```

The model retrieves ranked log records and runbook sections through two scoped search tools. The verifier checks the model's selection against both the retrieved citations and the complete set of matched diagnostic rules. Approval stays in the review CLI. The application has no model download path or paid API integration.

## Verified results

Both modes ran the same seven synthetic cases on an Apple M2 Mac. The fixtures cover four supported diagnoses and three cases where the investigator should abstain.

| Metric | Offline rules (default) | Ollama with Qwen3 4B Instruct |
| --- | ---: | ---: |
| Correct diagnosis or abstention | 7/7 | 7/7 |
| Evidence support checks | 7/7 | 7/7 |
| Tool permission probes | 13/13 | 13/13 |
| Median investigation latency | 0.086 ms | 5.98 s |
| p95 investigation latency | 0.191 ms | 13.46 s |
| Paid API cost per case | $0.00 | $0.00 |

The Ollama run made 18 successful live search tool calls. Timings cover investigation after corpus indexing and vary with hardware and model warm-up. Paid API cost excludes local computing costs. These synthetic results measure behavior on the supplied fixtures.

## Run the automated checks

```sh
python3 -m unittest discover -s tests -v
```

All 16 automated tests passed. They cover the approval gate, citation checks, tool scope, and the model protocol with simulated responses. To score your own fixtures, add an `expected` object with `diagnosis` and `signals` to each case. Use a `null` diagnosis with an empty signal list for expected abstention.
