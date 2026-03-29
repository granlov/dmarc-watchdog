# dmarc-watchdog

Lightweight DMARC aggregate report watchdog for a single technical user.

The MVP focuses on deterministic analysis, low noise, and near-zero cost:

- local execution
- no dashboard
- no cloud dependency
- alert only when something matters

## MVP Scope

Included:

- ingest DMARC report emails from IMAP, or from local files for safe dry runs
- extract XML from xml, gz, and zip attachments
- parse aggregate records (source IP, header_from, SPF, DKIM, disposition, count)
- detect anomalies with deterministic rules
- enrich sender IPs with reverse DNS and provider label for human-readable output
- maintain local state for deduplication and heartbeat proof-of-life
- print concise CLI output

Not included in MVP:

- web UI
- multi-user support
- AI/ML classification
- auto-learn allowlist
- external enrichment services (rDNS/ASN)

## Repository Safety Rules

This is a public repository. Never commit secrets or raw production mail content.

Rules:

1. Real credentials must live only in an untracked local file.
2. Commit only example config files.
3. Keep runtime state out of git.
4. Use anonymized samples for tests.
5. Self-review every commit for secret leakage.

Tracked files are safe examples:

- `config/config.example.json`
- `config/allowlist.example.json`

Ignored files include:

- `.env`
- `config/config.local.json`
- `config/allowlist.local.json`
- `state/`
- `samples/reports/`

## Branch Policy

`main` must always be production-ready at MVP level.

Workflow:

1. Create a feature branch.
2. Implement and self-review.
3. Merge to `main` only when green and stable.

## Project Layout

```text
dmarc_watchdog/
  cli.py
  config.py
  ingest.py
  dmarc_parser.py
  analyzer.py
  state_store.py
  runner.py
config/
  config.example.json
  allowlist.example.json
state/                  # generated locally
samples/reports/        # local test input, ignored by git
```

## Quick Start

1. Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

1. Dry run without mailbox credentials (recommended first):

```bash
python -m dmarc_watchdog.cli --config config/config.example.json
```

Default mode is `local-files`, reading from `samples/reports/`.

1. Move to IMAP integration only after local flow works:

- copy `config/config.example.json` to `config/config.local.json`
- copy `config/allowlist.example.json` to `config/allowlist.local.json`
- set `runtime.mode` to `imap`
- add IMAP credentials locally
- run with `--config config/config.local.json`

Credential timing:

- add mailbox credentials only in the final integration step, not during initial implementation

## Proof-of-Life

MVP uses passive proof-of-life:

1. CLI output shows run timestamp and status.
2. `state/state.json` stores `lastSuccessfulRunUtc` and `lastRunStatus`.
3. You inspect on demand.

No daily push notification is enabled by default in MVP.

## Sender Identity and Provider Guardrails

To reduce noisy IP-only output, each sender IP is enriched with:

- reverse DNS hostname (when resolvable)
- provider label based on hostname patterns

Default approved providers are:

- one.com
- shopify
- aws ses

If a sender does not match approved providers, the tool emits `Unexpected provider`.

You can tune patterns and approved providers in `senderIdentity` inside config.

## Cron Example

Run every day at 07:00:

```cron
0 7 * * * cd /path/to/dmarc-watchdog && /path/to/.venv/bin/python -m dmarc_watchdog.cli --config config/config.local.json >> watchdog.log 2>&1
```

## Current Status

Initial MVP skeleton is implemented:

- local/IMAP ingest
- attachment extraction
- XML parsing
- anomaly detection
- state persistence and heartbeat
- concise summary output

Next step is to validate against your mailbox test history and adjust allowlist/rules.
