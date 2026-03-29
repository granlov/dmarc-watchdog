# dmarc-watchdog

DMARC aggregate reports pile up unread. This tool reads them, flags anything unexpected, and stays quiet when everything is fine. No dashboard, no cloud dependency, runs locally on a schedule.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy and configure:

```bash
cp config/config.example.json config/config.YOUR-DOMAIN.json
cp config/allowlist.example.json config/allowlist.YOUR-DOMAIN.json
```

Run:

```bash
python -m dmarc_watchdog.cli --config config/config.YOUR-DOMAIN.json
```

## Scheduling (cron)

```cron
0 */3 * * * cd /path/to/dmarc-watchdog && .venv/bin/python -m dmarc_watchdog.cli --config config/config.YOUR-DOMAIN.json >> watchdog.log 2>&1
```

Runs every 3 hours. Automatically catches up from the last successful run — no reports are missed after a long absence. Each report is deduplicated by content hash so it is never processed twice.

## Public Repo Safety

Never commit real credentials or mail content. Sensitive files are gitignored by pattern:

- `config/config.*.json` — except `config.example.json`
- `config/allowlist.*.json` — except `allowlist.example.json`
- `state/`
- `samples/reports/`
