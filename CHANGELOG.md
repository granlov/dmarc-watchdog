# Changelog

Alla viktiga ändringar i projektet dokumenteras här.

## [Unreleased]

## [1.6.0] - 2026-07-16

### Added (1.6.0)

- Weekly Discord heartbeat: a "Weekly status" summary (records parsed, runs, anomaly counts) posts every 7 days even when nothing is wrong, so a silent channel always means "all clear" — not "webhook is broken". Toggle independently via `discord.heartbeatEnabled`.
- Config now carries an explicit `domain` field, shown on both anomaly alerts and the heartbeat instead of a generic placeholder.

### Fixed (1.6.0)

- Discord alerts were silently failing with `HTTP 403 Forbidden` because outgoing requests had no `User-Agent` header, which Discord's edge began rejecting. Added one.

## [1.5.0] - 2026-05-05

### Added (1.5.0)

- Discord-integration: anomalier postas som embeds till en Discord-webhook. Varje anomali får färg efter risknivå (röd/gul/grön), fält för domain, risk, meddelandeantal, detaljer, rekommendation, förklaring och bevis.
- Ny `DiscordConfig`-dataclass med `enabled` och `webhookUrl`. Konfigureras under `discord`-nyckeln i config-JSON.

## [1.4.1] - 2026-05-04

### Changed (1.4.1)

- Added Klaviyo (`klaviyomail.com`, `klaviyodns.com`) as a recognized provider in `providers.json`.
- Kept Mailbaby in `providers.json` for identification purposes; removed from `approvedProviders` in reliefahead.com config.

## [1.4.0] - 2026-03-29

### Added (1.4.0)

- IP-level guidance enrichment for anomalies: risk level, confidence, provider, rDNS, auth summary, and recommended action.
- New explanation module (`dmarc_watchdog/anomaly_explainer.py`) that classifies likely-legitimate vs investigate-now cases using existing signals (rDNS, provider, SPF/DKIM, allowlist).

### Changed (1.4.0)

- CLI and email output now present anomalies as readable 3-line blocks with header, `Info`, and `Action`.
- Risk scoring for `Unexpected provider` now avoids over-escalating known-provider redirects while keeping true SPF/DKIM/alignment problems high.
- `Info` now shows auth summaries like `SPF fail, DKIM pass` to explain score differences between similar IPs.

## [1.3.0] - 2026-03-29

### Added (1.3.0)

- Email alerts: when anomalies are detected, send notification to configured email addresses via SMTP. Enable in `alerts.enabled` with SMTP credentials.
- Alert configuration in `alerts` section of config: `smtpHost`, `smtpPort`, `smtpUsername`, `smtpPassword`, `fromAddress`, `toAddresses`.

## [1.2.0] - 2026-03-29

### Changed (1.2.0)

- IMAP fetch now automatically catches up from the last successful run instead of using a fixed lookback window. First run still uses `lookbackHours` if available, but now fetches ALL messages by default. No reports are missed after long absences (vacation, machine off).
- Removed `lookbackHours` configuration field — no longer needed for IMAP mode.
- Simplified README: now focuses on setup, scheduling, and why the tool exists.

### Fixed (1.2.0)

- Date-only IMAP `SINCE` query provides ~24h natural overlap for email send delays, so no additional overlap configuration needed.

## [1.1.0] - 2026-03-29

### Changed (1.1.0)

- IMAP-ingest ignorerar nu unread/read-status och filtrerar istället på mailheaders (subject/from/to). Deduplicering via state-hash är fortsatt spärr mot dubletter.
- Konfigurationsfältet `searchCriterion` ersatt med `filterSubjectContains`, `filterFromContains` och `filterToContains` i `imap`-sektionen.
- Provider-mönster för rDNS-klassificering utbrutna till separat fil `config/providers.json` som kan spåras i git och delas mellan konfigurationer. Refereras via `providerPatternsFile` i `senderIdentity`.

### Added (1.1.0)

- Inbyggda provider-mönster för Google, Microsoft och Apple.
- `.gitignore` täcker nu alla `config/config.*.json` och `config/allowlist.*.json` utom `*.example.json`, för att stödja namnkonvention per domän (t.ex. `config.reliefahead.com.json`).

## [1.0.0] - 2026-03-29

### Added (1.0.0)

- MVP-skelett för dmarc-watchdog (CLI, ingest, parser, regler, state)
- Säkerhetsregler för publikt repo i README
- Exempelkonfiguration och lokal state-hantering

### Changed (1.0.0)

- Allowlist hanteras nu som lokal otrackad fil (`config/allowlist.local.json`) med en checkad exempelmall (`config/allowlist.example.json`)
- Avsändare berikas nu med rDNS och provider-etikett, samt varning för oväntad provider
- Standardprovider-listan inkluderar nu one.com, shopify och aws ses
