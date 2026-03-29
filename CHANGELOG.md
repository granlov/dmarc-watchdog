# Changelog

Alla viktiga ändringar i projektet dokumenteras här.

## [Unreleased]

### Added (Unreleased)

- IP-level guidance enrichment for anomalies: risk level, confidence, evidence, and recommended action.
- New explanation module (`dmarc_watchdog/anomaly_explainer.py`) that classifies likely-legitimate vs investigate-now cases using existing signals (rDNS, provider, SPF/DKIM, allowlist).

### Changed (Unreleased)

- CLI and email alert output now include guidance context (`Why`, `Evidence`, `Action`) for each anomaly.

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
