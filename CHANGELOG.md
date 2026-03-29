# Changelog

Alla viktiga ändringar i projektet dokumenteras här.

## [Unreleased]

## [1.1.0] - 2026-03-29

### Changed

- IMAP-ingest ignorerar nu unread/read-status och filtrerar istället på mailheaders (subject/from/to). Deduplicering via state-hash är fortsatt spärr mot dubletter.
- Konfigurationsfältet `searchCriterion` ersatt med `filterSubjectContains`, `filterFromContains` och `filterToContains` i `imap`-sektionen.
- Provider-mönster för rDNS-klassificering utbrutna till separat fil `config/providers.json` som kan spåras i git och delas mellan konfigurationer. Refereras via `providerPatternsFile` i `senderIdentity`.

### Added

- Inbyggda provider-mönster för Google, Microsoft och Apple.
- `.gitignore` täcker nu alla `config/config.*.json` och `config/allowlist.*.json` utom `*.example.json`, för att stödja namnkonvention per domän (t.ex. `config.reliefahead.com.json`).

## [1.0.0] - 2026-03-29

### Added

- MVP-skelett för dmarc-watchdog (CLI, ingest, parser, regler, state)
- Säkerhetsregler för publikt repo i README
- Exempelkonfiguration och lokal state-hantering

### Changed

- Allowlist hanteras nu som lokal otrackad fil (`config/allowlist.local.json`) med en checkad exempelmall (`config/allowlist.example.json`)
- Avsändare berikas nu med rDNS och provider-etikett, samt varning för oväntad provider
- Standardprovider-listan inkluderar nu one.com, shopify och aws ses
