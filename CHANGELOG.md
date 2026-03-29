# Changelog

Alla viktiga ändringar i projektet dokumenteras här.

## [Unreleased]

## [1.0.0] - 2026-03-29

### Added

- MVP-skelett för dmarc-watchdog (CLI, ingest, parser, regler, state)
- Säkerhetsregler för publikt repo i README
- Exempelkonfiguration och lokal state-hantering

### Changed

- Allowlist hanteras nu som lokal otrackad fil (`config/allowlist.local.json`) med en checkad exempelmall (`config/allowlist.example.json`)
- Avsändare berikas nu med rDNS och provider-etikett, samt varning för oväntad provider
- Standardprovider-listan inkluderar nu one.com, shopify och aws ses
