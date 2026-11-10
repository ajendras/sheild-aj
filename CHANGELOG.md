# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-08

### Added

- Signature Validation — Constant-time HMAC-SHA256, RSA-PSS and Ed25519 verification with pluggable validators.
- Replay Protection — Timestamp + nonce checks backed by PSR-6 cache to block duplicate deliveries.
- Rate Limiting — Per-origin sliding-window limits using Redis or file cache adapters.
- Event Router — Maps validated event types to callables or Laravel/Symfony listeners.
- Audit Logging — Structured, redacted logs of every attempt via PSR-3 logger.
- Threat Detector — Runs configurable rules (IP blocklist, payload size, schema) on every request.
- Test CLI — Simulates legitimate and malicious webhooks for local testing.
- Framework Adapters — PSR-7 middleware plus Laravel service provider and Symfony bundle.
