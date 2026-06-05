# Changelog

## Unreleased

## 1.1.0 — 2026-06-05

- Scan private and gated Hugging Face models by setting `HF_TOKEN` / `HUGGING_FACE_HUB_TOKEN`; the token is sent only to `huggingface.co` and is never logged or included in telemetry.
- Remote fetch failures (auth, network, not found) now print a clear, status-aware message with no traceback and exit non-zero, instead of silently reporting zero artifacts.
- `cli_error` telemetry now includes an `http_status` bucket and a `token_present` boolean (never the token value).
- Add optional `token` / `platform-url` / `fail-on-platform-error` inputs for posting SBOM to an external dashboard (private early access).
- Action upload now includes the scanned branch/tag (`GITHUB_REF_NAME`) so the dashboard can attribute results to the right ref.
