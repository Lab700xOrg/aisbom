# HuggingFace token auth, scoped to the huggingface.co host

**Status:** accepted

To let users scan private and gated HuggingFace models (the dominant source of
CI/CD `HTTPError` failures), the CLI reads an access token from the environment
and sends it as a bearer credential. Because this means transmitting a
credential to a third party, we constrain it tightly:

- **Opt-in via environment only.** The token is read from `HF_TOKEN`, falling
  back to `HUGGING_FACE_HUB_TOKEN` (matching `huggingface_hub` precedence). We
  deliberately do **not** read the cached `~/.cache/huggingface/token` login
  file — silently using a developer's stored credentials is surprising, and the
  CI use case injects env vars anyway.
- **Sent only to `huggingface.co`.** The `Authorization` header is attached
  per-request, gated on an exact host match (`hostname == "huggingface.co"`).
  HF's `resolve` endpoint 302-redirects byte fetches to a presigned LFS CDN
  host; we rely on `requests`' default cross-host auth-stripping so the token
  is validated at `huggingface.co` and never leaks to the CDN, S3, or any
  arbitrary mirror. We do not set `Session.auth` or override `rebuild_auth`.
- **Never logged or sent to telemetry.** Only a `token_present` boolean and the
  bucketed `http_status` are emitted with `cli_error` — never the token value,
  URL, or repo id.

## Considered alternatives

- **Diagnostic-only (no auth):** catch the `HTTPError` and fail gracefully but
  leave private/gated models unscannable. Rejected — making those scans *work*
  is the actual product value behind the CI failures.
- **Offline pre-flight credential check:** fail early if a private model is
  scanned without a token. Rejected — repository privateness is not knowable
  offline; detecting it requires the very network call that fails. Handling is
  therefore reactive (status-aware messages on 401/403), not pre-flight.

## Consequences

The host restriction means generic `https://` URLs to non-HF hosts are always
fetched unauthenticated. If we later support other authenticated registries,
each needs its own explicit host-scoped credential rule — there is no generic
"send my token to any URL" path, by design.
