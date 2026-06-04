#!/usr/bin/env python3
"""POST the generated SBOM to the platform webhook (opt-in via --token)."""
from __future__ import annotations

import argparse
import os
import sys
from typing import Mapping

import requests

DEFAULT_PLATFORM_URL = "https://app.aisbom.io"
WEBHOOK_PATH = "/v1/scan-result"
REQUEST_TIMEOUT_SEC = 15.0

EXIT_OK = 0
EXIT_UPLOAD_FAILED = 3


def normalize_platform_url(url: str | None) -> str:
    if not url or not url.strip():
        return DEFAULT_PLATFORM_URL
    return url.strip().rstrip("/")


def compute_run_id(env: Mapping[str, str]) -> str:
    run_id = env.get("GITHUB_RUN_ID") or "unknown"
    attempt = env.get("GITHUB_RUN_ATTEMPT") or "1"
    return f"{run_id}-{attempt}"


def compute_ref(env: Mapping[str, str]) -> str | None:
    """The branch/tag actually scanned, sourced from GITHUB_REF_NAME.

    Returns None when unset or blank so callers can omit the header entirely
    rather than send an empty string (mirrors compute_run_id's env sourcing).
    """
    ref = (env.get("GITHUB_REF_NAME") or "").strip()
    return ref or None


def summarize_response(status: int, body: str) -> str:
    snippet = (body or "")[:400]
    return f"status={status} body={snippet!r}"


def upload(
    *,
    sbom_path: str,
    token: str,
    platform_url: str,
    trigger: str,
    fail_on_error: bool,
    env: Mapping[str, str],
) -> int:
    # Empty token = user didn't opt in. Caller should already have gated this,
    # but defend in depth so the helper is safe to invoke unconditionally.
    if not token:
        return EXIT_OK

    base = normalize_platform_url(platform_url)
    url = f"{base}{WEBHOOK_PATH}"
    run_id = compute_run_id(env)
    ref = compute_ref(env)

    # Loud, neutral log group — opted-in users see exactly where the data goes
    # and how to turn it off.
    print("::group::aisbom platform upload")
    print(f"[aisbom-action] POST {url}")
    print(f"[aisbom-action] trigger={trigger} run-id={run_id} ref={ref or '-'}")
    print("[aisbom-action] To disable, unset AISBOM_TOKEN in the repo secrets.")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Aisbom-Trigger": trigger,
        "X-Aisbom-Run-Id": run_id,
    }
    # Only send the ref when we actually know it — an empty header would be a
    # lie the receiver can't distinguish from "real branch named ''".
    if ref:
        headers["X-Aisbom-Ref"] = ref

    try:
        with open(sbom_path, "rb") as fh:
            payload = fh.read()
        resp = requests.post(
            url,
            data=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SEC,
        )
    except (requests.RequestException, OSError) as exc:
        print(f"[aisbom-action] upload failed: {type(exc).__name__}: {exc}")
        print("::endgroup::")
        return EXIT_UPLOAD_FAILED if fail_on_error else EXIT_OK

    print(f"[aisbom-action] {summarize_response(resp.status_code, resp.text)}")
    print("::endgroup::")

    if 200 <= resp.status_code < 300:
        return EXIT_OK
    return EXIT_UPLOAD_FAILED if fail_on_error else EXIT_OK


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sbom", required=True, help="Path to the SBOM JSON file")
    p.add_argument("--token", default="", help="Bearer token (empty = skip)")
    p.add_argument("--platform-url", default="", help="Override platform base URL")
    p.add_argument("--trigger", default="unknown",
                   help="GitHub event name (push, pull_request, ...)")
    p.add_argument("--fail-on-error", action="store_true",
                   help="Exit 3 on upload failure instead of best-effort 0")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return upload(
        sbom_path=args.sbom,
        token=args.token,
        platform_url=args.platform_url,
        trigger=args.trigger,
        fail_on_error=args.fail_on_error,
        env=os.environ,
    )


if __name__ == "__main__":
    sys.exit(main())
