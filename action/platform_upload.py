#!/usr/bin/env python3
"""POST the generated SBOM to the platform webhook (opt-in via --token).

When the scan also produced VEX documents (`aisbom scan --vex`), they are
uploaded alongside the SBOM in a single request. Exploitability statements
previously stayed on the runner, which meant the hosted inventory could never
show whether a finding was actually exploitable — the question the CRA and
FDA §524B ask about most directly.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping

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


def vex_paths_for(sbom_path: str) -> List[str]:
    """The VEX filenames `aisbom scan --vex` would have written for this SBOM.

    Mirrors ``aisbom.cli._vex_paths``. The two must agree exactly: if they
    drift, a plain `scan --vex` writes documents this helper never looks for
    and the exploitability data silently stops being uploaded — a failure with
    no error message anywhere.
    """
    stem = sbom_path[: -len(".json")] if sbom_path.endswith(".json") else sbom_path
    return [f"{stem}.openvex.json", f"{stem}.vex.cdx.json"]


def load_vex_documents(sbom_path: str) -> List[Dict[str, Any]]:
    """Read whichever VEX siblings exist next to the SBOM.

    Missing files are the normal case (the scan ran without ``--vex``). An
    unreadable or non-object file is skipped rather than raised on: the SBOM is
    what the user actually needs in their inventory, and failing the whole
    upload because a supplementary document is corrupt would cost them that
    entry to save a file the receiver would have ignored anyway.
    """
    documents: List[Dict[str, Any]] = []
    for path in vex_paths_for(sbom_path):
        if not Path(path).is_file():
            continue
        try:
            with open(path, "rb") as fh:
                parsed = json.loads(fh.read())
        except (OSError, ValueError):
            print(f"[aisbom-action] skipping unreadable VEX document: {path}")
            continue
        if isinstance(parsed, dict):
            documents.append(parsed)
        else:
            print(f"[aisbom-action] skipping VEX document that is not an object: {path}")
    return documents


def build_request_body(sbom_path: str, vex_documents: List[Dict[str, Any]] | None = None) -> bytes:
    """The bytes to POST: the SBOM alone, or an {sbom, vex} envelope.

    With no VEX documents the SBOM's own bytes are sent **verbatim**, so an
    upload from a repo that does not use ``--vex`` is byte-identical to what
    every previous release sent. Only when there is something extra to carry
    does the body become an envelope.

    If the SBOM cannot be parsed we send it raw as well. The SBOM is the
    document the receiver validates, and inventing an envelope around bytes we
    could not read would replace the receiver's specific rejection reason with
    a confusing one.
    """
    with open(sbom_path, "rb") as fh:
        raw = fh.read()

    # Accepted as an argument so a caller that already loaded the documents
    # (upload, which also logs the count) does not parse them a second time and
    # emit every "skipping unreadable document" warning twice.
    if vex_documents is None:
        vex_documents = load_vex_documents(sbom_path)
    if not vex_documents:
        return raw

    try:
        sbom = json.loads(raw)
    except ValueError:
        return raw
    if not isinstance(sbom, dict):
        return raw

    return json.dumps({"sbom": sbom, "vex": vex_documents}).encode("utf-8")


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
        vex_documents = load_vex_documents(sbom_path)
        payload = build_request_body(sbom_path, vex_documents)
        # Part of the same disclosure as the lines above: an opted-in user can
        # see from the log exactly how many documents left their runner, not
        # just that "an upload happened".
        print(f"[aisbom-action] vex-documents={len(vex_documents)}")
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
