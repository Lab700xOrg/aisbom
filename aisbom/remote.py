import os
import re
from typing import List, Optional, Any, Dict
from urllib.parse import quote, unquote, urlparse

# Per ADR-0001: bearer credentials are sent only to this exact host. HF's
# resolve endpoint 302-redirects byte fetches to a presigned LFS CDN / S3 host;
# requests' default cross-host auth-stripping drops the header on that hop, so
# the token is validated at huggingface.co and never leaks to the CDN.
_HF_HOST = "huggingface.co"


def _hf_token() -> Optional[str]:
    """Read the HF access token from the environment only (ADR-0001).

    Matches huggingface_hub precedence: HF_TOKEN, then HUGGING_FACE_HUB_TOKEN.
    The cached ~/.cache/huggingface/token login file is deliberately not read.
    """
    return os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")


def _auth_headers(url: str) -> Dict[str, str]:
    """Per-request Authorization header, gated on an exact huggingface.co host match.

    Returns an empty dict when there is no token or the host is anything other
    than huggingface.co — the security guard that keeps the token off the CDN /
    S3 / arbitrary-mirror hosts.
    """
    token = _hf_token()
    if token and urlparse(url).hostname == _HF_HOST:
        return {"Authorization": f"Bearer {token}"}
    return {}


class _RequestsStub:
    class Session:
        pass

    def get(self, *args, **kwargs):
        raise ImportError("requests is required for remote operations")


try:
    import requests  # type: ignore
except ImportError:  # Fallback stub to allow offline/tests when requests missing
    requests = _RequestsStub()


# (connect, read) seconds for every request that decides what gets scanned:
# each file-listing page and each byte-range read. `requests` applies the read
# timeout per socket read, not to the whole response, so a slow but moving
# transfer is never cut off; only a connection that stops sending is. An honest
# 1,000-entry listing page answers in well under a second, so a minute of
# silence is a stall. Without any timeout a stalled HF API held a CI scan
# forever. Deliberately longer than the model-card cap below: that call is
# enrichment and is meant to give up first.
HF_REQUEST_TIMEOUT = (10, 60)


class RemoteStream:
    """
    Minimal seekable, readable stream backed by HTTP Range requests.
    Supports read, seek, tell, and context manager usage.

    ``fetch_error`` holds the first network failure a request raised. The
    inspectors catch every exception while parsing, so a stall part-way
    through a file would otherwise reach the scanner as "could not parse";
    the scanner reads this after inspection to report it as a fetch failure.
    """

    def __init__(self, url: str, session: Optional[requests.Session] = None):
        self.url = url
        self.session = session or requests
        self.pos = 0
        self.fetch_error: Optional[BaseException] = None
        self.size = self._fetch_size()

    def _get(self, range_header: str):
        headers = {"Range": range_header}
        headers.update(_auth_headers(self.url))
        try:
            resp = self.session.get(self.url, headers=headers, timeout=HF_REQUEST_TIMEOUT)
            resp.raise_for_status()
        except Exception as exc:
            if self.fetch_error is None:
                self.fetch_error = exc
            raise
        return resp

    def _fetch_size(self) -> int:
        # Use a range request to learn total size from Content-Range header
        resp = self._get("bytes=0-0")
        content_range = resp.headers.get("Content-Range")
        if content_range and "/" in content_range:
            try:
                return int(content_range.split("/")[-1])
            except ValueError:
                pass
        # Fallback to Content-Length if range is not honored
        if resp.headers.get("Content-Length"):
            return int(resp.headers["Content-Length"])
        # Unknown size; treat as zero to avoid infinite loops
        return 0

    def read(self, size: int = -1) -> bytes:
        if self.pos >= self.size:
            return b""

        if size is None or size < 0:
            end = self.size - 1
        else:
            end = min(self.pos + size - 1, self.size - 1)

        resp = self._get(f"bytes={self.pos}-{end}")
        data = resp.content
        self.pos += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self.pos + offset
        elif whence == 2:
            new_pos = self.size + offset
        else:
            raise ValueError("Invalid whence value")

        self.pos = max(0, min(new_pos, self.size))
        return self.pos

    def tell(self) -> int:
        return self.pos

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def close(self):
        # Nothing persistent to close; included for interface completeness
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def _supported_extensions() -> List[str]:
    """Every extension `DeepScanner` claims, read from the scanner itself.

    Kept as a derivation rather than a second list, because the two drifting
    apart is not a cosmetic problem: an extension the local walk scans and the
    remote resolver does not is a format that reports every `hf://` model clean.
    """
    from aisbom import scanner  # local: `scanner` imports this module

    return sorted(
        set(scanner.PYTORCH_EXTENSIONS)
        | set(scanner.KERAS_EXTENSIONS)
        | set(scanner.PICKLE_VARIANT_EXTENSIONS)
        | {scanner.SAFETENSORS_EXTENSION, scanner.GGUF_EXTENSION, scanner.ONNX_EXTENSION}
    )


# The tree API pages at 1,000 entries, so this reads up to ~100k entries.
# No real model repo comes close; the cap exists so a pathological listing
# cannot hold a scan forever. Hitting it is reported, never silent.
_HF_LISTING_MAX_PAGES = 100


class HFRepoListing(list):
    """The download URLs of a repo's supported model files.

    A plain list of URL strings, so callers that iterate it are unaffected,
    plus whether the listing stopped at the page cap with more pages left.
    A truncated listing means some files were never seen, and the scanner
    must say so instead of reporting the repo clean.
    """

    def __init__(self, urls=(), truncated: bool = False, pages_read: int = 0,
                 paths=()):
        super().__init__(urls)
        self.truncated = truncated
        self.pages_read = pages_read
        # Every file in the repo, scanned or not. A format that is identified
        # by a companion file (OpenVINO's `.xml` graph beside its `.bin`) is
        # checked against this, so a missing companion costs no request.
        self.paths = frozenset(paths)


def resolve_huggingface_repo(repo_id: str) -> HFRepoListing:
    """
    Resolve a Hugging Face repo into a list of file URLs for supported model artifacts.
    Accepts repo ids with or without the hf:// prefix.

    The listing is recursive and follows every page. Without both, files in
    subfolders (`onnx/`, `unet/`, `text_encoder/`, ...) were never fetched,
    and a repo whose weights all live in subfolders scanned as empty.
    """
    if repo_id.startswith("hf://"):
        repo_id = repo_id[len("hf://") :]

    # Derived from the scanner's own dispatch sets rather than restated here.
    # A format missing from this list is silently skipped for `hf://` scans — a
    # hostile model in that format passes a remote scan producing neither an
    # artifact nor an error — and a hand-maintained copy is exactly how that
    # happens. The import is function-local because `scanner` imports this
    # module, so a module-level one would be circular.
    supported_exts = tuple(_supported_extensions())

    url: Optional[str] = f"https://huggingface.co/api/models/{repo_id}/tree/main?recursive=true"
    urls: List[str] = []
    all_paths: List[str] = []
    pages_read = 0
    while url and pages_read < _HF_LISTING_MAX_PAGES:
        # Let fetch failures propagate (no broad swallow): a 401/403 on a
        # private/gated repo, a 404 typo, or a network error must surface to
        # the scanner as a real error with a status-aware hint — returning []
        # here is what produced the silent "0 artifacts found" (#58). This
        # holds for every page: a listing that fails halfway is not a smaller
        # repo. A successful listing with no supported files still returns
        # an empty list, which is correct.
        # A timeout raises like any other fetch failure: a stalled page is
        # not an empty one.
        resp = requests.get(url, headers=_auth_headers(url), timeout=HF_REQUEST_TIMEOUT)
        resp.raise_for_status()
        page = resp.json()
        if not isinstance(page, list):
            raise ValueError(f"Hugging Face file listing for {repo_id} was not a list")
        pages_read += 1

        for entry in page:
            if entry.get("type") == "directory":
                continue
            path = entry.get("path", "")
            if path:
                all_paths.append(path)
            if any(path.endswith(ext) for ext in supported_exts):
                urls.append(
                    f"https://huggingface.co/{repo_id}/resolve/main/{quote(path, safe='/')}"
                )

        url = ((getattr(resp, "links", None) or {}).get("next") or {}).get("url")
        # The token rides on every request to huggingface.co, so a next link
        # pointing anywhere else is refused rather than followed.
        if url and urlparse(url).hostname != _HF_HOST:
            raise ValueError(
                f"Hugging Face file listing for {repo_id} linked its next page "
                f"outside huggingface.co"
            )

    return HFRepoListing(urls, truncated=bool(url), pages_read=pages_read, paths=all_paths)


def hf_repo_relative_path(url: str, repo_id: str) -> Optional[str]:
    """The repo-relative path of a URL built by `resolve_huggingface_repo`, else None.

    Used as the component name for `hf://` artifacts, so two `model.onnx`
    files in different folders stay distinguishable. A file at the repo root
    yields its bare filename, which is the name it always had.

    Matches the exact prefix the resolver builds rather than searching the
    path for "resolve", which a repo can itself be named.
    """
    if repo_id.startswith("hf://"):
        repo_id = repo_id[len("hf://") :]
    prefix = f"https://huggingface.co/{repo_id}/resolve/main/"
    if not url.startswith(prefix):
        return None
    return unquote(url[len(prefix) :]) or None


_HF_WEB_HOSTS = frozenset({"huggingface.co", "www.huggingface.co", "hf.co", "www.hf.co"})

# First path segments of huggingface.co pages that are not `<owner>/<repo>`.
_HF_NON_REPO_ROOTS = frozenset({
    "api", "blog", "chat", "collections", "docs", "enterprise", "join",
    "learn", "login", "models", "new", "organizations", "papers", "posts",
    "pricing", "search", "settings", "tasks",
})


def rewrite_hf_web_url(target: str):
    """Map a huggingface.co *web page* URL onto something the scanner can read.

    Returns ``(new_target, problem)``:

    * ``(None, None)``: not an HF page URL (an ``hf://`` slug, a local path,
      another host, or a ``/resolve/`` file URL that already works). Leave it.
    * ``(new_target, None)``: an exact equivalent. A repo page or its
      ``tree/main`` root is the whole repo at main, which is what ``hf://``
      reads. A ``blob/<rev>/<path>`` page is that file at that revision, which
      is what the same URL with ``resolve`` in place of ``blob`` serves.
    * ``(None, problem)``: an HF page with no exact equivalent. A branch or
      subfolder tree is a different set of files from "every file at main",
      so following it as the repo would scan something the user did not
      name. ``problem`` says what to pass instead.

    Before this, every one of these URLs found no file, reported no error and
    exited 0, which is a false all-clear.
    """
    if not isinstance(target, str) or not target.startswith(("http://", "https://")):
        return None, None
    parsed = urlparse(target)
    if (parsed.hostname or "").lower() not in _HF_WEB_HOSTS:
        return None, None

    parts = [p for p in parsed.path.split("/") if p]
    if parts and parts[0] in ("datasets", "spaces"):
        kind = parts[0][:-1]
        return None, (
            f"{target} is a Hugging Face {kind} page; aisbom scans model repos "
            "only. Pass a model repo as hf://<owner>/<repo>."
        )
    if (
        len(parts) < 2
        or parts[0] in _HF_NON_REPO_ROOTS
        or not all(_REPO_SEGMENT_RE.match(s) for s in parts[:2])
    ):
        return None, (
            f"{target} is not a Hugging Face model repo page. Pass a model "
            "repo as hf://<owner>/<repo>, or a file's /resolve/ URL."
        )

    repo = f"{parts[0]}/{parts[1]}"
    rest = parts[2:]
    if not rest or rest == ["tree", "main"]:
        return f"hf://{repo}", None
    if rest[0] == "resolve":
        return None, None
    if rest[0] == "blob" and len(rest) >= 3:
        # Swap the one segment and keep the rest of the path byte-for-byte,
        # percent-encoding included. The host is normalised so the token
        # gate (exact huggingface.co match) still applies.
        return f"https://{_HF_HOST}/{repo}/resolve/{'/'.join(rest[1:])}", None
    return None, (
        f"{target} is a Hugging Face page that cannot be scanned exactly: an "
        "hf:// target reads every file in a repo at main, not a branch or a "
        f"subfolder. Scan the whole repo with hf://{repo}, or pass a file's "
        "/resolve/ URL."
    )


# The model-card fetch is deliberately capped well below the file-listing
# timeout: it is enrichment, not the scan, and a slow HF API must never be
# what makes a CI scan hang.
_MODEL_CARD_TIMEOUT_SECONDS = 10


_REPO_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# Enough for any real repo's listing (the API pages at 1,000 entries) while
# bounding how long a pathological repo can hold up a best-effort lookup.
_FILE_INDEX_MAX_PAGES = 20


def _api_repo_path(repo_id: str, revision: Optional[str]) -> Optional[str]:
    """Validated ``<repo_id>`` for an API URL, or None if either part is malformed.

    The metadata calls build URLs from ids that local-file matching reads out
    of files on disk, so anything that is not plainly a repo id and a commit
    is refused before it can become part of a request.
    """
    if repo_id.startswith("hf://"):
        repo_id = repo_id[len("hf://") :]
    repo_id = repo_id.strip("/")
    segments = repo_id.split("/")
    if not 1 <= len(segments) <= 2:
        return None
    if not all(_REPO_SEGMENT_RE.match(s) and ".." not in s for s in segments):
        return None
    if revision is not None and not _COMMIT_RE.match(revision):
        return None
    return repo_id


def fetch_huggingface_file_index(
    repo_id: str, revision: Optional[str] = None
) -> Optional[List[Dict[str, Any]]]:
    """Every file entry in a repo at a revision, from the HF tree API. Best-effort.

    Used to prove a local file came from a repo: entries carry the git blob
    ``oid`` and, for LFS files, ``lfs.oid`` (the file's SHA-256). Failures of
    any kind return None, under the same contract as
    :func:`fetch_huggingface_model_card` — this call only decides whether a
    local component gets a ``modelCard``.
    """
    repo_path = _api_repo_path(repo_id, revision)
    if repo_path is None:
        return None

    url: Optional[str] = (
        f"https://huggingface.co/api/models/{repo_path}/tree/{revision or 'main'}?recursive=true"
    )
    entries: List[Dict[str, Any]] = []
    try:
        for _ in range(_FILE_INDEX_MAX_PAGES):
            resp = requests.get(url, headers=_auth_headers(url), timeout=_MODEL_CARD_TIMEOUT_SECONDS)
            resp.raise_for_status()
            page = resp.json()
            if not isinstance(page, list):
                return None
            entries.extend(page)
            url = ((getattr(resp, "links", None) or {}).get("next") or {}).get("url")
            if not url:
                return entries
            # The token rides on every request to huggingface.co, so a next
            # link pointing anywhere else is not followed.
            if urlparse(url).hostname != _HF_HOST:
                return None
    except Exception:
        return None
    # Page cap reached: a partial listing could fail to prove a real match but
    # can never prove a false one, so it is still usable.
    return entries


def fetch_huggingface_model_card(
    repo_id: str, revision: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Fetch a repo's model-card metadata from the HF API. Best-effort.

    Unlike :func:`resolve_huggingface_repo`, every failure here is swallowed and
    returns ``None``. That asymmetry is intentional and is the whole contract:
    the file listing decides *what gets scanned*, so losing it silently would
    hide a malicious model (#58). This call only decides whether the SBOM
    carries a richer ``modelCard`` block. A gated repo, a rate limit, an API
    outage, or a network blip must degrade to an SBOM without that block —
    never to a failed scan or a new exit code. Callers get ``None`` and omit
    the field.

    Returns the raw API payload (``cardData``, ``config``, ``pipeline_tag``,
    ``tags``, ``sha`` …) so mapping stays in :mod:`aisbom.modelcard`.

    ``revision`` pins the card to a commit, for a local file matched at the
    revision its HF cache snapshot names; without it the card is ``main``'s.
    """
    repo_path = _api_repo_path(repo_id, revision)
    if repo_path is None:
        return None

    api_url = f"https://huggingface.co/api/models/{repo_path}"
    if revision:
        api_url += f"/revision/{revision}"
    try:
        resp = requests.get(
            api_url,
            headers=_auth_headers(api_url),
            timeout=_MODEL_CARD_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None

    # A 200 that isn't a JSON object (HTML error page, proxy interstitial) is
    # as useless as a failure and must not reach the mapper as, say, a list.
    return data if isinstance(data, dict) else None
