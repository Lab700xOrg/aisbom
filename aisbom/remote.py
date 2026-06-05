import os
from typing import List, Optional, Any, Dict
from urllib.parse import urlparse

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


class RemoteStream:
    """
    Minimal seekable, readable stream backed by HTTP Range requests.
    Supports read, seek, tell, and context manager usage.
    """

    def __init__(self, url: str, session: Optional[requests.Session] = None):
        self.url = url
        self.session = session or requests
        self.pos = 0
        self.size = self._fetch_size()

    def _fetch_size(self) -> int:
        # Use a range request to learn total size from Content-Range header
        headers = {"Range": "bytes=0-0"}
        headers.update(_auth_headers(self.url))
        resp = self.session.get(self.url, headers=headers)
        resp.raise_for_status()
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

        headers = {"Range": f"bytes={self.pos}-{end}"}
        headers.update(_auth_headers(self.url))
        resp = self.session.get(self.url, headers=headers)
        resp.raise_for_status()
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


def resolve_huggingface_repo(repo_id: str) -> List[str]:
    """
    Resolve a Hugging Face repo into a list of file URLs for supported model artifacts.
    Accepts repo ids with or without the hf:// prefix.
    """
    if repo_id.startswith("hf://"):
        repo_id = repo_id[len("hf://") :]

    api_url = f"https://huggingface.co/api/models/{repo_id}/tree/main"
    # Let fetch failures propagate (no broad swallow): a 401/403 on a
    # private/gated repo, a 404 typo, or a network error must surface to the
    # scanner as a real error with a status-aware hint — returning [] here is
    # what produced the silent "0 artifacts found" (#58). A successful 200 with
    # no supported files still returns [] below, which is correct.
    resp = requests.get(api_url, headers=_auth_headers(api_url))
    resp.raise_for_status()
    data = resp.json()

    supported_exts = (".pt", ".pth", ".bin", ".safetensors", ".gguf")
    urls = []
    for entry in data:
        path = entry.get("path", "")
        if any(path.endswith(ext) for ext in supported_exts):
            urls.append(f"https://huggingface.co/{repo_id}/resolve/main/{path}")

    return urls
