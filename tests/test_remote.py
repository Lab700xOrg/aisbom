import json
from pathlib import Path

import pytest

from aisbom.remote import RemoteStream, resolve_huggingface_repo
from aisbom.scanner import DeepScanner


def _mock_response(content: bytes, status=206, headers=None):
    class Resp:
        def __init__(self):
            self.content = content
            self.status_code = status
            self.headers = headers or {}

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception("http error")

        def json(self):
            return json.loads(self.content.decode())

    return Resp()


def test_remote_stream_read_and_seek(monkeypatch):
    data = b"HelloRemoteWorld"

    def fake_get(url, headers=None):
        rng = headers.get("Range", "bytes=0-0")
        # Parse bytes=start-end
        start_end = rng.split("=")[1]
        start, end = start_end.split("-")
        start = int(start)
        end = int(end) if end else len(data) - 1
        slice_bytes = data[start : end + 1]
        hdrs = {"Content-Range": f"bytes {start}-{end}/{len(data)}", "Content-Length": str(len(slice_bytes))}
        return _mock_response(slice_bytes, headers=hdrs)

    import aisbom.remote as remote
    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)

    stream = RemoteStream("http://example.com/file")
    assert stream.size == len(data)
    assert stream.read(5) == b"Hello"
    stream.seek(-5, 2)
    assert stream.read() == b"World"


def test_resolve_huggingface_repo(monkeypatch):
    tree = [
        {"path": "model.pt", "type": "file"},
        {"path": "README.md", "type": "file"},
        {"path": "weights.gguf", "type": "file"},
    ]

    def fake_get(url, headers=None):
        return _mock_response(json.dumps(tree).encode(), status=200)

    import aisbom.remote as remote
    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)
    urls = resolve_huggingface_repo("org/model")
    assert "https://huggingface.co/org/model/resolve/main/model.pt" in urls
    assert "https://huggingface.co/org/model/resolve/main/weights.gguf" in urls


def test_remote_scanner_detects_pickle_threat(monkeypatch, tmp_path):
    import zipfile
    import pickle
    from aisbom.mock_generator import MockExploitPayload

    payload = pickle.dumps(MockExploitPayload(), protocol=2)
    zip_bytes = Path(tmp_path / "remote.pt")
    with zipfile.ZipFile(zip_bytes, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/data.pkl", payload)
        zf.writestr("archive/version", "3")
    content = zip_bytes.read_bytes()

    def fake_get(url, headers=None):
        rng = headers.get("Range", "bytes=0-0")
        start_end = rng.split("=")[1]
        start, end = start_end.split("-")
        start = int(start)
        end = int(end) if end else len(content) - 1
        slice_bytes = content[start : end + 1]
        hdrs = {"Content-Range": f"bytes {start}-{end}/{len(content)}", "Content-Length": str(len(slice_bytes))}
        return _mock_response(slice_bytes, headers=hdrs)

    import aisbom.remote as remote
    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)
    urls = ["http://example.com/remote.pt"]
    monkeypatch.setattr("aisbom.scanner.DeepScanner._resolve_remote_targets", lambda self, t: urls)

    results = DeepScanner("http://example.com/remote.pt").scan()
    assert results["artifacts"][0]["risk_level"].startswith("CRITICAL")


# --- HF token auth (ADR-0001) ---

import aisbom.remote as remote


def test_auth_headers_attached_only_for_huggingface_host(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "secret-tok")
    # Exact HF host -> header present
    hf = remote._auth_headers("https://huggingface.co/org/model/resolve/main/model.pt")
    assert hf["Authorization"] == "Bearer secret-tok"
    # CDN / presigned LFS host -> NO header (the 302 redirect target)
    assert remote._auth_headers("https://cdn-lfs.huggingface.co/repos/x/y") == {}
    assert remote._auth_headers("https://abc.s3.amazonaws.com/blob") == {}
    # Arbitrary mirror / non-HF host -> NO header
    assert remote._auth_headers("https://example.com/model.pt") == {}


def test_auth_headers_token_precedence_and_env_only(monkeypatch):
    # HF_TOKEN wins over HUGGING_FACE_HUB_TOKEN
    monkeypatch.setenv("HF_TOKEN", "primary")
    monkeypatch.setenv("HUGGING_FACE_HUB_TOKEN", "fallback")
    assert remote._hf_token() == "primary"
    # Fallback when HF_TOKEN absent
    monkeypatch.delenv("HF_TOKEN", raising=False)
    assert remote._hf_token() == "fallback"
    # Neither -> no token, no header even on HF host
    monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
    assert remote._hf_token() is None
    assert remote._auth_headers("https://huggingface.co/org/model/resolve/main/x.pt") == {}


def test_remote_stream_sends_bearer_per_request_to_hf(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "secret-tok")
    data = b"HelloRemoteWorld"
    seen_headers = []

    def fake_get(url, headers=None):
        seen_headers.append(headers or {})
        rng = (headers or {}).get("Range", "bytes=0-0")
        start_end = rng.split("=")[1]
        start, end = start_end.split("-")
        start = int(start)
        end = int(end) if end else len(data) - 1
        slice_bytes = data[start : end + 1]
        hdrs = {"Content-Range": f"bytes {start}-{end}/{len(data)}", "Content-Length": str(len(slice_bytes))}
        return _mock_response(slice_bytes, headers=hdrs)

    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)

    url = "https://huggingface.co/org/model/resolve/main/model.pt"
    stream = RemoteStream(url)
    stream.read(5)
    # Header attached per-request on the size probe + the read
    assert len(seen_headers) >= 2
    for h in seen_headers:
        assert h.get("Authorization") == "Bearer secret-tok"
        assert "Range" in h  # auth is merged with the per-request Range header


def test_remote_stream_no_bearer_on_non_hf_host(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "secret-tok")
    data = b"data"
    seen_headers = []

    def fake_get(url, headers=None):
        seen_headers.append(headers or {})
        rng = (headers or {}).get("Range", "bytes=0-0")
        start_end = rng.split("=")[1]
        start, end = start_end.split("-")
        start = int(start)
        end = int(end) if end else len(data) - 1
        slice_bytes = data[start : end + 1]
        hdrs = {"Content-Range": f"bytes {start}-{end}/{len(data)}", "Content-Length": str(len(slice_bytes))}
        return _mock_response(slice_bytes, headers=hdrs)

    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)

    RemoteStream("https://cdn-lfs.huggingface.co/blob").read(2)
    for h in seen_headers:
        assert "Authorization" not in h


def test_resolve_huggingface_repo_sends_bearer(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "secret-tok")
    tree = [{"path": "model.pt", "type": "file"}]
    seen_headers = []

    def fake_get(url, headers=None):
        seen_headers.append(headers or {})
        return _mock_response(json.dumps(tree).encode(), status=200)

    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)
    resolve_huggingface_repo("org/model")
    assert seen_headers and seen_headers[0].get("Authorization") == "Bearer secret-tok"
