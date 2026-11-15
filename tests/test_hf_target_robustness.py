"""Remote targets that used to end in a false all-clear.

Two shapes of the same failure, both on a security tool's flagship path:

* A stalled Hugging Face API (listing or byte range) hung a CI scan forever,
  because no request carried a timeout. A stall must now surface as a fetch
  error (exit 1) with a message that says it timed out, including when it
  happens part-way through reading a file, where the inspectors' broad
  exception handlers used to turn it into a parse error.
* A URL that no inspector claims (a Hugging Face *web page*, a `.zip`, a URL
  whose query string hid the extension) found nothing and exited 0. HF page
  URLs that map exactly onto something scannable are rewritten; the rest are
  refused with the form to use instead.
"""

import io
import json
import struct

import pytest
import requests as _requests
from typer.testing import CliRunner

import aisbom.remote as remote
import aisbom.scanner as scanner_module
from aisbom import cli as cli_module
from aisbom.cli import app
from aisbom.remote import RemoteStream, resolve_huggingface_repo, rewrite_hf_web_url
from aisbom.scanner import TARGET_ERROR_TYPES, DeepScanner

runner = CliRunner()


def _tree_page(entries, next_url=None):
    class Resp:
        status_code = 200
        headers = {}
        content = json.dumps(entries).encode()
        links = {"next": {"url": next_url}} if next_url else {}

        def raise_for_status(self):
            pass

        def json(self):
            return entries

    return Resp()


def _range_response(blob: bytes, start: int, end: int):
    class Resp:
        status_code = 206
        content = blob[start:end + 1]
        headers = {"Content-Range": f"bytes {start}-{end}/{len(blob)}"}

        def raise_for_status(self):
            pass

    return Resp()


def _safetensors_bytes() -> bytes:
    header = b'{"__metadata__":{}}'
    return struct.pack("<Q", len(header)) + header


@pytest.fixture
def stub_requests(monkeypatch):
    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    return remote.requests


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: state_dir)
    monkeypatch.setattr(cli_module, "run_version_check_wrapper", lambda: None)
    monkeypatch.setattr(cli_module, "update_result", {"version": None})
    monkeypatch.setattr(scanner_module, "fetch_huggingface_model_card", lambda *a, **k: None)
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
    monkeypatch.delenv("AISBOM_NO_TELEMETRY", raising=False)
    monkeypatch.delenv("AISBOM_OFFLINE", raising=False)
    monkeypatch.chdir(tmp_path)
    events = []

    def _record(event, params=None, scan_id=None):
        events.append((event, dict(params or {})))
        return None

    monkeypatch.setattr("aisbom.telemetry.post_event", _record)
    return {"tmp": tmp_path, "events": events}


def _cli_errors(events):
    return [p for e, p in events if e == "cli_error"]


# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------

_PAGE1 = "https://huggingface.co/api/models/org/model/tree/main?recursive=true"
_PAGE2 = _PAGE1 + "&cursor=2"
_PAGE3 = _PAGE1 + "&cursor=3"


def test_every_listing_page_carries_a_timeout(stub_requests, monkeypatch):
    timeouts = []
    pages = {
        _PAGE1: _tree_page([{"path": "a.safetensors", "type": "file"}], _PAGE2),
        _PAGE2: _tree_page([{"path": "b/b.safetensors", "type": "file"}], _PAGE3),
        _PAGE3: _tree_page([{"path": "c.gguf", "type": "file"}]),
    }

    def fake_get(url, headers=None, timeout=None):
        timeouts.append(timeout)
        return pages[url]

    monkeypatch.setattr(stub_requests, "get", fake_get)
    urls = resolve_huggingface_repo("hf://org/model")

    # An honest multi-page listing still completes in full.
    assert len(urls) == 3 and urls.truncated is False and urls.pages_read == 3
    assert timeouts == [remote.HF_REQUEST_TIMEOUT] * 3


def test_request_timeout_bounds_both_connect_and_read():
    connect, read = remote.HF_REQUEST_TIMEOUT
    # Above the model-card enrichment cap, which is meant to give up first.
    assert 0 < connect <= read
    assert read > remote._MODEL_CARD_TIMEOUT_SECONDS


def test_remote_stream_requests_carry_a_timeout(stub_requests, monkeypatch):
    blob = _safetensors_bytes()
    timeouts = []

    def fake_get(url, headers=None, timeout=None):
        timeouts.append(timeout)
        start, end = headers["Range"][len("bytes="):].split("-")
        return _range_response(blob, int(start), int(end))

    monkeypatch.setattr(stub_requests, "get", fake_get)
    with RemoteStream("https://example.com/m.safetensors") as stream:
        assert stream.read(4) == blob[:4]

    assert timeouts == [remote.HF_REQUEST_TIMEOUT] * 2


def test_listing_stall_is_a_fetch_error_not_an_empty_listing(stub_requests, monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        raise _requests.exceptions.ReadTimeout("stalled")

    monkeypatch.setattr(stub_requests, "get", fake_get)
    results = DeepScanner("hf://org/model").scan()

    assert results["artifacts"] == []
    [err] = results["errors"]
    assert err["fetch_failure"] is True
    assert isinstance(err["exception"], _requests.exceptions.Timeout)


def test_stall_mid_file_is_a_fetch_error_not_a_parse_error(stub_requests, monkeypatch):
    """The size probe succeeds, then a range read stalls.

    The inspectors catch every exception, so without help the stall became an
    unreadable-file verdict carrying the raw exception string.
    """
    blob = _safetensors_bytes()
    url = "https://example.com/model.safetensors"

    def fake_get(u, headers=None, timeout=None):
        if headers["Range"] == "bytes=0-0":
            return _range_response(blob, 0, 0)
        raise _requests.exceptions.ReadTimeout("stalled")

    monkeypatch.setattr(stub_requests, "get", fake_get)
    results = DeepScanner(url).scan()

    assert results["artifacts"] == []
    [err] = results["errors"]
    assert err.get("fetch_failure") is True
    assert not err.get("unreadable")
    assert isinstance(err["exception"], _requests.exceptions.Timeout)


def test_cli_stall_exits_1_with_a_timeout_message_and_telemetry(cli_env, monkeypatch):
    def boom(target):
        raise _requests.exceptions.ReadTimeout("stalled")

    monkeypatch.setattr(scanner_module, "resolve_huggingface_repo", boom)
    result = runner.invoke(app, ["scan", "hf://org/model"])

    assert result.exit_code == 1
    assert "Timed out" in result.output
    assert "huggingface.co" in result.output
    [payload] = _cli_errors(cli_env["events"])
    assert payload["http_status"] == "timeout"
    assert payload["error_type"] == "ReadTimeout"
    assert payload["target_type"] == "huggingface"


def test_connection_error_keeps_its_own_message():
    msg = cli_module._format_fetch_error(
        _requests.exceptions.ConnectionError("refused"), "hf://org/model"
    )
    assert "Network error reaching huggingface.co" in msg
    assert "Timed out" not in msg


# ---------------------------------------------------------------------------
# Hugging Face web-page URLs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://huggingface.co/org/model",
    "https://huggingface.co/org/model/",
    "https://huggingface.co/org/model/tree/main",
    "https://huggingface.co/org/model/tree/main/",
    "http://huggingface.co/org/model/tree/main",
    "https://www.huggingface.co/org/model",
    "https://hf.co/org/model/tree/main",
    "https://huggingface.co/org/model?library=transformers",
])
def test_repo_and_root_tree_pages_become_hf_targets(url):
    assert rewrite_hf_web_url(url) == ("hf://org/model", None)


@pytest.mark.parametrize("url,expected", [
    ("https://huggingface.co/org/model/blob/main/model.safetensors",
     "https://huggingface.co/org/model/resolve/main/model.safetensors"),
    ("https://huggingface.co/org/model/blob/main/onnx/model.onnx",
     "https://huggingface.co/org/model/resolve/main/onnx/model.onnx"),
    ("https://hf.co/org/model/blob/v1.0/model.pt?download=true",
     "https://huggingface.co/org/model/resolve/v1.0/model.pt"),
    ("https://huggingface.co/org/model/blob/main/my%20model.pt",
     "https://huggingface.co/org/model/resolve/main/my%20model.pt"),
    # A file hosted in a dataset or Space is still a single file.
    ("https://huggingface.co/datasets/org/data/blob/main/weights.safetensors",
     "https://huggingface.co/datasets/org/data/resolve/main/weights.safetensors"),
    ("https://hf.co/spaces/org/app/blob/main/model.pt",
     "https://huggingface.co/spaces/org/app/resolve/main/model.pt"),
])
def test_blob_pages_become_resolve_urls(url, expected):
    assert rewrite_hf_web_url(url) == (expected, None)


@pytest.mark.parametrize("url", [
    "https://huggingface.co/org/model/resolve/main/model.pt",
    # Direct file URLs in datasets and Spaces always reached RemoteStream;
    # refusing the repo pages must not refuse these.
    "https://huggingface.co/datasets/org/data/resolve/main/weights.safetensors",
    "https://huggingface.co/spaces/org/app/resolve/main/model.safetensors",
    "https://example.com/org/model/tree/main",
    "https://cdn-lfs.huggingface.co/repos/ab/cd/file",
    "hf://org/model",
    "./models",
])
def test_non_page_targets_are_left_alone(url):
    assert rewrite_hf_web_url(url) == (None, None)


@pytest.mark.parametrize("url,suggests", [
    # The resolver reads every file at main; a branch or a subfolder is a
    # different set of files, so neither can be followed exactly.
    ("https://huggingface.co/org/model/tree/dev", "hf://org/model"),
    ("https://huggingface.co/org/model/tree/main/onnx", "hf://org/model"),
    ("https://huggingface.co/org/model/blob/main", "hf://org/model"),
    ("https://huggingface.co/org/model/discussions", "hf://org/model"),
    ("https://huggingface.co/datasets/org/data", "model repos"),
    ("https://huggingface.co/spaces/org/app", "model repos"),
    ("https://huggingface.co/datasets/org/data/tree/main", "model repos"),
    ("https://huggingface.co/gpt2", "hf://<owner>/<repo>"),
    ("https://huggingface.co/", "hf://<owner>/<repo>"),
])
def test_pages_that_cannot_map_exactly_are_refused(url, suggests):
    target, problem = rewrite_hf_web_url(url)
    assert target is None
    assert problem and suggests in problem


def test_scanner_follows_a_tree_page_as_the_repo(monkeypatch):
    seen = []
    monkeypatch.setattr(scanner_module, "resolve_huggingface_repo",
                        lambda t: seen.append(t) or [])
    monkeypatch.setattr(scanner_module, "fetch_huggingface_model_card", lambda *a, **k: None)

    scanner = DeepScanner("https://huggingface.co/org/model/tree/main")
    results = scanner.scan()

    assert scanner.root_path == "hf://org/model"
    assert scanner.rewritten_from == "https://huggingface.co/org/model/tree/main"
    assert seen == ["hf://org/model"]
    assert results["errors"] == []


def test_scanner_reads_a_blob_page_as_the_file(stub_requests, monkeypatch):
    blob = _safetensors_bytes()
    asked = []

    def fake_get(url, headers=None, timeout=None):
        asked.append(url)
        start, end = headers["Range"][len("bytes="):].split("-")
        return _range_response(blob, int(start), int(end))

    monkeypatch.setattr(stub_requests, "get", fake_get)
    results = DeepScanner("https://huggingface.co/org/model/blob/main/model.safetensors").scan()

    assert set(asked) == {"https://huggingface.co/org/model/resolve/main/model.safetensors"}
    assert [a["name"] for a in results["artifacts"]] == ["model.safetensors"]
    assert results["errors"] == []


def test_unmappable_page_is_a_target_error_with_no_request(stub_requests, monkeypatch):
    def explode(*a, **k):
        raise AssertionError("a refused page must not be fetched")

    monkeypatch.setattr(stub_requests, "get", explode)
    results = DeepScanner("https://huggingface.co/org/model/tree/dev").scan()

    [err] = results["errors"]
    assert err["target_error"] is True
    assert err["target_error_type"] == "UnsupportedHFPageURL"
    assert "hf://org/model" in err["error"]


def test_new_target_error_type_is_in_the_closed_set():
    assert "UnsupportedHFPageURL" in TARGET_ERROR_TYPES


def test_cli_notes_the_rewrite_and_scans(cli_env, monkeypatch):
    monkeypatch.setattr(scanner_module, "resolve_huggingface_repo", lambda t: [])
    result = runner.invoke(app, ["scan", "https://huggingface.co/org/model/tree/main"])

    assert result.exit_code == 0, result.output
    assert "hf://org/model" in result.output
    assert _cli_errors(cli_env["events"]) == []


def test_cli_refuses_unmappable_page_with_exit_1(cli_env):
    result = runner.invoke(app, ["scan", "https://huggingface.co/org/model/tree/dev"])

    assert result.exit_code == 1
    assert "hf://org/model" in result.output
    [payload] = _cli_errors(cli_env["events"])
    assert payload["error_type"] == "UnsupportedHFPageURL"
    assert payload["target_type"] == "https"
    assert payload["http_status"] == "none"
    # The closed-set code is all that leaves: no repo id, no URL.
    assert "org/model" not in json.dumps(payload)


# ---------------------------------------------------------------------------
# Any URL no inspector claims
# ---------------------------------------------------------------------------

def test_unclaimed_url_is_a_target_error_with_no_request(stub_requests, monkeypatch):
    def explode(*a, **k):
        raise AssertionError("an unclaimed URL must not be fetched")

    monkeypatch.setattr(stub_requests, "get", explode)
    results = DeepScanner("https://example.com/models/bundle.zip").scan()

    assert results["artifacts"] == []
    [err] = results["errors"]
    assert err["target_error_type"] == "UnsupportedFileType"


def test_query_string_does_not_hide_the_extension(stub_requests, monkeypatch):
    blob = _safetensors_bytes()

    def fake_get(url, headers=None, timeout=None):
        start, end = headers["Range"][len("bytes="):].split("-")
        return _range_response(blob, int(start), int(end))

    monkeypatch.setattr(stub_requests, "get", fake_get)
    results = DeepScanner("https://example.com/model.safetensors?download=true").scan()

    assert results["errors"] == []
    assert [a["framework"] for a in results["artifacts"]] == ["SafeTensors"]


def test_cli_unclaimed_url_exits_1(cli_env):
    result = runner.invoke(app, ["scan", "https://example.com/models/bundle.zip"])

    assert result.exit_code == 1
    [payload] = _cli_errors(cli_env["events"])
    assert payload["error_type"] == "UnsupportedFileType"
    assert payload["target_type"] == "https"
