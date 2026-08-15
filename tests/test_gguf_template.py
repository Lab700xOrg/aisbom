"""GGUF metadata traversal and chat-template (Jinja) injection detection.

A GGUF model can ship a Jinja chat template in its metadata. That template runs
on every inference request, so it executes as a consequence of using the model
for its intended purpose — which is what makes a hostile one worth flagging.

Nothing here renders, parses, or compiles a template. Jinja is never imported;
the templates below are strings carrying recognizable signatures, not working
exploits.

The metadata tests matter as much as the template ones: the chat template sits
*behind* the tokenizer arrays in the key-value block, so reading it at all
requires stepping over array, float and bool values at exactly the right widths.
"""

import struct

import pytest

from aisbom.mock_generator import (
    BENIGN_CHAT_TEMPLATE,
    MALICIOUS_CHAT_TEMPLATE,
    create_mock_gguf,
    create_mock_gguf_with_template,
)
from aisbom.properties import build_component_properties
from aisbom.safety import (
    jinja_threats_are_critical,
    scan_jinja_template,
)
from aisbom.scanner import DeepScanner


# --- Jinja template analysis ----------------------------------------------

def test_benign_template_is_clean():
    assert scan_jinja_template(BENIGN_CHAT_TEMPLATE) == []


def test_empty_and_non_string_templates_are_clean():
    assert scan_jinja_template("") == []
    assert scan_jinja_template(None) == []


def test_subclasses_escape_chain_is_detected():
    threats = scan_jinja_template(MALICIOUS_CHAT_TEMPLATE)
    assert "JINJA_SANDBOX_ESCAPE: __class__" in threats
    assert "JINJA_SANDBOX_ESCAPE: __mro__" in threats
    assert "JINJA_SANDBOX_ESCAPE: __subclasses__" in threats
    assert jinja_threats_are_critical(threats) is True


def test_globals_builtins_import_chain_is_detected():
    template = (
        "{{ self.__init__.__globals__['__builtins__']['__import__']('os')"
        ".popen('id').read() }}"
    )
    threats = scan_jinja_template(template)
    assert "JINJA_SANDBOX_ESCAPE: __globals__" in threats
    assert "JINJA_SANDBOX_ESCAPE: __builtins__" in threats
    assert "JINJA_SANDBOX_ESCAPE: __import__" in threats
    assert "JINJA_DANGEROUS_CALL: popen" in threats
    assert jinja_threats_are_critical(threats) is True


def test_attr_filter_bypass_is_detected():
    """`|attr('...')` fetches an attribute by name, past dotted-access filters."""
    threats = scan_jinja_template("{{ ''|attr('__class__') }}")
    assert "JINJA_ATTR_FILTER" in threats
    assert jinja_threats_are_critical(threats) is True


def test_attr_filter_tolerates_whitespace():
    assert "JINJA_ATTR_FILTER" in scan_jinja_template("{{ x | attr ('y') }}")


@pytest.mark.parametrize("name", ["eval", "exec", "system", "subprocess", "compile"])
def test_dangerous_calls_are_detected(name):
    threats = scan_jinja_template("{{ " + name + "('x') }}")
    assert f"JINJA_DANGEROUS_CALL: {name}" in threats


def test_context_leak_objects_are_detected():
    threats = scan_jinja_template("{{ lipsum.__globals__ }}{{ cycler }}")
    assert any(t.startswith("JINJA_CONTEXT_LEAK:") for t in threats)


@pytest.mark.parametrize("tag", ["include", "extends", "import"])
def test_template_inclusion_is_detected(tag):
    threats = scan_jinja_template("{% " + tag + " 'other.j2' %}")
    assert f"JINJA_TEMPLATE_INCLUSION: {tag}" in threats


def test_template_inclusion_alone_is_not_critical():
    """Inclusion is anomalous but needs a target template to matter."""
    threats = scan_jinja_template("{% include 'other.j2' %}")
    assert threats == ["JINJA_TEMPLATE_INCLUSION: include"]
    assert jinja_threats_are_critical(threats) is False


def test_inclusion_is_reported_once_for_repeats():
    threats = scan_jinja_template("{% include 'a' %}{% include 'b' %}")
    assert threats.count("JINJA_TEMPLATE_INCLUSION: include") == 1


def test_dangerous_names_are_matched_as_whole_identifiers():
    """`evaluate` and `system_prompt` must not read as `eval` and `system`.

    Substring matching here would flag ordinary templates, and a detector that
    fires on benign models is one people turn off.
    """
    template = (
        "{% for m in messages %}{{ m['system_prompt'] }}"
        "{{ evaluate_score }}{{ compiled_output }}{{ execution_time }}"
        "{% endfor %}"
    )
    assert scan_jinja_template(template) == []


def test_underscored_tokens_are_matched_within_attribute_chains():
    """Boundaries must not stop a real `__class__` from matching after a dot."""
    assert "JINJA_SANDBOX_ESCAPE: __class__" in scan_jinja_template("{{ a.__class__ }}")


def test_oversized_template_reports_that_it_was_not_fully_read():
    """Padding past the bound must not buy a clean result.

    The analysis is bounded so a hostile file cannot make it run forever, but
    an unread remainder is reported rather than treated as absence of findings
    — otherwise filler is all it takes to hide an escape.
    """
    from aisbom.safety import JINJA_TEMPLATE_MAX_CHARS, jinja_analysis_is_incomplete

    padded = ("x" * JINJA_TEMPLATE_MAX_CHARS) + "{{ ''.__subclasses__() }}"
    threats = scan_jinja_template(padded)

    assert any(t.startswith("JINJA_TEMPLATE_TRUNCATED:") for t in threats)
    assert jinja_analysis_is_incomplete(threats) is True


def test_template_within_the_bound_is_not_marked_truncated():
    from aisbom.safety import jinja_analysis_is_incomplete

    assert jinja_analysis_is_incomplete(scan_jinja_template(BENIGN_CHAT_TEMPLATE)) is False


# --- false positives on real-world chat templates ------------------------

REAL_WORLD_TEMPLATES = {
    "llama-2": (
        "{% if messages[0]['role'] == 'system' %}"
        "{% set loop_messages = messages[1:] %}{% endif %}"
        "{% for message in loop_messages %}{{ message['content'] }}{% endfor %}"
    ),
    "mistral": (
        "{% for message in messages %}"
        "{% if message['role'] == 'user' %}{{ '[INST] ' + message['content'] + ' [/INST]' }}"
        "{% elif message['role'] == 'system' %}{{ '<<SYS>>' + message['content'] }}"
        "{% endif %}{% endfor %}"
    ),
    "zephyr": (
        "{% for message in messages %}"
        "{% if message['role'] == 'system' %}{{ '<|system|>' }}{% endif %}{% endfor %}"
    ),
    "chatml": (
        "{% for message in messages %}"
        "{{'<|im_start|>' + message['role'] + chr(10) + message['content']}}{% endfor %}"
    ),
}


@pytest.mark.parametrize("name", sorted(REAL_WORLD_TEMPLATES))
def test_real_world_templates_are_clean(name):
    """`role == 'system'` appears in nearly every instruction-tuned template.

    Reading that mention as a call to `os.system` would fail CI on a large
    share of real models — the kind of false positive that gets a scanner
    switched off.
    """
    assert scan_jinja_template(REAL_WORLD_TEMPLATES[name]) == []


def test_dangerous_names_inside_string_literals_are_not_calls():
    assert scan_jinja_template("{{ 'please eval this' }}") == []
    assert scan_jinja_template('{{ "exec summary" }}') == []
    assert scan_jinja_template("{% if role == 'system' %}{% endif %}") == []


def test_dangerous_names_inside_comments_are_ignored():
    assert scan_jinja_template("{# calls os.system here #}{{ x }}") == []


@pytest.mark.parametrize("template,token", [
    ("{{ os.system('id') }}", "system"),
    ("{{ eval('1+1') }}", "eval"),
    ("{{ subprocess.Popen('id') }}", "Popen"),
    ("{{ x.popen('id') }}", "popen"),
    ("{{ getattr(o, 'x') }}", "getattr"),
])
def test_real_calls_are_still_detected(template, token):
    """Requiring call syntax must not blunt detection of an actual call."""
    assert f"JINJA_DANGEROUS_CALL: {token}" in scan_jinja_template(template)


def test_attr_filter_payload_in_a_literal_is_still_detected():
    """Literal-stripping must not hide `|attr('__class__')`.

    The escape checks deliberately read the raw template, because this bypass
    carries its payload inside a string literal.
    """
    threats = scan_jinja_template("{{ ''|attr('__class__') }}")
    assert "JINJA_ATTR_FILTER" in threats
    assert "JINJA_SANDBOX_ESCAPE: __class__" in threats


# --- GGUF metadata traversal ---------------------------------------------

def test_all_metadata_keys_are_read_past_arrays_floats_and_bools(tmp_path):
    """The regression that makes the chat template reachable at all.

    A walker that mishandles array, float or bool widths desynchronises and
    silently drops every key after the first one it gets wrong.
    """
    create_mock_gguf_with_template(tmp_path / "m.gguf", chat_template=BENIGN_CHAT_TEMPLATE)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    keys = art["details"]["metadata_keys"]

    assert keys == [
        "general.architecture",
        "general.name",
        "general.license",
        "general.file_type",
        "llama.attention.layer_norm_rms_epsilon",
        "llama.block_count",
        "tokenizer.ggml.tokens",
        "tokenizer.ggml.scores",
        "tokenizer.ggml.add_bos_token",
        "tokenizer.chat_template",
    ]
    assert art["details"]["kv_parsed"] == art["details"]["kv_count"] == 10
    assert "metadata_truncated" not in art["details"]


def test_license_after_a_float_is_still_found(tmp_path):
    """A restrictive license sitting behind a float must not be lost.

    Getting this wrong is a silent false negative: the model reports UNKNOWN
    legal status and a clean scan.
    """
    create_mock_gguf_with_template(
        tmp_path / "m.gguf", chat_template=None, license_name="cc-by-nc-4.0"
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["license"] == "cc-by-nc-4.0"
    assert art["legal_status"].startswith("LEGAL RISK")


def test_architecture_and_quantization_survive_the_walk(tmp_path):
    create_mock_gguf_with_template(tmp_path / "m.gguf")
    details = DeepScanner(str(tmp_path)).scan()["artifacts"][0]["details"]

    assert details["architecture"] == "llama"
    assert details["quantization"] == 15


def test_array_contents_are_summarized_not_retained(tmp_path):
    create_mock_gguf_with_template(tmp_path / "m.gguf", vocab_size=32)
    details = DeepScanner(str(tmp_path)).scan()["artifacts"][0]["details"]

    # metadata_keys names the array, but no token strings are carried along.
    assert "tokenizer.ggml.tokens" in details["metadata_keys"]
    assert "tok0" not in repr(details)


def test_single_key_gguf_still_works(tmp_path):
    """The original minimal fixture must keep parsing identically."""
    create_mock_gguf(tmp_path)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["framework"] == "GGUF"
    assert art["license"] == "cc-by-nc-sa-4.0"
    assert art["legal_status"].startswith("LEGAL RISK")
    assert art["risk_level"] == "LOW"


def test_truncated_metadata_is_reported_not_hidden(tmp_path):
    full = create_mock_gguf_with_template(
        tmp_path / "full.gguf", chat_template=BENIGN_CHAT_TEMPLATE
    ).read_bytes()
    (tmp_path / "full.gguf").unlink()
    (tmp_path / "cut.gguf").write_bytes(full[: len(full) // 2])

    details = DeepScanner(str(tmp_path)).scan()["artifacts"][0]["details"]
    assert details["metadata_truncated"] is True
    assert details["kv_parsed"] < details["kv_count"]


def test_absurd_array_count_does_not_hang(tmp_path):
    """A declared count of billions must be rejected, not iterated."""
    blob = (
        b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 1)
        + struct.pack("<Q", 4) + b"toks"
        + struct.pack("<I", 9)              # ARRAY
        + struct.pack("<I", 8)              # of STRING
        + struct.pack("<Q", 2 ** 40)        # count
    )
    (tmp_path / "bomb.gguf").write_bytes(blob)

    details = DeepScanner(str(tmp_path)).scan()["artifacts"][0]["details"]
    assert details["metadata_truncated"] is True


def test_unknown_value_type_stops_the_walk_cleanly(tmp_path):
    blob = (
        b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 1)
        + struct.pack("<Q", 3) + b"key"
        + struct.pack("<I", 77)             # not a GGUF type
    )
    (tmp_path / "weird.gguf").write_bytes(blob)

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    assert art["details"]["metadata_truncated"] is True
    assert "CRITICAL" not in art["risk_level"]


def test_invalid_magic_is_still_rejected(tmp_path):
    (tmp_path / "bad.gguf").write_bytes(b"NOPE" + b"\x00" * 32)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    assert art["risk_level"] == "UNKNOWN (Invalid Header)"


# --- end to end -----------------------------------------------------------

def test_malicious_template_is_critical(tmp_path):
    create_mock_gguf_with_template(
        tmp_path / "evil.gguf", chat_template=MALICIOUS_CHAT_TEMPLATE
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "Chat Template" in art["risk_level"]
    assert art["details"]["chat_template_present"] is True
    assert any(
        t.startswith("JINJA_SANDBOX_ESCAPE:")
        for t in art["details"]["chat_template_threats"]
    )
    assert len(art["details"]["chat_template_sha256"]) == 64


def test_benign_template_scans_clean(tmp_path):
    create_mock_gguf_with_template(
        tmp_path / "clean.gguf", chat_template=BENIGN_CHAT_TEMPLATE
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["risk_level"] == "LOW"
    assert art["details"]["chat_template_present"] is True
    assert art["details"]["chat_template_threats"] == []


def test_model_without_a_template_is_unaffected(tmp_path):
    create_mock_gguf_with_template(tmp_path / "none.gguf", chat_template=None)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["risk_level"] == "LOW"
    assert art["details"]["chat_template_present"] is False
    assert art["details"]["chat_template_threats"] == []


def test_inclusion_only_template_is_medium(tmp_path):
    create_mock_gguf_with_template(
        tmp_path / "inc.gguf", chat_template="{% include 'other.j2' %}{{ x }}"
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "MEDIUM" in art["risk_level"]
    assert "CRITICAL" not in art["risk_level"]


# --- named template variants ---------------------------------------------

def _gguf_with_templates(path, templates: dict):
    """Write a GGUF carrying several named chat-template keys."""
    from aisbom.mock_generator import (
        _gguf_kv_bool, _gguf_kv_float32, _gguf_kv_string, _gguf_kv_string_array,
        _gguf_kv_uint32,
    )
    pairs = [
        _gguf_kv_string("general.architecture", "llama"),
        _gguf_kv_string("general.license", "apache-2.0"),
        _gguf_kv_uint32("general.file_type", 15),
        _gguf_kv_float32("llama.attention.layer_norm_rms_epsilon", 1e-5),
        _gguf_kv_string_array("tokenizer.ggml.tokens", ["a", "b"]),
        _gguf_kv_bool("tokenizer.ggml.add_bos_token", True),
    ]
    for key, body in templates.items():
        pairs.append(_gguf_kv_string(key, body))
    blob = (
        b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0)
        + struct.pack("<Q", len(pairs)) + b"".join(pairs)
    )
    path.write_bytes(blob)
    return path


def test_named_template_variants_are_scanned(tmp_path):
    """Models with multiple templates key them as `chat_template.<name>`.

    An exact-key lookup treats such a model as having no template at all, so a
    payload in every named variant would go unread.
    """
    _gguf_with_templates(tmp_path / "m.gguf", {
        "tokenizer.chat_template.default": BENIGN_CHAT_TEMPLATE,
        "tokenizer.chat_template.tool_use": MALICIOUS_CHAT_TEMPLATE,
    })
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["details"]["chat_template_present"] is True
    assert art["details"]["chat_template_keys"] == [
        "tokenizer.chat_template.default",
        "tokenizer.chat_template.tool_use",
    ]
    assert "CRITICAL" in art["risk_level"]
    # The finding names which variant it came from.
    assert any(
        "[tokenizer.chat_template.tool_use]" in t
        for t in art["details"]["chat_template_threats"]
    )


def test_named_variants_that_are_all_benign_scan_clean(tmp_path):
    _gguf_with_templates(tmp_path / "m.gguf", {
        "tokenizer.chat_template.default": BENIGN_CHAT_TEMPLATE,
        "tokenizer.chat_template.rag": BENIGN_CHAT_TEMPLATE,
    })
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["risk_level"] == "LOW"
    assert art["details"]["chat_template_threats"] == []
    assert len(art["details"]["chat_template_digests"]) == 2


def test_a_similar_but_unrelated_key_is_not_treated_as_a_template(tmp_path):
    _gguf_with_templates(tmp_path / "m.gguf", {
        "tokenizer.chat_template_version": "3",
    })
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    assert art["details"]["chat_template_present"] is False


# --- SBOM plumbing --------------------------------------------------------

def test_template_properties_are_emitted(tmp_path):
    create_mock_gguf_with_template(
        tmp_path / "evil.gguf", chat_template=MALICIOUS_CHAT_TEMPLATE
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    props = build_component_properties(art)
    as_dict = dict(props)
    names = {n for n, _ in props}

    assert as_dict["aisbom:format"] == "gguf"
    assert as_dict["aisbom:gguf:chat_template"] == "present"
    assert len(as_dict["aisbom:gguf:chat_template_sha256"]) == 64
    assert int(as_dict["aisbom:gguf:chat_template_threat_count"]) >= 3
    assert "aisbom:gguf:chat_template_threat" in names
    assert as_dict["aisbom:risk"].startswith("CRITICAL")


def test_template_body_is_not_emitted_into_the_sbom(tmp_path):
    """The template digest goes into the SBOM; the template itself does not."""
    create_mock_gguf_with_template(
        tmp_path / "m.gguf", chat_template=BENIGN_CHAT_TEMPLATE
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    values = " ".join(v for _, v in build_component_properties(art))

    assert "endfor" not in values


def test_no_template_properties_when_absent(tmp_path):
    create_mock_gguf_with_template(tmp_path / "m.gguf", chat_template=None)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    names = {n for n, _ in build_component_properties(art)}

    assert "aisbom:gguf:chat_template" not in names
    assert "aisbom:gguf:chat_template_threat_count" not in names


# --- CLI ------------------------------------------------------------------

def test_malicious_template_exits_two(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    create_mock_gguf_with_template(
        tmp_path / "evil.gguf", chat_template=MALICIOUS_CHAT_TEMPLATE
    )
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "evil.gguf" in result.output, result.output
    assert "CRITICAL" in result.output, result.output
    assert result.exit_code == 2, result.output


def test_benign_template_exits_zero(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    create_mock_gguf_with_template(
        tmp_path / "clean.gguf", chat_template=BENIGN_CHAT_TEMPLATE
    )
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "clean.gguf" in result.output, result.output
    assert result.exit_code == 0, result.output


def test_inclusion_only_template_does_not_exit_two(tmp_path, monkeypatch):
    """MEDIUM must not fail CI, or the severity stops carrying information."""
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    create_mock_gguf_with_template(
        tmp_path / "inc.gguf", chat_template="{% include 'other.j2' %}"
    )
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output


# --- remote ---------------------------------------------------------------

def test_remote_gguf_template_is_detected(monkeypatch, tmp_path):
    """The remote dispatch arm must exercise the template path too."""
    import aisbom.remote as remote

    content = create_mock_gguf_with_template(
        tmp_path / "remote.gguf", chat_template=MALICIOUS_CHAT_TEMPLATE
    ).read_bytes()
    requests_made = []

    def fake_get(url, headers=None):
        rng = (headers or {}).get("Range", "bytes=0-0")
        requests_made.append(rng)
        start, _, end = rng.split("=")[1].partition("-")
        start = int(start)
        end = int(end) if end else len(content) - 1
        chunk = content[start:end + 1]

        class Resp:
            status_code = 206

            def __init__(self):
                self.content = chunk
                self.headers = {
                    "Content-Range": f"bytes {start}-{end}/{len(content)}",
                    "Content-Length": str(len(chunk)),
                }

            def raise_for_status(self):
                pass

        return Resp()

    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)
    monkeypatch.setattr(
        "aisbom.scanner.DeepScanner._resolve_remote_targets",
        lambda self, target: ["http://example.com/remote.gguf"],
    )

    results = DeepScanner("http://example.com/remote.gguf").scan()
    art = results["artifacts"][0]

    assert results["errors"] == []
    assert "CRITICAL" in art["risk_level"]
    assert art["hash"] == "remote_unhashed"
    # The metadata block is buffered, not walked field by field: a handful of
    # range requests, not one per key.
    assert len(requests_made) <= 4, requests_made
