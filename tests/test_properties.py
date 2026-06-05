from aisbom.properties import build_component_properties


def _props_dict(pairs):
    """Collapse pairs into a dict; for repeated keys, collect values in a list."""
    out = {}
    for k, v in pairs:
        if k in out:
            out[k].append(v)
        else:
            out[k] = [v]
    return out


def test_non_model_artifact_emits_no_properties():
    art = {"framework": "Python Path Config", "details": {}}
    assert build_component_properties(art) == []


def test_unknown_framework_emits_no_properties():
    art = {"framework": "Something New", "details": {}}
    assert build_component_properties(art) == []


def test_pickle_emits_one_opcode_per_threat_plus_count():
    art = {
        "framework": "PyTorch",
        "details": {"threats": ["os.system", "subprocess.Popen"]},
    }
    pairs = build_component_properties(art)
    d = _props_dict(pairs)

    assert d["aisbom:format"] == ["pickle"]
    assert d["aisbom:pickle:opcode"] == ["os.system", "subprocess.Popen"]
    assert d["aisbom:pickle:opcode_count"] == ["2"]


def test_pickle_with_no_threats_reports_zero_count_and_no_opcodes():
    art = {"framework": "PyTorch", "details": {"threats": []}}
    d = _props_dict(build_component_properties(art))

    assert d["aisbom:format"] == ["pickle"]
    assert "aisbom:pickle:opcode" not in d
    assert d["aisbom:pickle:opcode_count"] == ["0"]


def test_pickle_missing_threats_key_is_safe():
    art = {"framework": "PyTorch", "details": {}}
    d = _props_dict(build_component_properties(art))
    assert d["aisbom:pickle:opcode_count"] == ["0"]


def test_safetensors_emits_tensor_count_dtypes_header_keys():
    art = {
        "framework": "SafeTensors",
        "details": {
            "tensors": 2,
            "dtypes": ["F16", "F32"],
            "header_keys": ["weight", "bias"],
        },
    }
    d = _props_dict(build_component_properties(art))

    assert d["aisbom:format"] == ["safetensors"]
    assert d["aisbom:safetensors:tensor_count"] == ["2"]
    assert d["aisbom:safetensors:dtypes"] == ["F16,F32"]
    assert d["aisbom:safetensors:header_keys"] == ["weight,bias"]


def test_safetensors_omits_empty_optional_fields():
    art = {"framework": "SafeTensors", "details": {"tensors": 0}}
    d = _props_dict(build_component_properties(art))

    assert d["aisbom:safetensors:tensor_count"] == ["0"]
    assert "aisbom:safetensors:dtypes" not in d
    assert "aisbom:safetensors:header_keys" not in d


def test_gguf_emits_architecture_quantization_metadata_keys():
    art = {
        "framework": "GGUF",
        "details": {
            "architecture": "llama",
            "quantization": "10",
            "metadata_keys": ["general.architecture", "general.file_type"],
        },
    }
    d = _props_dict(build_component_properties(art))

    assert d["aisbom:format"] == ["gguf"]
    assert d["aisbom:gguf:architecture"] == ["llama"]
    assert d["aisbom:gguf:quantization"] == ["10"]
    assert d["aisbom:gguf:metadata_keys"] == ["general.architecture,general.file_type"]


def test_gguf_omits_missing_optional_fields():
    art = {"framework": "GGUF", "details": {"metadata_keys": ["general.license"]}}
    d = _props_dict(build_component_properties(art))

    assert d["aisbom:format"] == ["gguf"]
    assert "aisbom:gguf:architecture" not in d
    assert "aisbom:gguf:quantization" not in d
    assert d["aisbom:gguf:metadata_keys"] == ["general.license"]


def test_risk_and_legal_emitted_for_each_format():
    for framework in ("PyTorch", "SafeTensors", "GGUF"):
        art = {
            "framework": framework,
            "risk_level": "LOW",
            "legal_status": "OK",
            "details": {},
        }
        d = _props_dict(build_component_properties(art))
        assert d["aisbom:risk"] == ["LOW"]
        assert d["aisbom:legal"] == ["OK"]


def test_risk_and_legal_emitted_for_non_format_model_component():
    # A "Python Path Config" .pth is still emitted as an ML-model component by
    # cli.py, so it must carry risk/legal even though it has no aisbom:format.
    art = {
        "framework": "Python Path Config",
        "risk_level": "LOW",
        "legal_status": "UNKNOWN",
        "details": {},
    }
    d = _props_dict(build_component_properties(art))
    assert "aisbom:format" not in d
    assert d["aisbom:risk"] == ["LOW"]
    assert d["aisbom:legal"] == ["UNKNOWN"]


def test_risk_value_carries_full_label_matching_description_segment():
    # aisbom:risk mirrors the Risk: description segment verbatim, parens and all.
    art = {
        "framework": "PyTorch",
        "risk_level": "CRITICAL (RCE Detected: os.system)",
        "legal_status": "OK",
        "details": {"threats": ["os.system"]},
    }
    description = (
        f"Risk: {art['risk_level']} | Framework: {art['framework']} | "
        f"Legal: {art['legal_status']} | License: {art.get('license')}"
    )
    d = _props_dict(build_component_properties(art))
    risk_segment = description.split(" | ")[0][len("Risk: "):]
    legal_segment = description.split(" | ")[2][len("Legal: "):]
    assert d["aisbom:risk"] == [risk_segment]
    assert d["aisbom:legal"] == [legal_segment]


def test_risk_and_legal_omitted_when_keys_absent():
    art = {"framework": "PyTorch", "details": {"threats": []}}
    d = _props_dict(build_component_properties(art))
    assert "aisbom:risk" not in d
    assert "aisbom:legal" not in d


def test_all_keys_are_namespaced():
    for art in (
        {"framework": "PyTorch", "details": {"threats": ["os.system"]}},
        {"framework": "SafeTensors", "details": {"tensors": 1, "dtypes": ["F16"], "header_keys": ["w"]}},
        {"framework": "GGUF", "details": {"architecture": "llama", "quantization": "10", "metadata_keys": ["k"]}},
    ):
        for name, _ in build_component_properties(art):
            assert name.startswith("aisbom:")
