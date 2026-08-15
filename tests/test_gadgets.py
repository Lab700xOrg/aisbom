"""Indirect-execution gadget imports, in blocklist and strict mode.

The evasion these cover is not a clever opcode trick — it is picking a module
nobody thought to list. A debugger's `run`, an event loop's subprocess
transport and a package installer's entry point all execute attacker-chosen
code exactly as `os.system` does, while looking like ordinary library imports.

The dominant risk in this area is the *opposite* of a miss. Expanding a
blocklist and tightening an allowlist is how a scanner starts flagging real
checkpoints, and a scanner that flags real checkpoints gets switched off — so
roughly half of what follows is false-positive guards.

Nothing here is unpickled; payloads are disassembled with pickletools only.
"""

import collections
import datetime
import decimal
import fractions
import pathlib
import pickle
import re
import uuid

import pytest

from aisbom.mock_generator import (
    harmless_reduce_pickle,
    harmless_stack_global_pickle,
)
from aisbom.safety import (
    DANGEROUS_GLOBALS,
    EXECUTION_ATTRIBUTE_NAMES,
    _is_safe_import,
    is_dangerous_global,
    scan_pickle_stream,
)


# --- the documented gadgets ----------------------------------------------

GADGETS = [
    ("bdb", "Bdb"),
    ("bdb", "run"),
    ("bdb", "runeval"),
    ("pdb", "Pdb"),
    ("asyncio.unix_events", "_UnixSubprocessTransport"),
    ("asyncio", "create_subprocess_shell"),
    ("asyncio.subprocess", "create_subprocess_exec"),
    ("asyncio.base_events", "BaseEventLoop"),
    ("pip", "main"),
    ("pip._internal", "main"),
    ("runpy", "run_path"),
    ("importlib", "import_module"),
    ("imp", "load_source"),
    ("pty", "spawn"),
    ("platform", "popen"),
    ("ctypes", "CDLL"),
    ("timeit", "timeit"),
    ("code", "interact"),
    ("codeop", "compile_command"),
    ("cProfile", "runctx"),
    ("multiprocessing", "Process"),
    ("sys", "modules"),
    ("builtins", "__import__"),
    ("nt", "system"),
]


@pytest.mark.parametrize("module,name", GADGETS)
def test_gadget_is_flagged_in_blocklist_mode(module, name):
    """The headline requirement: these must not need `--strict` to be caught."""
    threats = scan_pickle_stream(harmless_reduce_pickle(module, name))
    assert threats == [f"{module}.{name}"]


@pytest.mark.parametrize("module,name", GADGETS)
def test_gadget_is_flagged_in_strict_mode(module, name):
    threats = scan_pickle_stream(harmless_reduce_pickle(module, name), strict_mode=True)
    assert threats == [f"UNSAFE_IMPORT: {module}.{name}"]


@pytest.mark.parametrize("module,name", GADGETS)
def test_gadget_is_flagged_via_stack_global_too(module, name):
    """Protocol 4 resolves the global off the stack; same verdict required."""
    threats = scan_pickle_stream(harmless_stack_global_pickle(module, name))
    assert threats == [f"{module}.{name}"]


# --- submodules the table does not enumerate -----------------------------

@pytest.mark.parametrize("module,name", [
    ("asyncio.some_future_module", "run"),
    ("asyncio.windows_events", "create_subprocess_shell"),
    ("importlib.a.b.c", "import_module"),
    ("pip._internal.cli.some.deep.path", "main"),
    ("ctypes.util", "CDLL"),
])
def test_unlisted_submodule_of_a_dangerous_family_is_still_flagged(module, name):
    """A new submodule name must not be a way around the table."""
    assert is_dangerous_global(module, name) is True
    assert scan_pickle_stream(harmless_reduce_pickle(module, name)) == [f"{module}.{name}"]


def test_dangerous_attribute_on_an_allowlisted_module_is_not_strict_safe():
    """The 'benign prefix' hole: an allowlisted package with a sink attribute."""
    assert _is_safe_import("torch", "system") is False
    assert _is_safe_import("torch.nested.thing", "popen") is False
    assert _is_safe_import("numpy", "run") is False
    assert _is_safe_import("collections", "eval") is False


def test_ordinary_attributes_on_allowlisted_modules_remain_safe():
    assert _is_safe_import("torch.nn.modules.linear", "Linear") is True
    assert _is_safe_import("torch._utils", "_rebuild_tensor_v2") is True
    assert _is_safe_import("numpy.core.multiarray", "_reconstruct") is True
    assert _is_safe_import("collections", "OrderedDict") is True


# --- dual-use constructors: the argument decides -------------------------
#
# `attrgetter`/`methodcaller` build a callable from a name given as a *string*,
# so `methodcaller("system")` reaches a sink without naming it as a global.
# Flagging the constructor unconditionally would flag every checkpoint that
# stores an ordinary `attrgetter("name")`, so the argument is what is judged.
# `functools.reduce` is deliberately not listed at all: whatever dangerous
# callable it is handed appears as its own global and is caught on its own.

BENIGN_DUAL_USE = [
    ("attrgetter", ("name",)),
    ("attrgetter", ("a.b",)),
    ("attrgetter", ("weight", "bias")),
    ("methodcaller", ("upper",)),
    ("methodcaller", ("strip", " ")),
    ("methodcaller", ("get", "key")),
]

DANGEROUS_DUAL_USE = [
    ("attrgetter", ("__globals__",)),
    ("attrgetter", ("__class__.__mro__",)),
    ("attrgetter", ("__reduce__",)),
    ("methodcaller", ("system", "id")),
    ("methodcaller", ("popen", "id")),
    ("methodcaller", ("run",)),
]


@pytest.mark.parametrize("ctor,args", BENIGN_DUAL_USE)
@pytest.mark.parametrize("protocol", [2, 4])
def test_benign_dual_use_constructors_are_clean(ctor, args, protocol):
    import operator
    blob = pickle.dumps(getattr(operator, ctor)(*args), protocol=protocol)
    assert scan_pickle_stream(blob) == []
    assert scan_pickle_stream(blob, strict_mode=True) == []


@pytest.mark.parametrize("ctor,args", DANGEROUS_DUAL_USE)
@pytest.mark.parametrize("protocol", [2, 4])
def test_dangerous_dual_use_arguments_are_flagged(ctor, args, protocol):
    import operator
    blob = pickle.dumps(getattr(operator, ctor)(*args), protocol=protocol)
    blocklist = scan_pickle_stream(blob)
    strict = scan_pickle_stream(blob, strict_mode=True)

    assert blocklist, f"{ctor}{args} should be reported"
    assert strict, f"{ctor}{args} should be reported in strict mode"
    # The finding names the argument, not just the constructor.
    assert args[0] in blocklist[0]


def test_dual_use_argument_judgement_is_directly_testable():
    from aisbom.safety import dual_use_argument_is_dangerous as bad

    assert bad("name") is False
    assert bad("weight") is False
    assert bad("") is False
    assert bad(None) is False
    assert bad("__globals__") is True
    assert bad("__class__.__mro__") is True
    assert bad("system") is True


def test_functools_reduce_alone_is_not_reported():
    """The callable it is given is what matters, and that is caught separately."""
    from aisbom.safety import is_dangerous_global
    assert is_dangerous_global("functools", "reduce") is False


# --- false-positive guards (the main risk of this change) ----------------

REAL_CHECKPOINT_GLOBALS = [
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch", "FloatStorage"),
    ("torch", "LongStorage"),
    ("torch.storage", "_load_from_bytes"),
    ("torch.nn.modules.linear", "Linear"),
    ("torch.nn.modules.container", "Sequential"),
    ("torch.nn.modules.activation", "ReLU"),
    ("collections", "OrderedDict"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy", "dtype"),
    ("numpy", "ndarray"),
    ("builtins", "complex"),
    ("re", "_compile"),
    ("copyreg", "_reconstructor"),
    ("datetime", "datetime"),
    ("pathlib", "PurePosixPath"),
]


@pytest.mark.parametrize("module,name", REAL_CHECKPOINT_GLOBALS)
def test_real_checkpoint_globals_are_never_flagged(module, name):
    """These appear in genuine model files. Flagging any of them is a defect."""
    assert is_dangerous_global(module, name) is False
    assert _is_safe_import(module, name) is True
    assert scan_pickle_stream(harmless_reduce_pickle(module, name)) == []
    assert scan_pickle_stream(harmless_reduce_pickle(module, name), strict_mode=True) == []


def _benign_objects():
    return {
        "state_dict": {"state_dict": {"layer.weight": [0.1, 0.2]}},
        "ordered_dict": collections.OrderedDict([("w", [1.0]), ("b", [2.0])]),
        "nested_ordered": collections.OrderedDict([("a", collections.OrderedDict([("b", 1)]))]),
        "defaultdict": collections.defaultdict(list, {"a": [1]}),
        "deque": collections.deque([1, 2, 3]),
        "counter": collections.Counter("aabbcc"),
        "mixed_tuple": (1, 2.5, "three", b"four", None, True),
        "sets": {"s": {1, 2}, "f": frozenset([3, 4])},
        "complex": complex(1, 2),
        "regex": re.compile(r"^layer\.\d+$"),
        "datetime": datetime.datetime(2026, 1, 1, 12, 0, 0),
        "timedelta": datetime.timedelta(days=3, seconds=42),
        "path": pathlib.PurePosixPath("/models/checkpoint.pt"),
        "decimal": decimal.Decimal("3.14159"),
        "fraction": fractions.Fraction(3, 7),
        "uuid": uuid.UUID("12345678-1234-5678-1234-567812345678"),
        "bytearray": bytearray(b"weights"),
    }


@pytest.mark.parametrize("label", sorted(_benign_objects()))
@pytest.mark.parametrize("protocol", [2, 4, 5])
def test_ordinary_pickled_objects_are_clean_in_both_modes(label, protocol):
    """A broad sweep of things a checkpoint plausibly contains.

    Protocol 4 and 5 matter specifically: they reach globals through
    STACK_GLOBAL, the same opcode an allowlist-abuse payload uses.
    """
    blob = pickle.dumps(_benign_objects()[label], protocol=protocol)
    assert scan_pickle_stream(blob) == []
    assert scan_pickle_stream(blob, strict_mode=True) == []


def test_a_benign_ordered_dict_is_indistinguishable_from_the_allowlist_abuse_shape():
    """Why allowlist abuse is not flagged, recorded as an executable fact.

    An ordinary OrderedDict state_dict at protocol 4 reaches an allowlisted
    global through STACK_GLOBAL and immediately REDUCEs it — the same
    observable sequence as a payload that shadows a trusted name. Any rule
    keyed on that shape would flag essentially every real checkpoint, so the
    scorecard leaves that case at 'partial' rather than buying a detection
    with false positives on ordinary models.
    """
    import io
    import pickletools

    benign = pickle.dumps(collections.OrderedDict([("w", [1.0])]), protocol=4)
    abuse = harmless_stack_global_pickle("collections", "OrderedDict")

    def signature(blob):
        ops = [op.name for op, _a, _p in pickletools.genops(io.BytesIO(blob))]
        return {"STACK_GLOBAL" in ops, "REDUCE" in ops}

    assert signature(benign) == signature(abuse) == {True}
    assert scan_pickle_stream(benign) == []
    assert scan_pickle_stream(benign, strict_mode=True) == []


# --- table hygiene --------------------------------------------------------

def test_original_blocklist_entries_are_preserved():
    """Expanding the table must not drop what it already caught."""
    for module, name in [
        ("os", "system"), ("os", "popen"), ("os", "execl"), ("os", "execvp"),
        ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "check_call"),
        ("subprocess", "check_output"), ("subprocess", "run"),
        ("builtins", "eval"), ("builtins", "exec"), ("builtins", "compile"),
        ("builtins", "open"),
        ("posix", "system"), ("posix", "popen"),
        ("webbrowser", "open"),
        ("socket", "socket"), ("socket", "connect"),
    ]:
        assert is_dangerous_global(module, name) is True, f"{module}.{name}"


def test_execution_attribute_names_match_exactly_not_as_substrings():
    """`_load_from_bytes` must not match `load`; `evaluate` must not match `eval`."""
    assert _is_safe_import("torch.storage", "_load_from_bytes") is True
    assert _is_safe_import("torch", "evaluate") is True
    assert _is_safe_import("torch", "systematic") is True
    assert _is_safe_import("torch", "compiler_config") is True


def test_empty_and_malformed_globals_do_not_crash():
    assert is_dangerous_global("", "") is False
    assert is_dangerous_global(None, None) is False
    assert is_dangerous_global("os", "") is False
    assert _is_safe_import("", "x") is False


def test_blocklist_names_are_all_plausible_attributes():
    """Guard against a stray empty entry silently disabling a module."""
    for module, names in DANGEROUS_GLOBALS.items():
        assert names, f"{module} has an empty name set"
        assert all(isinstance(n, str) and n for n in names), module


def test_execution_attribute_set_is_non_empty_and_stringly_typed():
    assert EXECUTION_ATTRIBUTE_NAMES
    assert all(isinstance(n, str) and n for n in EXECUTION_ATTRIBUTE_NAMES)


# --- end to end -----------------------------------------------------------

def test_bdb_gadget_in_a_model_file_is_critical(tmp_path):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", harmless_reduce_pickle("bdb", "Bdb"))
        z.writestr("archive/version", "3")
    (tmp_path / "model.pt").write_bytes(buf.getvalue())

    from aisbom.scanner import DeepScanner
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "bdb.Bdb" in art["risk_level"]


def test_gadget_model_exits_two(tmp_path, monkeypatch):
    import io
    import zipfile
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", harmless_reduce_pickle("asyncio", "create_subprocess_shell"))
        z.writestr("archive/version", "3")
    (tmp_path / "gadget.pt").write_bytes(buf.getvalue())

    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "gadget.pt" in result.output, result.output
    assert "CRITICAL" in result.output, result.output
    assert result.exit_code == 2, result.output


def test_ordinary_model_does_not_exit_two(tmp_path, monkeypatch):
    """The false-positive guard, end to end."""
    import io
    import zipfile
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "archive/data.pkl",
            pickle.dumps(collections.OrderedDict([("layer.weight", [0.1])]), protocol=4),
        )
        z.writestr("archive/version", "3")
    (tmp_path / "ordinary.pt").write_bytes(buf.getvalue())

    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "ordinary.pt" in result.output, result.output
    assert result.exit_code == 0, result.output
