import base64
import binascii
import io
import json
import pickletools
import re
from typing import Any, Dict, List, Set, Tuple

# The "Blocklist" of dangerous modules and functions
# If a model tries to import these, it is trying to break out of the sandbox.
#
# The entries below the original six close the *indirect* paths: reaching an
# executable sink through a module nobody thinks to blocklist. A debugger's
# `run`, an event loop's subprocess transport and a package installer's entry
# point all execute attacker-chosen code just as surely as `os.system` does,
# and each has been used in a published picklescan bypass.
#
# Every addition was checked against the globals a genuine checkpoint carries —
# `torch._utils._rebuild_tensor_v2`, `torch.FloatStorage`,
# `torch.storage._load_from_bytes`, `collections.OrderedDict`,
# `numpy.core.multiarray._reconstruct`, `numpy.dtype`, `numpy.ndarray`,
# `builtins.complex` — because a scanner that flags ordinary models is a
# scanner people switch off, and that is a worse outcome than a missed case.
DANGEROUS_GLOBALS = {
    "os": {"system", "popen", "execl", "execvp", "execv", "execve", "spawnl", "spawnv"},
    "subprocess": {"Popen", "call", "check_call", "check_output", "run", "getoutput", "getstatusoutput"},
    "builtins": {"eval", "exec", "compile", "open", "__import__", "breakpoint", "input"},
    "posix": {"system", "popen", "execv", "spawnv"},
    "nt": {"system", "popen", "execv", "spawnv"},
    "webbrowser": {"open", "open_new", "open_new_tab", "get"},
    "socket": {"socket", "connect", "create_connection"},

    # Debugger gadgets. `Bdb.run` and friends compile and execute a string;
    # the debugger module itself is the "benign-looking" part.
    "bdb": {"Bdb", "run", "runeval", "runcall", "runctx"},
    "pdb": {"Pdb", "run", "runeval", "runcall", "set_trace", "post_mortem"},

    # Event-loop gadgets: the subprocess transports spawn a process, and the
    # loop's own run methods execute a supplied coroutine.
    "asyncio": {
        "create_subprocess_shell", "create_subprocess_exec", "run",
        "get_event_loop", "new_event_loop", "SelectorEventLoop",
    },
    "asyncio.unix_events": {
        "_UnixSubprocessTransport", "_UnixDefaultEventLoopPolicy", "SelectorEventLoop",
    },
    "asyncio.base_events": {"BaseEventLoop"},
    "asyncio.base_subprocess": {"BaseSubprocessTransport"},
    "asyncio.subprocess": {"create_subprocess_shell", "create_subprocess_exec"},
    "asyncio.events": {"get_event_loop", "new_event_loop"},

    # Package installation as code execution.
    "pip": {"main"},
    "pip._internal": {"main"},
    "pip._internal.cli.main": {"main"},
    "setuptools": {"setup"},

    # Terminal / process spawning.
    "pty": {"spawn", "fork", "openpty"},
    "platform": {"popen", "_syscmd_ver"},
    "multiprocessing": {"Process", "Pool"},

    # Import-mechanism abuse — the primitive a shadowing attack needs before it
    # can make an allowlisted name resolve somewhere else.
    "importlib": {"import_module", "reload", "__import__"},
    "importlib.util": {"spec_from_file_location", "module_from_spec"},
    "importlib.machinery": {"SourceFileLoader", "ExtensionFileLoader"},
    "imp": {"load_source", "load_module", "load_dynamic", "load_compiled"},
    "runpy": {"run_path", "run_module", "_run_code", "_run_module_code"},
    "pkgutil": {"get_loader", "find_loader"},
    "sys": {"modules", "settrace", "setprofile", "_getframe", "exit"},

    # Interactive interpretation and timing helpers that take code as a string.
    "code": {"interact", "InteractiveInterpreter", "InteractiveConsole", "compile_command"},
    "codeop": {"compile_command", "Compile", "CommandCompiler"},
    "timeit": {"timeit", "repeat", "Timer"},
    "cProfile": {"run", "runctx", "Profile"},
    "profile": {"run", "runctx", "Profile"},

    # Native code loading.
    "ctypes": {"CDLL", "cdll", "WinDLL", "windll", "PyDLL", "LibraryLoader", "CFUNCTYPE"},

    # dill extends pickle to serialize things pickle cannot: functions, lambdas,
    # classes defined at the prompt. It does that by putting a *marshalled code
    # object* in the stream and rebuilding it on load — the same construct that
    # makes a Keras `Lambda` layer an execution vector, and executable without
    # any further precondition. The names below are the ones that reconstruct or
    # import code.
    #
    # `_create_type`, `_load_type` and `_create_array` are deliberately absent:
    # they name a type or rebuild an array and execute nothing on their own. A
    # dill file holding only data emits none of these entries at all, which is
    # what keeps an ordinary `.dill` scanning clean.
    "dill._dill": {"_create_function", "_create_code", "_import_module", "_get_attr"},
    "dill": {"loads", "load"},
}

# Callable-construction helpers that are genuinely dual-use. `methodcaller` and
# `attrgetter` build a callable from a *name given as a string*, so
# `methodcaller("system")` reaches a sink without ever naming it as a global —
# but `attrgetter("name")` is an ordinary helper that real code serializes.
#
# Listing them unconditionally would flag every checkpoint that stores one, so
# the argument decides: these are reported only when the name they fetch is
# itself an execution sink or an introspection primitive. `functools.reduce` is
# deliberately absent — the dangerous callable it is handed appears as its own
# global and is caught on its own merits.
DUAL_USE_CONSTRUCTORS = {
    ("operator", "methodcaller"),
    ("operator", "attrgetter"),
    ("_operator", "methodcaller"),
    ("_operator", "attrgetter"),
}

# Introspection primitives that make an attribute fetch an escape chain.
_ESCAPE_ATTRIBUTE_NAMES = {
    "__class__", "__bases__", "__base__", "__mro__", "__subclasses__",
    "__globals__", "__builtins__", "__import__", "__init__", "__code__",
    "__reduce__", "__getattribute__", "__dict__", "__func__", "__self__",
    "__module__", "__loader__", "__spec__",
}

# Modules whose *whole family* is dangerous: a dotted submodule inherits the
# parent's entry, so `asyncio.unix_events.X` is judged against `asyncio` too.
# Without this a new submodule name sidesteps the table by not being listed.
DANGEROUS_MODULE_FAMILIES = ("asyncio", "importlib", "pip", "ctypes", "multiprocessing")

# Attribute names that execute something, whatever module they are reached
# through. This is the generalization of the table above: it catches the next
# "benign module, dangerous method" pair without waiting for it to be listed.
#
# Matched exactly, never as a substring — `torch.storage._load_from_bytes` must
# not match `load`, and it does not.
EXECUTION_ATTRIBUTE_NAMES = {
    "system", "popen", "spawn", "spawnl", "spawnv", "fork", "forkpty",
    "exec", "execv", "execl", "execfile", "eval", "compile",
    "run", "runeval", "runcall", "runctx", "run_path", "run_module",
    "call", "check_call", "check_output", "getoutput", "getstatusoutput",
    "Popen", "check_response",
    "import_module", "__import__", "load_module", "load_source", "load_dynamic",
    "interact", "compile_command",
}

# Strict allowlist mode: only these modules/functions are permitted
SAFE_MODULES = {
    "torch",
    "numpy",
    "collections",
    "builtins",
    "copyreg",
    "__builtin__",
    "typing",
    "datetime",
    # Expanded Safe List
    "pathlib",
    "posixpath",
    "ntpath",
    "re",
    "copy",
    "functools",
    "operator",
    "warnings",
    "contextlib",
    "abc",
    "enum",
    "dataclasses",
    "types",
    "_operator",
    "complex",
    # Ordinary value types that turn up in model metadata and configs. Strict
    # mode flagged these before, purely for being unrecognized; none of them
    # carries an execution-shaped attribute, and the attribute check above
    # still governs them.
    "decimal",
    "fractions",
    "uuid",
    "numbers",
    "array",
    "struct",
    "math",
    "itertools",
    "string",
    # Serialization wrappers whose own globals are structural, not executable.
    # A joblib file records its arrays through `joblib.numpy_pickle`, and a dill
    # file records types through `dill._dill`; strict mode flagged both purely
    # for being unrecognized, which made every benign artifact in those formats
    # unscannable in the mode that is supposed to be the careful one.
    #
    # Scoped precisely: `joblib.numpy_pickle`, not `joblib`, so `joblib.parallel`
    # and anything else in the package stays unknown and stays flagged. `dill`
    # is allowlisted as a package, but the DANGEROUS_GLOBALS entries above are
    # checked first and still win — an allowlisted module cannot launder a sink.
    "joblib.numpy_pickle",
    "dill",
}

SAFE_BUILTINS = {
    "getattr", "setattr", "bytearray", "dict", "list", "set", "tuple",
    # Expanded Builtins
    "slice", "frozenset", "range", "complex",
    "bool", "int", "float", "str", "bytes", "object",
}

def _module_roots(module: str):
    """Yield a dotted module and each of its ancestors, longest first.

    ``asyncio.unix_events`` yields ``asyncio.unix_events`` then ``asyncio``, so
    a rule written against a package also governs its submodules.
    """
    parts = (module or "").split(".")
    for cut in range(len(parts), 0, -1):
        yield ".".join(parts[:cut])


def is_dangerous_global(module: str, name: str) -> bool:
    """True if ``module.name`` is a known execution sink, direct or indirect.

    Checks the exact pair, then the module's ancestors for the families where a
    submodule inherits the parent's entry, then the attribute name on its own —
    so a sink reached through an unlisted submodule is still caught.
    """
    if not module or not name:
        return False

    for candidate in _module_roots(module):
        listed = DANGEROUS_GLOBALS.get(candidate)
        if listed and name in listed:
            return True
        # For a dangerous family, any attribute that executes something counts,
        # even one nobody has enumerated yet.
        if candidate in DANGEROUS_MODULE_FAMILIES and name in EXECUTION_ATTRIBUTE_NAMES:
            return True

    return False


def _is_safe_import(module: str, name: str) -> bool:
    """Validate an import against strict (allowlist) mode.

    Strict mode answers "is this recognized as safe", but a name being reached
    through a recognized module is not enough on its own: the attribute has to
    be innocuous too. An allowlisted package with an execution-shaped attribute
    (`.run`, `.system`, `.popen`) is exactly the "benign prefix" shape this is
    meant to close, so that check runs before the module allowlist.
    """
    if not module:
        return False

    # 0. A known sink is never safe, whatever its module looks like.
    if is_dangerous_global(module, name):
        return False

    # 1. An execution-shaped attribute is not safe even on an allowlisted
    #    module. Builtins are exempted here because SAFE_BUILTINS is an explicit
    #    allowlist of names, checked below, and it is narrower than this rule.
    if module not in ("builtins", "__builtin__") and name in EXECUTION_ATTRIBUTE_NAMES:
        return False

    # 2. Exact-match safe modules, and their submodules. Real checkpoints carry
    #    globals like `torch.nn.modules.linear.Linear` and
    #    `numpy.core.multiarray._reconstruct`, so submodules of an allowlisted
    #    package have to be permitted — with step 1 above as the guard rail.
    for candidate in _module_roots(module):
        if candidate in SAFE_MODULES:
            if candidate in ("builtins", "__builtin__"):
                return name in SAFE_BUILTINS
            return True

    # 3. Codecs (explicitly allow encode/decode only).
    if module == "_codecs" and name in ("encode", "decode"):
        return True

    return False

def dual_use_argument_is_dangerous(argument) -> bool:
    """True if a name handed to `attrgetter`/`methodcaller` reaches a sink.

    ``methodcaller("upper")`` builds an ordinary callable; ``methodcaller(
    "system")`` builds one that runs a command. Dotted forms count too, since
    ``attrgetter("__class__.__mro__")`` walks the chain in a single call.
    """
    if not isinstance(argument, str) or not argument:
        return False
    for part in argument.split("."):
        if part in EXECUTION_ATTRIBUTE_NAMES or part in _ESCAPE_ATTRIBUTE_NAMES:
            return True
    return False

# A legacy `torch.save` file is several pickles laid end to end, so a scan that
# stops at the first STOP never reaches the object.
#
# Walking them needs a work limit, because the smallest valid pickle is two
# bytes (`N.`) and a 10MB file of them would otherwise mean five million
# disassembly calls — seconds of CPU per file, multiplied across a directory.
#
# But a silent limit is itself an evasion: pad a file with that many trivial
# pickles and the payload sits past the last stream examined, while the file is
# reported as though fully scanned. So the limit is generous — five orders of
# magnitude above the five streams a real legacy checkpoint carries — and
# reaching it is *reported*, never silently swallowed. "We stopped looking" and
# "there is nothing there" are different answers.
PICKLE_MAX_STREAMS = 50_000

# Emitted when the walk stops with bytes still unexamined. Callers must treat a
# result carrying this as "not fully scanned" rather than as a clean bill.
PICKLE_SCAN_INCOMPLETE = "PICKLE_SCAN_INCOMPLETE"


def _scan_single_stream(data: bytes, start: int, strict_mode: bool, threats: List[str],
                        stream=None):
    """Disassemble one pickle from ``start``; return the offset past its STOP.

    Returns ``None`` when the stream ends without a STOP (truncated or not a
    pickle at all), which is the signal to stop looking for another one. Any
    threats found before that point are still recorded — a corrupt tail must not
    discard what the front of the stream already revealed.
    """
    memo = []  # recent string values, for STACK_GLOBAL
    # `STACK_GLOBAL` takes its module and name from the stack, and either can get
    # there from the pickle's *memo table* rather than from a literal immediately
    # before it. A real joblib file does exactly that:
    #
    #     SHORT_BINUNICODE 'dtype'   <- a dict key
    #     BINGET 8                   <- pushes 'numpy', memoized much earlier
    #     SHORT_BINUNICODE 'dtype'
    #     STACK_GLOBAL               <- numpy.dtype
    #
    # Watching only the literals resolves that as `dtype.dtype`, which is both a
    # false positive (the real global is allowlisted) and, on other shapes, a
    # false negative — a genuinely dangerous global reached through the memo
    # resolves to a module name that matches nothing in the tables.
    #
    # Tracking the table needs no stack simulation: a memo entry is always the
    # value that was just pushed, so remembering the last push is enough.
    memo_table: Dict[int, Any] = {}
    memo_index = 0        # MEMOIZE assigns indices in order from zero
    last_push: Any = None  # the value a MEMOIZE/PUT would record
    # One buffer is reused across the whole walk; allocating a fresh view per
    # stream is what made a file of tiny pickles expensive.
    if stream is None:
        stream = io.BytesIO(data)
    stream.seek(start)

    # A dual-use constructor is judged by the name it is given, so the decision
    # waits for the arguments between the global and its REDUCE.
    pending = {"ctor": None, "args": []}

    def resolve(module, name):
        if not module or not name:
            return
        if (module, name) in DUAL_USE_CONSTRUCTORS:
            # Defer: the argument decides. Recorded even in strict mode, where
            # the module is allowlisted and would otherwise pass unexamined.
            pending["ctor"] = (module, name)
            pending["args"] = []
            return
        if strict_mode:
            if not _is_safe_import(module, name):
                threats.append(f"UNSAFE_IMPORT: {module}.{name}")
        elif is_dangerous_global(module, name):
            threats.append(f"{module}.{name}")

    def settle_dual():
        ctor, args = pending["ctor"], pending["args"]
        if ctor and any(dual_use_argument_is_dangerous(a) for a in args):
            module, name = ctor
            bad = next(a for a in args if dual_use_argument_is_dangerous(a))
            label = f"{module}.{name}({bad!r})"
            threats.append(f"UNSAFE_IMPORT: {label}" if strict_mode else label)
        pending["ctor"] = None
        pending["args"] = []

    try:
        for opcode, arg, pos in pickletools.genops(stream):
            if opcode.name in ("SHORT_BINUNICODE", "UNICODE", "BINUNICODE",
                               "BINUNICODE8"):
                memo.append(arg)
                if len(memo) > 2:
                    memo.pop(0)
                last_push = arg
                if pending["ctor"] is not None:
                    pending["args"].append(arg)

            elif opcode.name == "MEMOIZE":
                memo_table[memo_index] = last_push
                memo_index += 1

            elif opcode.name in ("BINPUT", "PUT", "LONG_BINPUT"):
                # Protocol 3 and below name the slot explicitly.
                memo_table[arg] = last_push

            elif opcode.name in ("BINGET", "GET", "LONG_BINGET"):
                cached = memo_table.get(arg)
                last_push = cached
                if isinstance(cached, str):
                    memo.append(cached)
                    if len(memo) > 2:
                        memo.pop(0)
                    if pending["ctor"] is not None:
                        pending["args"].append(cached)

            else:
                # Anything else that reaches the stack is not a string, so a
                # MEMOIZE that follows must not record a stale one.
                last_push = None

            if opcode.name == "GLOBAL":
                # Arg is "module\nname"
                if isinstance(arg, str) and "\n" in arg:
                    module, name = arg.split("\n", 1)
                elif isinstance(arg, str) and " " in arg:
                    # Some protocols encode as "module name" (space-separated)
                    module, name = arg.split(" ", 1)
                else:
                    module, name = None, None
                resolve(module, name)

            elif opcode.name == "STACK_GLOBAL":
                if len(memo) == 2:
                    # The module/name pair is not an argument to a pending
                    # constructor; drop it from whatever was collected.
                    if pending["ctor"] is not None:
                        for used in memo:
                            if pending["args"] and pending["args"][-1] == used:
                                pending["args"].pop()
                    resolve(memo[0], memo[1])
                # Clear memo after use to avoid false positives
                memo.clear()

            elif opcode.name in ("REDUCE", "NEWOBJ", "OBJ", "INST"):
                settle_dual()

            elif opcode.name == "STOP":
                settle_dual()
                # `pos` is an absolute offset into the buffer.
                return pos + 1
    except Exception:
        # Malformed downstream; keep whatever was found before the break.
        settle_dual()
        return None

    settle_dual()
    return None


# --- SALVAGE PASS: globals in bytes the structural walk could not reach ---
#
# A structural disassembly stops dead at the first byte it cannot account for,
# and joblib guarantees that happens: it writes the pickle up to an array
# wrapper, then dumps the raw array buffer inline, then resumes pickling. On a
# real model file `pickletools.genops` therefore dies a couple of hundred bytes
# in, and everything after the first array — which is where a payload would
# naturally sit — was never examined. It was not reported as unexamined either:
# the walk simply returned what it had, and the file read as clean.
#
# So the remaining bytes get a second, non-structural pass that looks for the
# two ways a global can be spelled. It is strictly additive: it can only find
# globals the structural walk never saw, and it runs only when that walk stopped
# early.
#
# What it deliberately cannot do is judge a dual-use constructor, because the
# argument that decides is a stack relationship and this pass has no stack.
# `operator.methodcaller("system")` hidden behind a raw array block is therefore
# out of reach; there is a test that says so.

# `c` + "module\nname\n" — the protocol 0/1 spelling.
_GLOBAL_OPCODE = re.compile(
    rb"c([A-Za-z_][A-Za-z0-9_.]{0,255})\n([A-Za-z_][A-Za-z0-9_.]{0,255})\n"
)

_STACK_GLOBAL_OPCODE = 0x93
_SHORT_BINUNICODE_OPCODE = 0x8C
_BINUNICODE_OPCODE = 0x58

# How far back a `STACK_GLOBAL`'s two operands may be spelled out. A module and
# a name are short; this is generous and keeps the backward walk bounded.
_SALVAGE_LOOKBACK = 320

# Ceilings so that a large adversarial buffer cannot turn the pass into the
# denial of service that removing the stream cap would have been.
_SALVAGE_MAX_CANDIDATES = 200_000
_SALVAGE_MAX_FINDINGS = 50


def _string_ending_at(data: bytes, end: int) -> Tuple[str, int] | None:
    """Read backwards for a unicode push whose bytes finish exactly at ``end``.

    Returns ``(value, start_offset)``. Anchoring on the end is what makes this
    unambiguous: a length-prefixed string can be identified without knowing
    where it began, because only one starting offset makes its declared length
    land on the byte we already have.
    """
    for size in range(0, min(256, end - 1)):
        start = end - 2 - size
        if start < 0:
            break
        if data[start] == _SHORT_BINUNICODE_OPCODE and data[start + 1] == size:
            try:
                return data[start + 2:end].decode("utf-8"), start
            except UnicodeDecodeError:
                return None

    for size in range(0, min(_SALVAGE_LOOKBACK, end - 4)):
        start = end - 5 - size
        if start < 0:
            break
        if data[start] == _BINUNICODE_OPCODE:
            declared = int.from_bytes(data[start + 1:start + 5], "little")
            if declared == size:
                try:
                    return data[start + 5:end].decode("utf-8"), start
                except UnicodeDecodeError:
                    return None
    return None


# A `MEMOIZE` (and, at lower protocols, a `BINPUT`) sits between a string and
# whatever consumes it, so the operands of a `STACK_GLOBAL` are rarely flush
# against it. Real bytes look like:
#
#     \x8c\x05posix  \x94  \x8c\x06system  \x94  \x93
#
# Anchoring strictly on the end byte therefore finds nothing at all. A couple of
# bytes of slack are allowed instead, and the length check still decides — a
# candidate only resolves when its declared length lands exactly where it must.
_SALVAGE_SLACK = 3


def _string_before(data: bytes, end: int) -> Tuple[str, int] | None:
    """``_string_ending_at`` with a few bytes of tolerance for memo opcodes."""
    for back in range(_SALVAGE_SLACK + 1):
        if end - back < 2:
            break
        found = _string_ending_at(data, end - back)
        if found:
            return found
    return None


def salvage_globals(data: bytes, start: int = 0) -> List[Tuple[str, str]]:
    """Recover ``(module, name)`` pairs from a buffer without disassembling it.

    Used on the region a structural walk could not cross. Both spellings are
    handled: the `GLOBAL` opcode's newline-delimited pair, and `STACK_GLOBAL`
    preceded by two unicode pushes. Order is preserved and duplicates are kept
    out, so a repeating pattern in array data cannot flood the result.
    """
    found: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    if start >= len(data):
        return found
    region = data[start:]

    for match in _GLOBAL_OPCODE.finditer(region):
        pair = (match.group(1).decode("ascii"), match.group(2).decode("ascii"))
        if pair not in seen:
            seen.add(pair)
            found.append(pair)
        if len(found) >= _SALVAGE_MAX_FINDINGS:
            return found

    cursor = 0
    examined = 0
    while examined < _SALVAGE_MAX_CANDIDATES:
        at = region.find(bytes([_STACK_GLOBAL_OPCODE]), cursor)
        if at == -1:
            break
        cursor = at + 1
        examined += 1

        name = _string_before(region, at)
        if not name:
            continue
        module = _string_before(region, name[1])
        if not module:
            continue
        pair = (module[0], name[0])
        if pair not in seen:
            seen.add(pair)
            found.append(pair)
        if len(found) >= _SALVAGE_MAX_FINDINGS:
            break

    return found


def _judge_salvaged(pairs, strict_mode: bool, threats: List[str]) -> None:
    """Judge salvaged pairs against the blocklist only, in either mode.

    Strict mode's allowlist is deliberately not applied here. Its premise —
    "anything unrecognized is suspicious" — needs names resolved *exactly*, and
    this pass resolves them approximately: with no memo table it cannot see that
    the module operand of a `STACK_GLOBAL` arrived from a `BINGET`, so a real
    `numpy.dtype` reads as `dtype.dtype`. Handing an allowlist a garbled name
    manufactures a false positive on every ordinary joblib file.

    The blocklist has no such problem: it fires only on an exact match against a
    known sink, and a garbled name matches nothing. The cost is that an
    unrecognized-but-not-blocklisted import hidden behind a raw array block is
    not reported in strict mode; there is a test that says so.
    """
    already = set(threats)
    for module, name in pairs:
        if not is_dangerous_global(module, name):
            continue
        label = f"UNSAFE_IMPORT: {module}.{name}" if strict_mode else f"{module}.{name}"
        if label not in already:
            already.add(label)
            threats.append(label)


def scan_pickle_stream(data: bytes, strict_mode: bool = False) -> List[str]:
    """
    Disassembles a pickle stream and checks for dangerous imports.
    Returns a list of detected threats (e.g., ["os.system"]).

    A file may hold several pickles end to end — this is exactly what
    ``torch.save`` writes in its legacy (non-ZIP) format, where a magic number,
    a protocol version and a sys-info dict all precede the object itself. Every
    stream is scanned, because stopping at the first STOP would mean never
    looking at the payload in such a file.

    The walk stops at ``PICKLE_MAX_STREAMS`` to bound work on a file made of
    minimal two-byte pickles. If that happens with bytes still unexamined, the
    returned list carries ``PICKLE_SCAN_INCOMPLETE`` so the caller cannot mistake
    an unfinished scan for a clean one — a silent limit would just be somewhere
    to hide a payload.
    """
    threats: List[str] = []
    offset = 0
    buffer = io.BytesIO(data)

    for _ in range(PICKLE_MAX_STREAMS):
        # Terminates because a stream is only followed when it ended strictly
        # further into the buffer than it began, and the buffer is finite.
        next_offset = _scan_single_stream(data, offset, strict_mode, threats, buffer)
        if next_offset is None or next_offset <= offset:
            # The walk stopped without reaching a STOP: either these bytes are
            # not a pickle at all, or one has raw data spliced into it. Both
            # leave the rest of the buffer unread, so it gets the salvage pass
            # rather than being reported as though it had been scanned.
            _judge_salvaged(salvage_globals(data, offset), strict_mode, threats)
            return threats
        offset = next_offset
        if offset >= len(data):
            return threats

    # Ran out of budget with bytes left over.
    threats.append(PICKLE_SCAN_INCOMPLETE)
    return threats


# --- KERAS LAMBDA-LAYER DETECTION ---
#
# A Keras `Lambda` layer serializes an arbitrary Python callable into the model
# config as a base64-encoded marshalled code object, and `load_model` executes
# it. That makes the model config itself an execution vector, in the same way a
# pickle stream is — so it gets the same treatment: read the serialized form,
# recognize the dangerous construct, never run it. Nothing here calls
# `marshal.loads`; a payload is identified from its header bytes alone.

# `Lambda` is the layer class. `__lambda__` is how Keras 3 tags the serialized
# callable *inside* that layer's config — a distinct finding, reported under its
# own prefix so one Lambda layer isn't counted twice. Keeping the second check
# is deliberate defence in depth: it still fires when the embedded blob is in a
# form the marshal header check below doesn't recognise.
KERAS_LAMBDA_LAYER_CLASS = "lambda"
KERAS_SERIALIZED_LAMBDA_CLASS = "__lambda__"
KERAS_LAMBDA_CLASS_NAMES = {KERAS_LAMBDA_LAYER_CLASS, KERAS_SERIALIZED_LAMBDA_CLASS}

# CPython marshal type code for a code object: TYPE_CODE ('c', 0x63), or the
# same with FLAG_REF set (0xE3), which is what `marshal.dumps` actually emits.
_MARSHAL_CODE_PREFIXES = (0x63, 0xE3)

# A marshalled code object is always far larger than this; the floor keeps
# short incidental base64 (flags, small blobs) out of the check.
_MIN_MARSHAL_B64_LEN = 24

_B64_CHARS = re.compile(r"\A[A-Za-z0-9+/=\s]+\Z")

# Signatures for the coarse byte-level fallback below.
_LAMBDA_BYTE_SIGNATURES = (
    b'"class_name": "Lambda"',
    b'"class_name":"Lambda"',
    b'"class_name": "__lambda__"',
    b'"class_name":"__lambda__"',
)

# Depth guard so a hostile deeply-nested config can't exhaust the stack.
_MAX_CONFIG_DEPTH = 200


def looks_like_marshalled_code(value: Any) -> bool:
    """True if ``value`` is base64 that decodes to a Python code object.

    The payload is *never* unmarshalled — only its header is inspected. After
    the type byte, marshal writes argcount as a little-endian uint32, so a
    genuine code object always has three zero bytes at offsets 2-4. Requiring
    that structure is what keeps ordinary text beginning with ``c`` (0x63) from
    reading as a code object.
    """
    if not isinstance(value, str) or not _B64_CHARS.match(value):
        return False

    # Keras 2's `func_dump` uses codecs base64, which wraps lines at 76 chars.
    candidate = "".join(value.split())
    if len(candidate) < _MIN_MARSHAL_B64_LEN:
        return False

    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return False

    return (
        len(raw) > 8
        and raw[0] in _MARSHAL_CODE_PREFIXES
        and raw[2:5] == b"\x00\x00\x00"
    )


def _lambda_label(node: Dict[str, Any], path: str) -> str:
    """Prefer the layer's own name; fall back to its position in the config."""
    config = node.get("config")
    if isinstance(config, dict):
        name = config.get("name")
        if isinstance(name, str) and name:
            return name
    return path or "<root>"


def scan_keras_config(config: Any) -> List[str]:
    """Walk a parsed Keras model config and report code-execution vectors.

    Returns threat strings in the same spirit as ``scan_pickle_stream``:
    ``KERAS_LAMBDA: <layer name>`` for a Lambda layer,
    ``KERAS_SERIALIZED_LAMBDA: <json path>`` for a serialized callable nested
    inside one, and ``KERAS_MARSHALLED_CODE: <json path>`` for an embedded code
    object — the last reported wherever it appears, so a payload smuggled
    outside a Lambda layer is caught too.

    The walk is shape-agnostic on purpose: Keras 2 and Keras 3 nest Lambda
    layers differently, and matching on structure rather than on one expected
    layout means a new serialization shape does not silently stop being seen.
    """
    threats: List[str] = []
    seen: Set[int] = set()

    def visit(node: Any, path: str, depth: int) -> None:
        if depth > _MAX_CONFIG_DEPTH:
            return
        if isinstance(node, (dict, list)):
            # Guards against the self-referential configs a hostile file can
            # contain (and against shared subtrees being walked twice).
            if id(node) in seen:
                return
            seen.add(id(node))

        if isinstance(node, dict):
            class_name = node.get("class_name")
            if isinstance(class_name, str):
                normalized = class_name.strip().lower()
                if normalized == KERAS_LAMBDA_LAYER_CLASS:
                    threats.append(f"KERAS_LAMBDA: {_lambda_label(node, path)}")
                elif normalized == KERAS_SERIALIZED_LAMBDA_CLASS:
                    threats.append(f"KERAS_SERIALIZED_LAMBDA: {path or '<root>'}")
            for key, value in node.items():
                child = f"{path}.{key}" if path else str(key)
                visit(value, child, depth + 1)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit(value, f"{path}[{index}]", depth + 1)
        elif isinstance(node, str) and looks_like_marshalled_code(node):
            threats.append(f"KERAS_MARSHALLED_CODE: {path or '<root>'}")

    visit(config, "", 0)
    return threats


def scan_keras_config_bytes(raw: bytes) -> List[str]:
    """Coarse signature scan for a config that could not be parsed as JSON.

    A truncated or otherwise malformed container must not become a way to hide
    a payload: if the JSON cannot be recovered, the raw bytes are still
    searched for the Lambda signature. This is deliberately less precise than
    ``scan_keras_config`` — it reports that a Lambda layer is present without
    being able to name it — and it is a fallback, not the primary path.
    """
    if any(sig in raw for sig in _LAMBDA_BYTE_SIGNATURES):
        return ["KERAS_LAMBDA: <unparsed config>"]
    return []


# --- ONNX GRAPH INSPECTION ---
#
# ONNX carries no pickle, so the risk is not a payload inside the file — it is
# what loading the file makes the runtime reach for:
#
#   * **External data.** A tensor can live outside the model, addressed by a
#     relative path. A path that climbs out of the model directory (or names an
#     absolute path or a URL) turns `load_model` into an arbitrary-file read
#     against whatever the loading process can see. The ONNX specification
#     requires these paths to stay within the model directory, so one that does
#     not is a spec violation as well as a security signal.
#   * **Custom operators.** An operator in a non-standard domain cannot run
#     without a matching custom op library being registered, which is a
#     native-code load the model author chose and the model consumer inherits.

# Domains defined by the ONNX standard. Anything else is a custom operator set.
# The empty domain is the default (ai.onnx).
ONNX_STANDARD_DOMAINS = {
    "",
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.training",
    "ai.onnx.preview.training",
}

# A URL-ish scheme prefix: `http://`, `file://`, `s3://` …
_URL_SCHEME = re.compile(r"\A[A-Za-z][A-Za-z0-9+.\-]*://")

# A Windows drive-letter path: `C:\…` or `C:/…`
_WINDOWS_DRIVE = re.compile(r"\A[A-Za-z]:[\\/]")


def external_location_escapes(location: str) -> bool:
    """True if an external-data path leaves the model's own directory.

    Absolute paths, Windows drive paths, UNC paths and URLs escape by
    definition. Relative paths are resolved by tracking depth, so ``a/../b``
    (which stays put) is not reported while ``../secrets`` and ``a/../../etc``
    are. Resolution is textual on purpose — the point is to judge what the file
    *asks for*, without touching the filesystem it is asking about.
    """
    if not isinstance(location, str) or not location:
        return False
    if _URL_SCHEME.match(location) or _WINDOWS_DRIVE.match(location):
        return True
    if location.startswith("/") or location.startswith("\\"):
        return True

    depth = 0
    for part in re.split(r"[\\/]+", location):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def scan_onnx_model(model: Dict[str, Any]) -> List[str]:
    """Report security signals from an extracted ONNX model structure.

    Takes the dict produced by the scanner's protobuf walk (see
    ``DeepScanner._inspect_onnx``) rather than raw bytes, so the wire-format
    decoding and the security judgement stay separable and separately testable.

    Threat strings follow the convention of the other scanners in this module:

    * ``ONNX_EXTERNAL_DATA_ESCAPE: <path>`` — reaches outside the model directory
    * ``ONNX_EXTERNAL_DATA: <path>`` — external tensor within the directory; not
      an escape, but the model is not self-contained and the bytes it will load
      are not covered by the model's own hash
    * ``ONNX_CUSTOM_OP: <domain>.<op_type>`` — operator outside the standard set
    """
    threats: List[str] = []

    for entry in model.get("external_data") or []:
        location = (entry or {}).get("location")
        if not location:
            continue
        if external_location_escapes(location):
            threats.append(f"ONNX_EXTERNAL_DATA_ESCAPE: {location}")
        else:
            threats.append(f"ONNX_EXTERNAL_DATA: {location}")

    for op in model.get("custom_ops") or []:
        domain = (op or {}).get("domain") or ""
        op_type = (op or {}).get("op_type") or "?"
        threats.append(f"ONNX_CUSTOM_OP: {domain}.{op_type}")

    return threats


def onnx_domain_is_custom(domain: str | None) -> bool:
    """True if an operator domain lies outside the ONNX standard set."""
    return (domain or "") not in ONNX_STANDARD_DOMAINS


# --- CHAT-TEMPLATE (JINJA) INSPECTION ---
#
# A GGUF model can ship a Jinja chat template in its metadata. Unlike a pickle,
# that template is not run when the file is opened — it is run on every
# inference request, which is what makes it worth reading closely: the template
# executes as a matter of using the model for its intended purpose, not as the
# result of some further mistake by the user.
#
# What the template can reach depends on who renders it, and the range is wide:
#
#   * llama.cpp renders templates with minja, a C++ subset with no Python
#     objects to reach for.
#   * `transformers.apply_chat_template` uses Jinja's sandboxed environment,
#     which blocks unsafe attribute access — sandbox escapes are still
#     published against it.
#   * plenty of tooling renders chat templates with a plain `jinja2.Template`,
#     which is unsandboxed server-side template injection.
#
# So the constructs below are graded by whether they have *any* legitimate use
# in a chat template. An attribute chain reaching `__subclasses__` does not; it
# is the standard escape primitive and nothing else. Template inclusion has a
# plausible-but-anomalous reading, so it is graded lower.
#
# NOTHING HERE RENDERS, PARSES, OR COMPILES THE TEMPLATE. Jinja is never
# imported — the template is treated purely as a string, because handing a
# hostile template to a real template engine to find out whether it is hostile
# would be the vulnerability.

# Attribute-traversal and introspection primitives. These are the building
# blocks of every published Jinja/SSTI sandbox escape and have no business in a
# template that formats chat messages.
_JINJA_ESCAPE_TOKENS = (
    "__class__",
    "__bases__",
    "__base__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__import__",
    "__init__",
    "__code__",
    "__reduce__",
    "__getattribute__",
    "__dict__",
    "__loader__",
    "__spec__",
)

# Callables that execute code or reach the OS. `popen` covers os.popen and
# subprocess.Popen; the pattern is matched case-sensitively on purpose, since
# these are exact attribute names.
_JINJA_DANGEROUS_CALLS = (
    "eval",
    "exec",
    "compile",
    "getattr",
    "setattr",
    "system",
    "popen",
    "Popen",
    "check_output",
    "subprocess",
    "importlib",
    "marshal",
    "pickle",
    "breakpoint",
)

# Jinja's `attr` filter fetches an attribute by *name*, which is the documented
# way around a filter that blocks dotted attribute access.
_JINJA_ATTR_FILTER = re.compile(r"\|\s*attr\s*\(")

# Objects a template environment may expose that leak the application context.
_JINJA_CONTEXT_LEAKS = (
    "self._TemplateReference__context",
    "lipsum",
    "cycler",
    "joiner",
)

# Tags that pull in another template — a file read chosen by the model author.
_JINJA_INCLUSION = re.compile(r"\{%-?\s*(include|extends|import|from)\b")

# Templates are metadata, not weights; anything past this is not a chat format.
JINJA_TEMPLATE_MAX_CHARS = 256 * 1024


def _word_pattern(token: str) -> re.Pattern:
    """Match ``token`` as a whole identifier, not as a substring.

    Without the boundary, ``eval`` would match inside ``evaluate`` and every
    template mentioning it would be reported.
    """
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])")


def _call_pattern(token: str) -> re.Pattern:
    """Match ``token`` only where it is *used*, not merely mentioned.

    Several of the dangerous names are ordinary English words — `system` above
    all — and chat templates compare against them as data constantly
    (``{% if message['role'] == 'system' %}``). Requiring one of the three
    shapes a real use takes keeps the mention from reading as a call:

    * ``name(``   — invoked
    * ``.name``   — reached as an attribute
    * ``name.``   — used as a module

    Combined with literal-stripping below, a role comparison no longer matches.
    """
    escaped = re.escape(token)
    return re.compile(
        r"(?:\.\s*" + escaped + r"(?![A-Za-z0-9_]))"          # .name
        r"|(?<![A-Za-z0-9_.])" + escaped + r"\s*[(.]"          # name( or name.
    )


# Jinja comments carry no behaviour, so their contents are not evidence.
_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.DOTALL)

# Single- or double-quoted string literals.
_JINJA_STRING_LITERAL = re.compile(r"'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"", re.DOTALL)


def _strip_literals_and_comments(template: str) -> str:
    """Remove comments and quoted strings, keeping the code around them.

    Only used for the *call* check. The escape-token and `attr` checks
    deliberately run against the raw template, because ``|attr('__class__')``
    hides its payload inside a string literal — stripping literals there would
    remove the very evidence being looked for.
    """
    without_comments = _JINJA_COMMENT.sub(" ", template)
    return _JINJA_STRING_LITERAL.sub(" ", without_comments)


_JINJA_ESCAPE_PATTERNS = tuple((t, _word_pattern(t)) for t in _JINJA_ESCAPE_TOKENS)
_JINJA_CALL_PATTERNS = tuple((t, _call_pattern(t)) for t in _JINJA_DANGEROUS_CALLS)
_JINJA_LEAK_PATTERNS = tuple((t, _word_pattern(t.split(".")[-1])) for t in _JINJA_CONTEXT_LEAKS)


def scan_jinja_template(template: str) -> List[str]:
    """Statically report dangerous constructs in a chat template.

    The template is a string throughout — it is never rendered, parsed by a
    template engine, or compiled.

    Threat strings, in the convention used by the other scanners here:

    * ``JINJA_SANDBOX_ESCAPE: <token>`` — attribute-traversal / introspection
      primitive with no legitimate use in a chat template
    * ``JINJA_ATTR_FILTER`` — the ``|attr()`` filter, used to fetch attributes
      by name past a dotted-access filter
    * ``JINJA_DANGEROUS_CALL: <name>`` — names a code-execution or OS callable
    * ``JINJA_CONTEXT_LEAK: <token>`` — reaches for an environment-provided
      object that exposes application context
    * ``JINJA_TEMPLATE_INCLUSION: <tag>`` — pulls in another template
    """
    if not isinstance(template, str) or not template:
        return []

    threats: List[str] = []

    # Bound the work, but never silently: padding a template past the limit
    # would otherwise be a way to hide an escape behind a wall of filler, so
    # the unread remainder is reported rather than assumed harmless.
    subject = template
    if len(template) > JINJA_TEMPLATE_MAX_CHARS:
        subject = template[:JINJA_TEMPLATE_MAX_CHARS]
        threats.append(
            f"JINJA_TEMPLATE_TRUNCATED: {len(template)} chars, "
            f"analyzed first {JINJA_TEMPLATE_MAX_CHARS}"
        )

    # Escape tokens and the attr filter are searched in the *raw* text: the
    # `|attr('__class__')` bypass carries its payload inside a string literal.
    for token, pattern in _JINJA_ESCAPE_PATTERNS:
        if pattern.search(subject):
            threats.append(f"JINJA_SANDBOX_ESCAPE: {token}")

    if _JINJA_ATTR_FILTER.search(subject):
        threats.append("JINJA_ATTR_FILTER")

    # Call and context checks run against code only, with literals and comments
    # removed, so that comparing a role to 'system' is not read as calling it.
    code = _strip_literals_and_comments(subject)

    for token, pattern in _JINJA_CALL_PATTERNS:
        if pattern.search(code):
            threats.append(f"JINJA_DANGEROUS_CALL: {token}")

    for token, pattern in _JINJA_LEAK_PATTERNS:
        if pattern.search(code):
            threats.append(f"JINJA_CONTEXT_LEAK: {token}")

    for match in _JINJA_INCLUSION.finditer(code):
        tag = f"JINJA_TEMPLATE_INCLUSION: {match.group(1)}"
        if tag not in threats:
            threats.append(tag)

    return threats


def jinja_threats_are_critical(threats: List[str]) -> bool:
    """True if any finding is an escape rather than merely anomalous.

    Escape primitives, the ``attr`` filter, dangerous callables and context
    leaks are treated as CRITICAL: a chat template is rendered on every
    inference request, so "the template runs" is not an extra precondition, it
    is what using the model means. Template inclusion alone stays below that
    line — it needs a target template to exist before it does anything.
    """
    return any(
        _threat_kind(t).startswith(
            ("JINJA_SANDBOX_ESCAPE:", "JINJA_DANGEROUS_CALL:", "JINJA_CONTEXT_LEAK:")
        )
        or _threat_kind(t) == "JINJA_ATTR_FILTER"
        for t in threats
    )


def _threat_kind(threat: str) -> str:
    """Strip the optional ``[template key] `` tag a multi-template model adds.

    Findings are tagged with the variant they came from when a model ships more
    than one chat template. Severity is a property of the finding, not of which
    template carried it, so the tag is removed before classifying.
    """
    if threat.startswith("["):
        _, _, rest = threat.partition("] ")
        return rest or threat
    return threat


def jinja_analysis_is_incomplete(threats: List[str]) -> bool:
    """True if part of the template went unread, so 'no findings' is not 'clean'."""
    return any(_threat_kind(t).startswith("JINJA_TEMPLATE_TRUNCATED:") for t in threats)
def looks_like_pickle_stream(data: bytes) -> bool:
    """True if ``data`` disassembles cleanly through to a pickle STOP opcode.

    Used to tell a legacy bare pickle apart from an ordinary text file, so the
    two can be reported honestly rather than lumped together. Deliberately
    strict — it requires reaching STOP — because a text file can begin with a
    byte that happens to be a valid opcode, and calling a config file a pickle
    is its own kind of wrong answer.

    Disassembly only. The stream is never unpickled.
    """
    if not data:
        return False
    try:
        for opcode, _arg, _pos in pickletools.genops(io.BytesIO(data)):
            if opcode.name == "STOP":
                return True
    except Exception:
        return False
    return False


class _NullWriter:
    """Sink for `pickletools.dis`, which validates by writing a listing."""

    def write(self, _text: str) -> None:
        pass


# Opcodes whose argument runs to a newline and can plausibly *start* a real
# pickle while carrying a lot of bytes. Each maps to the characters its
# argument legitimately begins with, so a file is only re-read when its second
# byte is consistent with the opcode its first byte claims to be.
#
# This guard is why a parquet file is not re-read: it opens `PAR1`, and while
# `P` is the PERSID opcode, PERSID is not on this list — no real pickle starts
# with a persistent id, and accepting it would mean re-reading every parquet,
# ORC and arrow file in a tree up to the sniff cap.
_NEWLINE_ARG_STARTS = {
    "S": b"'\"",                  # STRING — always quoted
    "V": None,                    # UNICODE — raw text, no reliable lead byte
    "I": b"0123456789+-",         # INT
    "L": b"0123456789+-",         # LONG
    "F": b"0123456789+-.",        # FLOAT
}


def _first_argument_overruns(data: bytes) -> bool:
    """Does `data`'s first opcode declare an argument longer than `data`?

    Discovery reads a bounded head and only re-reads when the head looked like
    an unfinished pickle. "At least one opcode parsed" is the usual signal, but
    a pickle that opens with a single huge literal completes *no* opcodes — so
    without this check a payload hidden behind one 64KB literal is never found,
    while the documented limit claims 16MB. Measured before it was fixed: a
    65,000-byte pad was caught and a 70,000-byte pad was not.

    Length-prefixed arguments are read exactly. Newline-terminated ones cannot
    be measured without the newline, so they are admitted only for the handful
    of opcodes that can really begin a pickle, and only when the following byte
    matches what that opcode's argument must start with.
    """
    if not data:
        return False
    op = pickletools.code2op.get(chr(data[0]))
    if op is None or op.arg is None:
        return False

    n = op.arg.n
    if n >= 0:
        # A fixed-width argument. These are a handful of bytes; they cannot be
        # what overran a 64KB read.
        return False

    if n == pickletools.UP_TO_NEWLINE:
        if op.code not in _NEWLINE_ARG_STARTS:
            return False
        if b"\n" in data:
            # The terminator is already in view, so the argument is not what
            # ran off the end — something else failed, and re-reading will not
            # change that.
            return False
        lead = _NEWLINE_ARG_STARTS[op.code]
        return lead is None or (len(data) > 1 and data[1] in lead)

    # Length-prefixed: read the declared size and believe it only far enough to
    # decide whether a bigger read would reach the end of the argument.
    widths = {
        pickletools.TAKEN_FROM_ARGUMENT1: 1,
        pickletools.TAKEN_FROM_ARGUMENT4: 4,
        pickletools.TAKEN_FROM_ARGUMENT4U: 4,
        pickletools.TAKEN_FROM_ARGUMENT8U: 8,
    }
    width = widths.get(n)
    if width is None or len(data) < 1 + width:
        return False
    declared = int.from_bytes(data[1 : 1 + width], "little")
    return 1 + width + declared > len(data)


def head_looks_like_pickle(data: bytes) -> tuple[bool, bool]:
    """Does the head of a file begin with a genuinely valid pickle?

    Used by discovery on files no extension claimed, where the question is not
    "what does this pickle import" but the earlier one: is this a pickle at
    all? Getting that wrong in either direction is expensive — miss it and a
    payload is invisible, over-claim it and every SBOM fills with phantom
    components — so the bar here is deliberately higher than elsewhere.

    Parsing as opcodes is *not* enough, and assuming it was is a trap worth
    recording: `.` is the STOP opcode, so on a "reaches STOP" test every CSS
    file that opens with a class selector is a pickle. Measured against a real
    `node_modules`, that rule claimed JavaScript, stylesheets, TypeScript
    declarations and a man page.

    So the head must *validate*: `pickletools.dis` walks the stack, and a
    pickle that pops from an empty stack or ends holding anything other than
    one object is rejected. Validation runs against the prefix ending at the
    first STOP rather than the whole buffer, so a payload followed by a corrupt
    tail — the nullifAI shape — is still recognized instead of being thrown
    out along with its own garbage.

    Returns `(is_pickle, may_be_truncated)`. The second flag is the caller's
    escalation signal: opcodes parsed cleanly but no STOP appeared, which is
    what a real pickle larger than the read window looks like.

    Disassembly only. The stream is never unpickled.
    """
    if not data:
        return (False, False)

    stop_at = None
    parsed = 0
    try:
        for opcode, _arg, pos in pickletools.genops(io.BytesIO(data)):
            parsed += 1
            if opcode.name == "STOP":
                stop_at = pos + 1
                break
    except Exception:
        pass

    if stop_at is None:
        # No complete pickle in view. Worth a bigger read if something parsed
        # — or if nothing parsed *because* the very first opcode carries an
        # argument that runs off the end of the buffer, which is the one way a
        # genuine pickle yields no opcodes at all.
        return (False, parsed > 0 or _first_argument_overruns(data))

    try:
        pickletools.dis(io.BytesIO(data[:stop_at]), out=_NullWriter())
    except Exception:
        return (False, False)
    return (True, False)
