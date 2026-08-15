import base64
import binascii
import io
import json
import pickletools
import re
from typing import Any, Dict, List, Set, Tuple

# The "Blocklist" of dangerous modules and functions
# If a model tries to import these, it is trying to break out of the sandbox.
DANGEROUS_GLOBALS = {
    "os": {"system", "popen", "execl", "execvp"},
    "subprocess": {"Popen", "call", "check_call", "check_output", "run"},
    "builtins": {"eval", "exec", "compile", "open"},
    "posix": {"system", "popen"},
    "webbrowser": {"open"},
    "socket": {"socket", "connect"},
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
}

SAFE_BUILTINS = {
    "getattr", "setattr", "bytearray", "dict", "list", "set", "tuple",
    # Expanded Builtins
    "slice", "frozenset", "range", "complex",
    "bool", "int", "float", "str", "bytes", "object",
}

def _is_safe_import(module: str, name: str) -> bool:
    """Helper to validate imports against strict mode policies."""
    # 1. Exact Match Safe Modules
    if module in SAFE_MODULES:
        return True
    
    # 2. Torch Submodules (torch.*)
    if module.startswith("torch."):
        return True
    
    # 3. Codecs (Explicitly allow encode/decode only)
    if module == "_codecs" and name in ("encode", "decode"):
        return True
        
    # 4. Pathlib internals handling (pathlib._local or generic submodules of safe packages?)
    # Generally if 'pathlib' is safe, 'pathlib.anything' *should* be safe if it's code, but strict mode is strict.
    # On many python versions, Path is in 'pathlib'. 'pathlib._local' is an implementation detail.
    # Let's allow submodules of SAFE_MODULES if they start with that name?
    # No, that opens up 'os.path' if 'os' was safe (it isn't).
    # But for 'pathlib', 're', nested usage is common.
    # Let's add specific check for known safe packages that use submodules
    if module.startswith("pathlib.") or module.startswith("re.") or module.startswith("collections."):
        return True

    # 5. Builtins Checks
    if module in ("builtins", "__builtin__"):
        return name in SAFE_BUILTINS

    return False

def scan_pickle_stream(data: bytes, strict_mode: bool = False) -> List[str]:
    """
    Disassembles a pickle stream and checks for dangerous imports.
    Returns a list of detected threats (e.g., ["os.system"]).
    """
    threats = []
    memo = []  # Used to track recent string literals for STACK_GLOBAL

    try:
        stream = io.BytesIO(data)
        
        for opcode, arg, pos in pickletools.genops(stream):
            # Track the last few string literals we've seen on the stack
            if opcode.name in ("SHORT_BINUNICODE", "UNICODE", "BINUNICODE"):
                memo.append(arg)
                if len(memo) > 2:
                    memo.pop(0)

            if opcode.name == "GLOBAL":
                # Arg is "module\nname"
                if isinstance(arg, str) and "\n" in arg:
                    module, name = arg.split("\n")
                elif isinstance(arg, str) and " " in arg:
                    # Some pickle protocols encode as "module name" (space-separated)
                    module, name = arg.split(" ", 1)
                else:
                    module, name = None, None

                if module and name:
                    if strict_mode:
                        if not _is_safe_import(module, name):
                            threats.append(f"UNSAFE_IMPORT: {module}.{name}")
                    else:
                        if module in DANGEROUS_GLOBALS and name in DANGEROUS_GLOBALS[module]:
                            threats.append(f"{module}.{name}")

            elif opcode.name == "STACK_GLOBAL":
                # Takes two arguments from the stack: module and name
                if len(memo) == 2:
                    module, name = memo
                    if strict_mode:
                        if not _is_safe_import(module, name):
                            threats.append(f"UNSAFE_IMPORT: {module}.{name}")
                    else:
                        if module in DANGEROUS_GLOBALS and name in DANGEROUS_GLOBALS[module]:
                            threats.append(f"{module}.{name}")
                # Clear memo after use to avoid false positives
                memo.clear()

    except Exception as e:
        # Avoid crashing on malformed pickles
        pass

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
