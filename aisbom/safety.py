import pickletools
import io
from typing import List, Set, Tuple

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
