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
    "_codecs",
}

SAFE_BUILTINS = {"getattr", "setattr", "bytearray", "dict", "list", "set", "tuple"}

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
                        is_safe = module in SAFE_MODULES
                        if module in ("builtins", "__builtin__"):
                            is_safe = is_safe and name in SAFE_BUILTINS
                        if not is_safe:
                            threats.append(f"UNSAFE_IMPORT: {module}.{name}")
                    else:
                        if module in DANGEROUS_GLOBALS and name in DANGEROUS_GLOBALS[module]:
                            threats.append(f"{module}.{name}")

            elif opcode.name == "STACK_GLOBAL":
                # Takes two arguments from the stack: module and name
                if len(memo) == 2:
                    module, name = memo
                    if strict_mode:
                        is_safe = module in SAFE_MODULES
                        if module in ("builtins", "__builtin__"):
                            is_safe = is_safe and name in SAFE_BUILTINS
                        if not is_safe:
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
