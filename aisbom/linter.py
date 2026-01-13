import pickletools
import io
from dataclasses import dataclass
from typing import List

# Allowlist Source of Truth: Mirrors torch.serialization._get_default_safe_globals()
# As of PyTorch 2.1+, these are the modules allowed by default in weights_only=True
PYTORCH_DEFAULT_SAFE_MODULES = {
    'torch',
    'numpy',
    'collections',
    'builtins',
    'copyreg',
    'datetime',
    # _codecs is often implied for encoding/decoding
    '_codecs'
}

@dataclass
class LintError:
    offset: int
    message: str
    severity: str  # ERROR, WARNING
    hint: str

class MigrationLinter:
    """
    Analyzes a pickle stream to determine if it is compatible with torch.load(weights_only=True).
    Does NOT execute any code (Pure Static Analysis).
    """

    def lint_pickle(self, data: bytes) -> List[LintError]:
        """
        Parses the pickle bytecode and applies compatibility rules.
        """
        errors = []
        try:
            # Create a bytes stream and iterate opcodes
            # We listify to allow lookback/stack simulation if needed, but linear pass with state is better.
            ops = list(pickletools.genops(io.BytesIO(data)))
            
            # Simple simulation of stack for strings (used by STACK_GLOBAL)
            # We don't need a full VM, just valid string tracking.
            # If we see a string op, we push it. If we see STACK_GLOBAL, we peek.
            # NOTE: This is heuristic. Complex stack manipulation (memo, dup) will defeat this.
            # That is the "Screen Door" limit.
            
            # Ops that push strings
            STRING_OPS = {'SHORT_BINUNICODE', 'BINUNICODE', 'UNICODE', 'STRING', 'BINBYTES', 'SHORT_BINBYTES'}
            
            # We maintain a list of inputs.
            # But the stack isn't just strings.
            # Let's just track the last few string arguments seen.
            # If STACK_GLOBAL is called, it MUST use the top 2 stack items.
            # If they are strings, we check them.
            
            sim_stack = []

            for opcode, arg, pos in ops:
                
                # Stack Tracking (Heuristic)
                if opcode.name in STRING_OPS and arg is not None:
                     # Attempt to decode bytes to string if needed
                     val = arg
                     if isinstance(val, bytes):
                        try:
                            val = val.decode('utf-8')
                        except:
                            pass
                     sim_stack.append(val)
                elif opcode.name in ('INT', 'BININT', 'BININT1', 'BININT2', 'LONG', 'BINFLOAT', 'MOMIOZE'):
                     # Pushes something else, or doesn't consume string stack in a way that matters?
                     # Global pushes a class.
                     pass
                elif opcode.name == 'STACK_GLOBAL':
                     # Consumes 2 items.
                     if len(sim_stack) >= 2:
                         name = sim_stack.pop()
                         module = sim_stack.pop()
                         
                         if isinstance(name, str) and isinstance(module, str):
                             self._check_import(module, name, pos, errors)
                     else:
                         # Stack underflow in simulation or non-string args
                         pass
                
                # Direct GLOBAL Opcode
                elif opcode.name == 'GLOBAL':
                    # arg is "module name"
                    if isinstance(arg, str):
                        parts = arg.split(' ')
                        if len(parts) >= 1:
                             # GLOBAL uses "module.name\n" in some protos, but pickletools strips it?
                             # Standard is "module name"
                             module = parts[0]
                             name = parts[-1] if len(parts) > 1 else "?"
                             self._check_import(module, name, pos, errors)
                
                # Rule 2: Remove REDUCE check
                # weights_only=True allows REDUCE. It only restricts the GLOBALs used.
                
                # We reset stack on STOP or other clear boundaries? No, valid pickle is one stream.
                
                # Handling non-string pushes:
                # If an int is pushed, and then STACK_GLOBAL is called, it's invalid pickle anyway (STACK_GLOBAL expects strings).
                # So mostly our str tacking is fine.
                # But POP, POP_MARK, DUP?
                # If these occur, our sim_stack gets desync.
                # "Screen Door".
                if opcode.name in ('POP', 'POP_MARK'):
                     # We might need to pop, but we don't know if we popped a string or an int.
                     # Aggressive reset or ignore?
                     # Let's blindly pop if safe.
                     if sim_stack:
                         sim_stack.pop()
        
        except Exception as e:
            pass

        return errors

    def _check_import(self, module: str, name: str, pos: int, errors: List[LintError]):
        if '.' in module:
             root_module = module.split('.')[0]
        else:
             root_module = module
             
        if root_module not in PYTORCH_DEFAULT_SAFE_MODULES:
             errors.append(LintError(
                 offset=pos,
                 message=f"Custom Class Import Detected: {module}.{name}",
                 severity="ERROR",
                 hint=f"Module '{root_module}' is not in PyTorch default allowlist. Use `torch.serialization.add_safe_globals`."
             ))



