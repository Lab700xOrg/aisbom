import pickle
import datetime
import os
import pytest
from logging import getLogger
from aisbom.linter import MigrationLinter

# Define a custom class for testing "Custom Class Import"
class UnsafeClass:
    def __init__(self):
        self.data = 1

class RCE:
    def __reduce__(self):
        return (os.system, ('ls',))

def test_safe_pickle():
    """Test that a safe object (datetime) passes linting."""
    data = pickle.dumps(datetime.datetime.now())
    linter = MigrationLinter()
    errors = linter.lint_pickle(data)
    assert len(errors) == 0, f"Expected 0 errors for datetime, got: {errors}"

def test_custom_class_import():
    """Test that a custom class triggers a GLOBAL error."""
    data = pickle.dumps(UnsafeClass())
    linter = MigrationLinter()
    errors = linter.lint_pickle(data)
    
    # We expect 'tests.test_linter' or 'test_linter' (depending on runner) not in allowlist
    assert len(errors) > 0
    # Check message
    assert "Custom Class Import Detected" in errors[0].message
    assert "UnsafeClass" in errors[0].message
    assert errors[0].severity == "ERROR"

def test_reduce_rce():
    """Test that __reduce__ triggers a Custom Class Import error for unsafe globals."""
    data = pickle.dumps(RCE())
    linter = MigrationLinter()
    errors = linter.lint_pickle(data)
    
    # RCE usage of __reduce__ usually emits the REDUCE opcode
    # But now we only flag the unsafe GLOBAL (posix.system)
    found = any("Custom Class Import Detected" in e.message and "posix" in e.message for e in errors)
    assert found, f"Expected unsafe global error for RCE, got: {errors}"


def test_linter_global_opcode():
    # Protocol 0 uses GLOBAL opcode explicitly
    data = pickle.dumps(UnsafeClass(), protocol=0)
    linter = MigrationLinter()
    errors = linter.lint_pickle(data)
    # Expect error because UnsafeClass is not in allowlist
    assert any("Custom Class Import Detected" in e.message for e in errors)

def test_linter_stack_underflow():
    # STACK_GLOBAL (b'\x93') with empty stack
    data = b'\x93.' 
    linter = MigrationLinter()
    # Should handle gracefully without raising
    errors = linter.lint_pickle(data)
    assert isinstance(errors, list)

def test_linter_pop_stack():
    # Push string then POP (b'0')
    # Protocol 0 STRING is S '...' \n
    data = b'S"test"\n0.' 
    linter = MigrationLinter()
    # Should run without error
    linter.lint_pickle(data)


