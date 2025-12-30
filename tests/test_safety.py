import pickle
import pytest
from pathlib import Path
import re
import operator
import collections
import operator
import collections
import _codecs
from aisbom.safety import scan_pickle_stream

# --- Safe Class Definitions ---
# We avoid custom classes to prevent "UNSAFE_IMPORT: test_safety..."
        
def test_complex_safe_payload_passes_strict_mode():
    """
    Verifies that a complex object using pathlib, re, operator, etc.
    scans as SAFE in strict mode.
    """
    # Use standard container with safe objects
    obj = {
        "path": Path("/tmp/model"),
        "pattern": re.compile(r"\d+"),
        "op": operator.add,
        "slice": slice(0, 10, 2),
        "set": frozenset([1, 2, 3]),
        "complex": 1 + 2j
    }
    # We use protocol=4 to ensure standard behavior
    payload = pickle.dumps(obj, protocol=4)
    
    threats = scan_pickle_stream(payload, strict_mode=True)
    assert len(threats) == 0, f"False positive threats detected: {threats}"

def test_strict_mode_blocks_unsafe():
    """Verify that strict mode still blocks dangerous modules."""
    class Malicious:
        def __reduce__(self):
            import os
            return (os.system, ("echo hacked",))

    payload = pickle.dumps(Malicious())
    threats = scan_pickle_stream(payload, strict_mode=True)
    
    # It should catch 'posix.system' or 'os.system'
    assert len(threats) > 0
    assert any("UNSAFE_IMPORT" in t for t in threats)
    assert any("system" in t for t in threats)

def test_torch_submodules_allowed():
    """
    Since we can't easily import random torch submodules in test environment if not installed or convoluted,
    we can craft a pickle stream manually or use a mock logic.
    Instead, we'll manually check the valid logic via pickletools logic if possible?
    Easier: Just pick a known safe Torch object if available.
    Or, rely on the fact that if we dump a simple torch tensor, it might use torch.storage.
    """
    # Create a minimalistic manual pickle stream that imports 'torch.nn.modules.linear'
    # GLOBAL 'torch.nn.modules.linear\nLinear'
    stream = b'\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00\x8c\x17torch.nn.modules.linear\x94\x8c\x06Linear\x94\x93\x94.'
    
    threats = scan_pickle_stream(stream, strict_mode=True)
    assert len(threats) == 0, f"Should allow torch submodule: {threats}"

def test_codecs_logic():
    # 1. _codecs.encode (Safe)
    stream_safe = b'\x80\x04\x95\x13\x00\x00\x00\x00\x00\x00\x00\x8c\x07_codecs\x94\x8c\x06encode\x94\x93\x94.'
    threats = scan_pickle_stream(stream_safe, strict_mode=True)
    assert len(threats) == 0
    
    # 2. _codecs.open (Unsafe/Not Allowed)
    stream_unsafe = b'\x80\x04\x95\x11\x00\x00\x00\x00\x00\x00\x00\x8c\x07_codecs\x94\x8c\x04open\x94\x93\x94.'
    threats = scan_pickle_stream(stream_unsafe, strict_mode=True)
    assert len(threats) == 1
    assert "UNSAFE_IMPORT: _codecs.open" in threats[0]
