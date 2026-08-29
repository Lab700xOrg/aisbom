"""Discovery by content, for files no extension claims.

The scanner used to decide what to open purely from a file's suffix. That is
the whole of CVE-2025-1889: name the payload `config.p` and nothing ever opens
it, so the scan reports "No AI models found" and exits 0 — a clean bill of
health on a directory carrying a reverse shell.

Adding `.p` to the extension list would flip the published corpus case and fix
nothing, because the technique is *any* unexpected suffix, not that one. The
attacker picks the name; we do not get to enumerate their choices. So an
unclaimed file is now sniffed by its bytes.

Two directions are tested here and both matter equally. Missing a payload is
the bug we are closing; claiming ordinary repository files as models would be
a worse one, because it would put noise in every SBOM and train users to
ignore findings. The false-positive half of this file is not padding.

Nothing is ever unpickled. Sniffing is `pickletools` disassembly plus the
stack validation `pickletools.dis` performs — the same read-only path the rest
of the scanner uses. Parsing as opcodes alone proved far too weak a test; see
the real-world false positives at the bottom of this file.
"""

import pytest

from aisbom.mock_generator import (
    harmless_reduce_pickle,
    harmless_stack_global_pickle,
)
from aisbom.scanner import DeepScanner


def scan_dir(tmp_path, name, blob, strict=False):
    """Write one file into its own directory and scan the directory."""
    holder = tmp_path / f"holder_{name.replace('/', '_')}"
    holder.mkdir(exist_ok=True)
    (holder / name).write_bytes(blob)
    return DeepScanner(str(holder), strict_mode=strict).scan()


def artifacts_of(results):
    return results["artifacts"]


# --- the evasion class: any suffix at all ---------------------------------

@pytest.mark.parametrize(
    "filename",
    [
        "config.p",          # the CVE-2025-1889 proof of concept verbatim
        "payload.dat",       # the same trick with a different suffix
        "weights.model",     # plausible-looking, still unlisted
        "checkpoint.bin.1",  # a rotated/suffixed name
        "state.cfg",         # wearing a config file's clothes
        "blob",              # no extension at all
        ".hidden",           # dotfile: suffix parsing must not swallow it
    ],
)
def test_a_payload_is_found_whatever_the_file_is_called(tmp_path, filename):
    """The fix has to close the class, not the one filename in the CVE."""
    results = scan_dir(tmp_path, filename, harmless_reduce_pickle("os", "system"))
    found = artifacts_of(results)
    assert len(found) == 1, found
    assert "CRITICAL" in found[0]["risk_level"]
    assert "os.system" in found[0]["risk_level"]


def test_a_protocol_4_payload_is_found_under_an_odd_name(tmp_path):
    """Protocol 0 is printable ASCII; protocol 4 is binary. Both must sniff."""
    results = scan_dir(tmp_path, "payload.dat", harmless_stack_global_pickle("os", "system"))
    found = artifacts_of(results)
    assert len(found) == 1, found
    assert "CRITICAL" in found[0]["risk_level"]


def test_a_sniffed_file_is_claimed_as_a_single_file_target(tmp_path):
    """`aisbom scan payload.dat` — named directly, not found by a walk."""
    target = tmp_path / "payload.dat"
    target.write_bytes(harmless_reduce_pickle("os", "system"))
    results = DeepScanner(str(target)).scan()
    assert results["errors"] == []
    assert len(results["artifacts"]) == 1
    assert "CRITICAL" in results["artifacts"][0]["risk_level"]


def test_a_sniffed_payload_is_flagged_in_strict_mode_too(tmp_path):
    results = scan_dir(tmp_path, "payload.dat", harmless_reduce_pickle("os", "system"), strict=True)
    found = artifacts_of(results)
    assert len(found) == 1, found
    assert "CRITICAL" in found[0]["risk_level"]


# --- the other direction: ordinary files stay unclaimed -------------------

ORDINARY_FILES = [
    ("README.md", b"# A project\n\nSome prose about the project.\n"),
    ("config.json", b'{\n  "name": "demo",\n  "version": 2\n}\n'),
    ("notes.txt", b"Nothing here. Consider the following list:\n- one\n- two\n"),
    ("train.py", b"import torch\n\n\ndef main():\n    print('hi')\n"),
    ("data.csv", b"col_a,col_b\n1,2\n3,4\n"),
    ("logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 512),
    ("archive.tar", b"\x00" * 1024),
    ("empty", b""),
    ("LICENSE", b"MIT License\n\nCopyright (c) 2026\n"),
    ("Makefile", b"all:\n\tcargo build\n"),
    ("index.html", b"<!doctype html>\n<html><body>hi</body></html>\n"),
    ("script.sh", b"#!/bin/sh\nset -eu\necho hello\n"),
]


@pytest.mark.parametrize("filename,blob", ORDINARY_FILES, ids=[f[0] for f in ORDINARY_FILES])
def test_ordinary_repository_files_are_not_claimed_as_models(tmp_path, filename, blob):
    """A scanner that flags everything is as useless as one that flags nothing.

    These are the files that sit beside a model in every real repository. If
    sniffing claims them, every SBOM gains phantom components and the finding
    list stops meaning anything.
    """
    results = scan_dir(tmp_path, filename, blob)
    assert artifacts_of(results) == []


def test_a_text_file_beginning_with_a_valid_opcode_byte_is_not_claimed(tmp_path):
    """`c` is the GLOBAL opcode and also how a great many words start.

    The sniff must be a real disassembly, not a first-byte guess, or every
    `config.yaml` and `changelog.md` in the tree becomes a model.
    """
    for text in (b"changelog for the project\n", b"config values follow\n",
                 b"Nothing to see\n", b"Some notes\n", b"Installation guide\n"):
        results = scan_dir(tmp_path, "doc_%d.txt" % len(text), text)
        assert artifacts_of(results) == [], text


def test_requirements_are_still_parsed_as_dependencies(tmp_path):
    """The named-file branch must keep winning over the sniff."""
    results = scan_dir(tmp_path, "requirements.txt", b"torch==2.4.0\nnumpy==1.26.4\n")
    assert artifacts_of(results) == []
    assert len(results["dependencies"]) == 2


def test_an_unusable_named_target_is_still_an_error(tmp_path):
    """`aisbom scan notes.txt` must still fail loudly rather than sniff-and-shrug."""
    target = tmp_path / "notes.txt"
    target.write_bytes(b"just some prose\n")
    results = DeepScanner(str(target)).scan()
    assert results["artifacts"] == []
    assert len(results["errors"]) == 1


# --- cost: the walk must not read whole files to decide -------------------

def test_a_large_unclaimed_file_is_not_read_in_full(tmp_path):
    """Sniffing happens on a bounded head read.

    A repository can hold gigabytes of parquet, checkpoints and archives that
    no inspector wants. Deciding "not a pickle" must cost a few kilobytes per
    file, not the whole file, or the walk becomes unusable on real trees.
    """
    from aisbom import scanner as scanner_mod

    holder = tmp_path / "big"
    holder.mkdir()
    big = holder / "dataset.parquet"
    big.write_bytes(b"PAR1" + b"\x00" * (4 * 1024 * 1024))

    reads = []
    real_open = open

    def counting_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        if str(path) == str(big):
            real_read = handle.read

            def tracked(size=-1):
                data = real_read(size)
                reads.append(len(data))
                return data

            handle.read = tracked
        return handle

    scanner_mod.open = counting_open
    try:
        results = DeepScanner(str(holder)).scan()
    finally:
        del scanner_mod.open

    assert artifacts_of(results) == []
    assert reads, "the file was never opened, so the sniff did not run"
    assert max(reads) <= scanner_mod.PICKLE_SNIFF_BYTES


# --- the trap that a real tree caught ------------------------------------

# Found by scanning an actual `node_modules` (5,101 files) rather than by
# imagination: an earlier version of this sniff accepted anything that parsed
# as opcodes and reached STOP, and claimed eleven files. `.` *is* the STOP
# opcode, so a stylesheet opening with a class selector was a one-opcode
# "pickle". These are the real filenames and shapes that were wrongly claimed.
REAL_WORLD_FALSE_POSITIVES = [
    ("prettify.css", b".com{color:#93a1a1}.str{color:#2aa198}\n"),
    ("marked.1", b".TH marked 1 \"2026\"\n.SH NAME\nmarked \\- a markdown parser\n"),
    ("index.d.ts", b"export declare function parse(s: string): string;\n"),
    ("threads.js", b"'use strict';\nmodule.exports = { run() { return 1; } };\n"),
    ("cli-api.js", b"export { createCli } from './cli.js';\n"),
    ("node.js", b"process.exit(0);\n"),
]


@pytest.mark.parametrize(
    "filename,blob", REAL_WORLD_FALSE_POSITIVES, ids=[f[0] for f in REAL_WORLD_FALSE_POSITIVES]
)
def test_files_that_a_weaker_sniff_wrongly_claimed(tmp_path, filename, blob):
    results = scan_dir(tmp_path, filename, blob)
    assert artifacts_of(results) == []


def test_a_lone_stop_opcode_is_not_a_pickle(tmp_path):
    """`.` parses and reaches STOP, but pops from an empty stack.

    This single byte is the whole reason the sniff validates the stack instead
    of trusting the disassembler's syntax walk.
    """
    results = scan_dir(tmp_path, "styles.css", b".")
    assert artifacts_of(results) == []


def test_a_valid_payload_followed_by_a_corrupt_tail_is_still_found(tmp_path):
    """The nullifAI shape, wearing an unlisted extension.

    Validation runs on the prefix ending at the first STOP, so garbage after a
    complete pickle does not get the file thrown out along with it. Truncating
    the stream is otherwise a way to opt out of being scanned.
    """
    blob = harmless_reduce_pickle("os", "system") + b"\x00\xff\xfe garbage tail \x01"
    results = scan_dir(tmp_path, "payload.dat", blob)
    found = artifacts_of(results)
    assert len(found) == 1, found
    assert "CRITICAL" in found[0]["risk_level"]


# --- large first argument: the escalation gap ----------------------------

# Discovery reads a small head, then re-reads with a larger budget only when
# the head looked like an unfinished pickle. The first version of that rule
# used "at least one opcode parsed" as the signal, which a pickle can defeat
# by opening with a single literal bigger than the first read: zero opcodes
# complete, so no re-read ever happens.
#
# Measured, not assumed -- a 65,000-byte pad was found and a 70,000-byte pad
# was not, so the real bound was the 64KB first read rather than the documented
# 16MB ceiling. These tests pin the ceiling to what we actually claim.

def padded_first_literal(pad_bytes, proto0=True):
    """A valid pickle whose FIRST opcode is one huge literal, then the payload.

    Protocol 0 uses a quoted STRING; the binary form uses a length-prefixed
    BINBYTES. Both are popped, so the stream ends holding exactly one object
    and is a structurally valid pickle either way.
    """
    payload = harmless_reduce_pickle("os", "system")
    if proto0:
        return b"S'" + (b"x" * pad_bytes) + b"'\n0" + payload
    import struct

    return b"B" + struct.pack("<I", pad_bytes) + (b"\x00" * pad_bytes) + b"0" + payload


@pytest.mark.parametrize("pad", [70_000, 250_000, 2_000_000])
def test_a_payload_behind_a_large_protocol0_literal_is_found(tmp_path, pad):
    """`S'<70KB>'` ahead of the payload must not buy silence."""
    results = scan_dir(tmp_path, "payload.dat", padded_first_literal(pad))
    found = artifacts_of(results)
    assert len(found) == 1, f"pad={pad} evaded discovery"
    assert "CRITICAL" in found[0]["risk_level"]


@pytest.mark.parametrize("pad", [70_000, 2_000_000])
def test_a_payload_behind_a_large_binary_literal_is_found(tmp_path, pad):
    """The same trick in a binary protocol, where the length is declared."""
    results = scan_dir(tmp_path, "payload.dat", padded_first_literal(pad, proto0=False))
    found = artifacts_of(results)
    assert len(found) == 1, f"pad={pad} evaded discovery"
    assert "CRITICAL" in found[0]["risk_level"]


def test_the_documented_ceiling_is_the_real_ceiling(tmp_path):
    """Past the cap we stop looking -- that is the limit we publish."""
    from aisbom import scanner as scanner_mod

    over = scanner_mod.PICKLE_SNIFF_MAX_BYTES + 1024
    results = scan_dir(tmp_path, "payload.dat", padded_first_literal(over))
    assert artifacts_of(results) == []


def test_binary_junk_with_no_newline_is_not_re_read(tmp_path):
    """The cost guard the escalation rule must not break.

    A parquet file opens with `PAR1` -- `P` happens to be a valid opcode byte
    -- and carries no newline for megabytes. If escalation fires on "first byte
    could be an opcode", every such file in a tree gets read to the cap.
    """
    from aisbom import scanner as scanner_mod

    holder = tmp_path / "cost"
    holder.mkdir()
    big = holder / "dataset.parquet"
    big.write_bytes(b"PAR1" + b"\x00" * (3 * 1024 * 1024))

    reads = []
    real_open = open

    def counting_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        if str(path) == str(big):
            real_read = handle.read

            def tracked(size=-1):
                data = real_read(size)
                reads.append(len(data))
                return data

            handle.read = tracked
        return handle

    scanner_mod.open = counting_open
    try:
        results = DeepScanner(str(holder)).scan()
    finally:
        del scanner_mod.open

    assert artifacts_of(results) == []
    assert sum(reads) <= scanner_mod.PICKLE_SNIFF_BYTES, (
        f"parquet was re-read: {reads}"
    )
