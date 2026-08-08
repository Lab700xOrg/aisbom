import importlib.metadata
import json
import re
from datetime import datetime, timezone
import hashlib
from typing import Dict, List, Any

# SPDX Tools Imports
from spdx_tools.spdx.model import (
    Document,
    Package,
    File,
    CreationInfo,
    Actor,
    ActorType,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
    SpdxNone,
    Checksum,
    ChecksumAlgorithm
)
from spdx_tools.spdx.writer.json import json_writer

from .properties import _format_for

# A SHA256 hexdigest, as produced by ``DeepScanner._calculate_hash``. The
# scanner also stores the sentinels ``remote_unhashed`` (range-request scans,
# where the bytes are never fully read) and ``hash_error`` (unreadable file) in
# the same field, so every consumer here has to distinguish a real digest from
# a placeholder rather than trusting the field to hold one.
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")

# SPDXID payloads are restricted to ``[a-zA-Z0-9.-]`` by the 2.3 spec.
_SPDX_ID_SAFE_RE = re.compile(r"[^a-zA-Z0-9.\-]")


def _tool_version() -> str:
    """Version of the running CLI, for the document's ``creators`` field.

    Mirrors ``cli.py``'s ``--version`` lookup. The PyInstaller binary ships
    without distribution metadata, so the lookup must not be load-bearing.
    """
    try:
        return importlib.metadata.version("aisbom-cli")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _sanitize(value: str) -> str:
    """Reduce arbitrary text to characters an SPDXID may carry."""
    return _SPDX_ID_SAFE_RE.sub("-", str(value))


def _sha256_or_none(value: Any) -> str | None:
    """Return ``value`` as a lowercase SHA256 hexdigest, or None if it isn't one."""
    if isinstance(value, str) and _SHA256_RE.fullmatch(value):
        return value.lower()
    return None


class SPDX2Generator:
    def __init__(self, creation_time=None):
        self.creation_time = creation_time or datetime.now(timezone.utc)
        self.packages = []
        self.relationships = []
        # SPDXIDs must be unique within a document. IDs are derived from
        # content so they stay stable across runs, but content alone cannot
        # guarantee uniqueness (the same file under the same basename in two
        # directories; every artifact of a remote scan sharing one sentinel
        # hash), so collisions are resolved by suffix in emission order.
        self._used_ids = set()

    def generate(self, results: Dict[str, Any]) -> str:
        """
        Converts AISBOM scan results to SPDX 2.3 JSON string.
        """
        doc_namespace = f"http://spdx.org/spdxdocs/aisbom-scan-{self.creation_time.timestamp()}"
        doc_spdx_id = "SPDXRef-DOCUMENT"

        # 1. Creation Info
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id=doc_spdx_id,
            name="AIsbom-Scan",
            document_namespace=doc_namespace,
            creators=[Actor(ActorType.TOOL, f"aisbom-cli-{_tool_version()}")],
            created=self.creation_time,
            data_license="CC0-1.0"
        )

        document = Document(creation_info=creation_info)

        # 2. Process Artifacts (AI Models)
        artifacts = results.get("artifacts", [])
        for index, art in enumerate(artifacts):
            self._process_artifact(art, doc_spdx_id, index)

        # 3. Process Dependencies (Libraries)
        dependencies = results.get("dependencies", [])
        for dep in dependencies:
            self._process_dependency(dep, doc_spdx_id)

        # 4. Assemble Document
        # SPDX requires an explicit DESCRIBES relationship unless the document
        # holds exactly one package, so a scan that turned up neither models
        # nor requirements has to say it describes NONE. Without this the
        # writer's validator rejects the document and the CLI dies on what is
        # a perfectly ordinary result.
        if not self.relationships:
            self.relationships.append(Relationship(
                doc_spdx_id, RelationshipType.DESCRIBES, SpdxNone()
            ))

        document.packages = self.packages
        document.relationships = self.relationships

        # 5. Serialize
        from io import StringIO
        output = StringIO()
        json_writer.write_document_to_stream(document, output)
        return output.getvalue()

    def _claim_id(self, base: str) -> str:
        """Return ``base``, or the first free ``base-N`` if it's already taken."""
        candidate = base
        suffix = 2
        while candidate in self._used_ids:
            candidate = f"{base}-{suffix}"
            suffix += 1
        self._used_ids.add(candidate)
        return candidate

    def _process_artifact(self, artifact: Dict, doc_spdx_id: str, index: int = 0):
        """Map AI model artifact to SPDX Package."""
        # The scanner emits ``name``; ``filename`` is accepted as a fallback
        # for callers still building artifacts the old way.
        name = artifact.get("name") or artifact.get("filename") or "unknown-model"
        safe_name = _sanitize(name)

        # Prefer a content-derived discriminator so unchanged inputs yield
        # byte-identical documents. Artifacts without a real digest (remote
        # scans, read failures) fall back to position, which is stable for a
        # given scan but carries no content meaning.
        digest = _sha256_or_none(artifact.get("hash"))
        discriminator = digest[:12] if digest else str(index)
        spdx_id = self._claim_id(f"SPDXRef-Artifact-{safe_name}-{discriminator}")

        # Risk / Format details. The format token comes from the same helper
        # the CycloneDX path uses, so the two exports cannot drift apart.
        comment = (
            f"Type: {_format_for(artifact) or 'unknown'}\n"
            f"Risk: {artifact.get('risk_level', 'UNKNOWN')}\n"
            f"Framework: {artifact.get('framework', 'unknown')}"
        )

        # Emit a checksum only when there is a genuine digest to report —
        # asserting nothing is correct for a remote artifact, whereas writing
        # the sentinel into the field would be a falsehood in a security SBOM.
        checksums = [Checksum(ChecksumAlgorithm.SHA256, digest)] if digest else []

        pkg = Package(
            name=name,
            spdx_id=spdx_id,
            download_location=SpdxNoAssertion(),
            files_analyzed=False,
            version="unknown", # Model version usually not in scan
            checksums=checksums,
            comment=comment,
            license_concluded=SpdxNoAssertion(),
             license_declared=SpdxNoAssertion(),
             copyright_text=SpdxNoAssertion()
        )

        self.packages.append(pkg)

        # Relationship: DOCUMENT DESCRIBES Package
        self.relationships.append(Relationship(
            doc_spdx_id, RelationshipType.DESCRIBES, spdx_id
        ))

    def _process_dependency(self, dep: Dict, doc_spdx_id: str):
        """Map library dependency to SPDX Package."""
        name = dep.get("name", "unknown-lib")
        version = dep.get("version", "unknown")
        # Versions reach here straight off a requirements specifier, so they
        # can carry characters an SPDXID may not (``2.0.*``); and the same pin
        # listed in two requirements files would otherwise claim one ID twice.
        spdx_id = self._claim_id(
            f"SPDXRef-Lib-{_sanitize(name)}-{_sanitize(version)}"
        )

        pkg = Package(
            name=name,
            spdx_id=spdx_id,
            version=version,
            download_location=SpdxNoAssertion(),
            files_analyzed=False,
            license_concluded=SpdxNoAssertion(),
            license_declared=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion()
        )

        self.packages.append(pkg)
        self.relationships.append(Relationship(
            doc_spdx_id, RelationshipType.DESCRIBES, spdx_id
        ))

def generate_spdx_sbom(results: Dict[str, Any]) -> str:
    generator = SPDX2Generator()
    return generator.generate(results)
