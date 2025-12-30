import json
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
    Checksum,
    ChecksumAlgorithm
)
# from spdx_tools.spdx.writer.write_utils import convert_to_dict
from spdx_tools.spdx.writer.json import json_writer

class SPDXGenerator:
    def __init__(self, creation_time=None):
        self.creation_time = creation_time or datetime.now(timezone.utc)
        self.packages = []
        self.relationships = []
        
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
            creators=[Actor(ActorType.TOOL, "aisbom-cli-0.1.0")],
            created=self.creation_time,
            data_license="CC0-1.0"
        )
        
        document = Document(creation_info=creation_info)

        # 2. Process Artifacts (AI Models)
        artifacts = results.get("artifacts", [])
        for art in artifacts:
            self._process_artifact(art, doc_spdx_id)

        # 3. Process Dependencies (Libraries)
        dependencies = results.get("dependencies", [])
        for dep in dependencies:
            self._process_dependency(dep, doc_spdx_id)
            
        # 4. Assemble Document
        document.packages = self.packages
        document.relationships = self.relationships

        # 5. Serialize
        # spdx-tools allows converting the Document object to a dict, which we can then dump as JSON
        # Note: spdx-tools 0.8.x interface uses writer.write_utils
        # Or we can write to an in-memory stream using json_writer?
        # json_writer writes to a file object.
        
        # However, for simplicity and strict control, converting to dict matches standard flow.
        # But spdx-tools document structure is complex.
        # Let's try to use the provided helpers.
        
        # Since spdx_tools.spdx.writer.write_utils.convert_to_dict might not exist or work as expected depending on version.
        # Actually it's simpler: The spdx-tools library is primarily about PARSING. 
        # But for WRITING, passing to `spdx_tools.spdx.writer.json.json_writer.write_document_to_stream(doc, stream)` is best.
        
        from io import StringIO
        output = StringIO()
        json_writer.write_document_to_stream(document, output)
        return output.getvalue()

    def _process_artifact(self, artifact: Dict, doc_spdx_id: str):
        """Map AI model artifact to SPDX Package."""
        name = artifact.get("filename", "unknown-model")
        # Sanitize name for ID
        safe_name = "".join(c if c.isalnum() else "-" for c in name)
        spdx_id = f"SPDXRef-Artifact-{safe_name}-{id(artifact)}"
        
        # Risk / Format details
        comment = (
            f"Type: {artifact.get('format', 'unknown')}\n"
            f"Risk: {artifact.get('risk_level', 'UNKNOWN')}\n"
            f"Framework: {artifact.get('framework', 'unknown')}"
        )

        pkg = Package(
            name=name,
            spdx_id=spdx_id,
            download_location=SpdxNoAssertion(),
            files_analyzed=False,
            version="unknown", # Model version usually not in scan
            comment=comment,
            license_concluded=SpdxNoAssertion(),
             license_declared=SpdxNoAssertion(),
             copyright_text=SpdxNoAssertion()
        )
        
        # Hashes
        if "hashes" in artifact:
            # AISBOM uses dict or list for hashes?
            # From previous steps, it seemed to be list like [{'alg': 'SHA-256', 'content': '...'}]
            # Or dict? Looking at generator.py output or mock.
            # Usually aisbom/scanner.py output.
            pass # TODO: Add checksums if available in right format
            
        self.packages.append(pkg)
        
        # Relationship: DOCUMENT DESCRIBES Package
        self.relationships.append(Relationship(
            doc_spdx_id, RelationshipType.DESCRIBES, spdx_id
        ))

    def _process_dependency(self, dep: Dict, doc_spdx_id: str):
        """Map library dependency to SPDX Package."""
        name = dep.get("name", "unknown-lib")
        version = dep.get("version", "unknown")
        safe_name = "".join(c if c.isalnum() else "-" for c in name)
        spdx_id = f"SPDXRef-Lib-{safe_name}-{version}"
        
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
    generator = SPDXGenerator()
    return generator.generate(results)
