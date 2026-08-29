"""SPDX 3.0 (AI Profile) JSON-LD export.

Why this is hand-built rather than delegated to ``spdx-tools``
--------------------------------------------------------------

``spdx-tools`` 0.8.5 — already a dependency for the 2.3 path — ships an
``spdx3`` subpackage with an ``AIPackage`` class and a JSON-LD writer, so
reaching for it is the obvious move. It does not work here: that subpackage
implements a *pre-release draft* of the specification, and the library's own
metadata describes the support as "neither complete nor stable". Concretely,
its writer emits

* ``"@context"`` as an object mapping prefixes, where released 3.0.1 requires
  the single context IRI;
* ``"@type"``/``"@id"``, where 3.0.1 uses ``"type"``/``"spdxId"``;
* unprefixed class names (``AIPackage``) and properties
  (``energyConsumption``), where 3.0.1 namespaces them (``ai_AIPackage``,
  ``ai_energyConsumption``) — and models energy consumption as a structured
  object rather than a string.

Output in that shape does not validate against the released SPDX 3.0.1 schema,
so consumers asking for "SPDX 3.0" would reject it. This module therefore
targets the released serialization directly, and ``tests/test_spdx3.py``
validates every generated document against the official bundled schema (which
sets ``unevaluatedProperties: false``, so a mis-namespaced key fails the suite).

This mirrors the decision already taken for CycloneDX 1.7 ``modelCard`` blocks
in ``aisbom.modelcard`` — build the payload here, prove it with schema
validation in the suite.

Honesty over completeness
-------------------------

The AI Profile has rich fields — ``ai_energyConsumption``, ``ai_metric``,
``ai_safetyRiskAssessment``, ``ai_hyperparameter``. AIsbom has no source of
truth for any of them: it reads model *files*, not training runs. They are
therefore omitted rather than filled with ``unknown`` placeholders. In a
security/compliance artifact an absent field is a smaller lie than a fabricated
one, and a downstream consumer can tell "not asserted" from "asserted as
unknown".
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .spdx_gen import _sanitize, _sha256_or_none, _tool_version

# The released 3.0.1 context. The schema pins this as a `const`, so it is not
# a formatting preference — a different value fails validation outright.
SPDX3_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SPDX3_SPEC_VERSION = "3.0.1"

# Every element points at one shared CreationInfo via this blank node, rather
# than inlining a copy per element. Both are schema-valid; this keeps the
# document readable and its size linear in the number of real elements.
_CREATION_INFO_REF = "_:creationInfo"


def _utc_stamp(moment: datetime) -> str:
    """Format as the schema's `created` pattern demands.

    The pattern rejects sub-second precision, so a naive ``isoformat()`` on a
    ``datetime.now()`` carrying microseconds produces an invalid document.
    """
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_str(value: Any) -> Optional[str]:
    """Return a non-empty stripped string, or None for anything else."""
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _card_datasets(hf_meta: Optional[Dict[str, Any]]) -> List[str]:
    """Training-dataset names declared in Hugging Face card metadata.

    Mirrors ``aisbom.modelcard._datasets`` — the same source feeds the
    CycloneDX ``modelCard``, and the two exports must not disagree about what
    a model was trained on.
    """
    card = (hf_meta or {}).get("cardData")
    raw = card.get("datasets") if isinstance(card, dict) else None
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    names: List[str] = []
    for entry in raw:
        name = _clean_str(entry)
        if name and name not in names:
            names.append(name)
    return names


class SPDX3Generator:
    """Build an SPDX 3.0.1 JSON-LD document from AIsbom scan results."""

    def __init__(self, creation_time: Optional[datetime] = None,
                 namespace: Optional[str] = None):
        self.creation_time = creation_time or datetime.now(timezone.utc)
        # Element IRIs must be absolute and must not be blank nodes (the
        # schema's `IRI` pattern rejects a leading `_:`), so every id is
        # rooted in a document namespace. When not supplied it is derived
        # from the scan's content in `generate()` — see `_content_namespace`.
        self.namespace = namespace
        self._used_ids: set[str] = set()

    def _content_namespace(self, results: Dict[str, Any]) -> str:
        """Derive the document namespace from what was scanned, not from the clock.

        A timestamp is the obvious choice and the wrong one in both directions:

        * Truncated to whole seconds it *collides* — two unrelated scans
          starting in the same second (parallel CI jobs are the normal case)
          produce documents whose `SpdxDocument`, agent, package and
          relationship IRIs are identical while describing different data, so
          a store importing both can merge or overwrite unrelated results.
        * Given sub-second precision instead, it never collides but is never
          stable either: re-scanning unchanged inputs yields all-new IRIs,
          which reads downstream as churn. `aisbom.modelcard` avoids emitting
          hourly-changing HF fields for exactly this reason — an SBOM that
          differs between two scans of an unchanged model produces phantom
          drift on the platform's diff.

        Deriving it from content satisfies both: identical inputs yield
        identical IRIs (they genuinely describe the same artifacts), and
        different inputs yield different ones no matter how close together the
        scans ran.
        """
        fingerprint = {
            "artifacts": [
                [
                    art.get("name") or art.get("filename") or "unknown-model",
                    art.get("hash"),
                ]
                for art in results.get("artifacts", [])
            ],
            "dependencies": [
                [dep.get("name"), dep.get("version")]
                for dep in results.get("dependencies", [])
            ],
            "datasets": _card_datasets(results.get("hf_model_card")),
        }
        digest = hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return f"https://aisbom.io/spdxdocs/aisbom-scan-{digest[:32]}"

    # -- identifiers ------------------------------------------------------

    def _claim_id(self, base: str) -> str:
        """Return ``base``, or the first free ``base-N`` if it's already taken.

        Same contract as the 2.3 generator: ids are content-derived so an
        unchanged scan yields an unchanged document, but content alone cannot
        guarantee uniqueness (two identical files in different directories;
        every artifact of a remote scan sharing one sentinel hash), so
        collisions resolve by suffix in emission order.
        """
        candidate = base
        suffix = 2
        while candidate in self._used_ids:
            candidate = f"{base}-{suffix}"
            suffix += 1
        self._used_ids.add(candidate)
        return candidate

    def _iri(self, fragment: str) -> str:
        return f"{self.namespace}#{fragment}"

    # -- elements ---------------------------------------------------------

    def _creation_info(self, tool_id: str) -> Dict[str, Any]:
        return {
            "type": "CreationInfo",
            "@id": _CREATION_INFO_REF,
            "specVersion": SPDX3_SPEC_VERSION,
            "created": _utc_stamp(self.creation_time),
            "createdBy": [tool_id],
        }

    def _tool_agent(self, tool_id: str) -> Dict[str, Any]:
        return {
            "type": "SoftwareAgent",
            "spdxId": tool_id,
            "creationInfo": _CREATION_INFO_REF,
            "name": f"aisbom-cli-{_tool_version()}",
        }

    def _ai_package(self, artifact: Dict[str, Any], index: int,
                    hf_meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        # The scanner emits `name`; `filename` is accepted as a fallback for
        # callers still building artifacts the old way.
        name = (
            artifact.get("name")
            or artifact.get("filename")
            or "unknown-model"
        )

        # Prefer a content-derived discriminator so unchanged inputs yield
        # byte-identical documents. Artifacts without a real digest (remote
        # range-request scans, read failures) fall back to position, which is
        # stable for a given scan but carries no content meaning.
        digest = _sha256_or_none(artifact.get("hash"))
        discriminator = digest[:12] if digest else str(index)
        spdx_id = self._claim_id(
            self._iri(f"Artifact-{_sanitize(name)}-{discriminator}")
        )

        pkg: Dict[str, Any] = {
            "type": "ai_AIPackage",
            "spdxId": spdx_id,
            "creationInfo": _CREATION_INFO_REF,
            "name": name,
            "software_primaryPurpose": "model",
        }

        # Only assert a checksum when there is a genuine digest. The scanner
        # stores `remote_unhashed` / `hash_error` sentinels in the same field,
        # and writing one into `hashValue` would be a falsehood in a security
        # SBOM rather than merely unhelpful.
        if digest:
            pkg["verifiedUsing"] = [{
                "type": "Hash",
                "algorithm": "sha256",
                "hashValue": digest,
            }]

        framework = _clean_str(artifact.get("framework"))
        if framework and framework.lower() != "unknown":
            pkg["ai_typeOfModel"] = [framework]

        # Risk and legal findings have no typed home in the AI Profile, so
        # they ride in `comment` — the same information the 2.3 export puts
        # in the package comment, kept consistent between the two.
        pkg["comment"] = (
            f"Risk: {artifact.get('risk_level', 'UNKNOWN')}\n"
            f"Framework: {artifact.get('framework', 'unknown')}\n"
            f"Legal: {artifact.get('legal_status', 'UNKNOWN')}"
        )

        datasets = _card_datasets(hf_meta)
        if datasets:
            pkg["ai_informationAboutTraining"] = (
                "Declared training datasets: " + ", ".join(datasets)
            )

        return pkg

    def _dataset_package(self, name: str) -> Dict[str, Any]:
        return {
            "type": "dataset_DatasetPackage",
            "spdxId": self._claim_id(self._iri(f"Dataset-{_sanitize(name)}")),
            "creationInfo": _CREATION_INFO_REF,
            "name": name,
            # Required by the schema. A card listing gives the dataset's name
            # and nothing about its modality, so anything other than an
            # explicit noAssertion would be invented.
            "dataset_datasetType": ["noAssertion"],
        }

    def _software_package(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        name = dep.get("name", "unknown-lib")
        version = dep.get("version", "unknown")
        return {
            "type": "software_Package",
            "spdxId": self._claim_id(
                self._iri(f"Lib-{_sanitize(name)}-{_sanitize(version)}")
            ),
            "creationInfo": _CREATION_INFO_REF,
            "name": name,
            "software_packageVersion": version,
            "software_primaryPurpose": "library",
        }

    def _relationship(self, fragment: str, source: str, rel_type: str,
                      targets: List[str]) -> Dict[str, Any]:
        return {
            "type": "Relationship",
            "spdxId": self._claim_id(self._iri(fragment)),
            "creationInfo": _CREATION_INFO_REF,
            "from": source,
            "relationshipType": rel_type,
            "to": targets,
        }

    # -- assembly ---------------------------------------------------------

    def generate(self, results: Dict[str, Any]) -> str:
        hf_meta = results.get("hf_model_card")
        if self.namespace is None:
            self.namespace = self._content_namespace(results)
        tool_id = self._iri("Agent-aisbom-cli")

        graph: List[Dict[str, Any]] = [
            self._creation_info(tool_id),
            self._tool_agent(tool_id),
        ]

        ai_packages = [
            self._ai_package(art, index, hf_meta)
            for index, art in enumerate(results.get("artifacts", []))
        ]
        graph.extend(ai_packages)

        # Dataset elements are shared across models: the card metadata is
        # per-scan, not per-file, so emitting one element per model would
        # duplicate the same dataset under distinct ids.
        dataset_packages = [
            self._dataset_package(name) for name in _card_datasets(hf_meta)
        ]
        graph.extend(dataset_packages)

        software_packages = [
            self._software_package(dep)
            for dep in results.get("dependencies", [])
        ]
        graph.extend(software_packages)

        relationships: List[Dict[str, Any]] = []
        if dataset_packages:
            dataset_ids = [d["spdxId"] for d in dataset_packages]
            for pkg in ai_packages:
                relationships.append(self._relationship(
                    f"Relationship-trainedOn-{len(relationships)}",
                    pkg["spdxId"], "trainedOn", dataset_ids,
                ))
        graph.extend(relationships)

        doc_id = self._claim_id(self._iri("SPDXRef-DOCUMENT"))
        contained = (
            [p["spdxId"] for p in ai_packages]
            + [d["spdxId"] for d in dataset_packages]
            + [s["spdxId"] for s in software_packages]
        )
        if contained:
            graph.append(self._relationship(
                "Relationship-describes", doc_id, "describes", contained,
            ))

        # `dataset` is claimed only when dataset elements are actually
        # present: profileConformance is a statement about what the document
        # contains, so claiming a profile it never exercises misleads
        # consumers filtering documents by profile.
        profiles = ["core", "software", "ai"]
        if dataset_packages:
            profiles.append("dataset")

        graph.append({
            "type": "SpdxDocument",
            "spdxId": doc_id,
            "creationInfo": _CREATION_INFO_REF,
            "name": "AIsbom-Scan",
            "profileConformance": profiles,
            # An empty scan still has to name a root. The document describing
            # itself is the honest answer to "a scan that found nothing",
            # and keeps the element valid without inventing content.
            "rootElement": contained or [doc_id],
        })

        return json.dumps(
            {"@context": SPDX3_CONTEXT, "@graph": graph}, indent=2
        )


def generate_spdx3_sbom(results: Dict[str, Any]) -> str:
    return SPDX3Generator().generate(results)
