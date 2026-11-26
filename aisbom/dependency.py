"""Identity of a requirements.txt dependency component, shared by every format.

The scanner records a version only for an exact pin (a single ``==``/``===``
without a wildcard) and keeps any other specifier as ``specifier``. A range such
as ``torch>=2.0`` names no installed version, so writing its lower bound into
the version field would claim something the requirements file does not say.

An exact pin also gets a purl, so third-party VEX tooling can join AIsbom's
CVE statements to the component by the package identity everyone uses rather
than by the ``dependency-<n>-<name>`` bom-ref convention.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from packageurl import PackageURL
from packaging.utils import canonicalize_name

# Where a non-exact specifier goes instead of the version field.
SPECIFIER_PROPERTY = "aisbom:requirement:specifier"


def dependency_purl(dep: Dict[str, Any]) -> Optional[str]:
    """``pkg:pypi/<name>@<version>`` for an exact pin, else ``None``."""
    purl = dependency_package_url(dep)
    return purl.to_string() if purl else None


def dependency_package_url(dep: Dict[str, Any]) -> Optional[PackageURL]:
    """The ``PackageURL`` for an exact pin, else ``None``.

    Keys on the scanner's ``pinned`` flag, not on whether a version string is
    present: a dependency dict without that flag has not been shown to be an
    exact pin. The name is normalised as PEP 503 does (lowercase, runs of
    ``-_.`` to ``-``), which is the form ``eol.py`` already matches against
    endoflife.date's ``pkg:pypi`` identifiers. ``PackageURL`` percent-encodes
    the version, so a local version label's ``+`` becomes ``%2B``.
    """
    name = dep.get("name")
    version = dep.get("version")
    if not dep.get("pinned") or not name or not version or version == "unknown":
        return None
    return PackageURL(
        type="pypi", name=canonicalize_name(str(name)), version=str(version)
    )


def specifier_comment(dep: Dict[str, Any]) -> Optional[str]:
    """The SPDX package comment that carries a non-exact specifier."""
    spec = dep.get("specifier")
    return f"Requirement specifier: {spec}" if spec else None
