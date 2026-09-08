"""Guards for the discovery metadata that PyPI and GitHub index.

None of this is runtime behaviour, which is exactly why it needs a test: the
keywords, classifiers and README terms are invisible in every normal code
review and silently deleteable in a routine `pyproject.toml` edit. The cost of
losing them is not a crash, it is that the package stops turning up in the
searches buyers actually run.
"""

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _poetry_table() -> dict:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["tool"]["poetry"]


# The high-intent terms from PLAN-2026-08-08 Part 1.4, in PyPI keyword form.
TARGET_KEYWORDS = {
    "aibom",
    "ai-bom",
    "mlbom",
    "model-scanning",
    "eu-ai-act",
    "cra",
    "mlsecops",
    "sbom",
    "cyclonedx",
    "spdx",
}

# The same terms in the human-readable form the README uses.
TARGET_README_TERMS = (
    "AIBOM",
    "ML-BOM",
    "MLSecOps",
    "EU AI Act",
    "Annex XI",
    "Cyber Resilience Act",
    "524B",
)


def test_license_is_declared_and_matches_the_license_file():
    assert _poetry_table()["license"] == "Apache-2.0"
    assert "Apache License" in (REPO_ROOT / "LICENSE").read_text()


def test_keywords_cover_the_target_search_terms():
    keywords = _poetry_table()["keywords"]
    assert TARGET_KEYWORDS <= set(keywords), TARGET_KEYWORDS - set(keywords)


def test_keywords_are_normalised_and_unique():
    keywords = _poetry_table()["keywords"]
    assert len(keywords) == len(set(keywords)), "duplicate keyword"
    for keyword in keywords:
        assert keyword == keyword.strip().lower(), keyword
        assert re.fullmatch(r"[a-z0-9][a-z0-9-]*", keyword), keyword


def test_classifiers_are_well_formed_and_carry_the_key_facets():
    classifiers = _poetry_table()["classifiers"]
    for classifier in classifiers:
        # PyPI rejects the whole upload on a malformed classifier, so a typo
        # here is a release-time failure, not a cosmetic one.
        assert " :: " in classifier, classifier
        assert classifier == classifier.strip(), classifier
    assert "License :: OSI Approved :: Apache Software License" in classifiers
    assert "Topic :: Security" in classifiers
    assert "Topic :: Scientific/Engineering :: Artificial Intelligence" in classifiers


def test_summary_describes_the_tool_without_duplicated_words():
    description = _poetry_table()["description"]
    assert 40 < len(description) <= 300, len(description)
    words = re.findall(r"\b\w+\b", description.lower())
    repeats = [a for a, b in zip(words, words[1:]) if a == b]
    assert not repeats, f"duplicated word(s) in summary: {repeats}"


def test_readme_covers_the_target_terms():
    readme = (REPO_ROOT / "README.md").read_text()
    missing = [term for term in TARGET_README_TERMS if term not in readme]
    assert not missing, missing
