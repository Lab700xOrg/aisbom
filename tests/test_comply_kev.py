"""The FDA pack's vulnerability table and its CISA KEV column.

Pack-level tests call `build_fda_pack` directly; CLI tests stub OSV and the
KEV lookup at module level, so no network is touched.
"""

import csv
import io

import pytest
from typer.testing import CliRunner

from aisbom import comply, kev, osv
from aisbom.cli import app
from aisbom.vex import VEX_FINDING_CLASSES, FindingClass, VexStatement
from tests.test_comply import _local_sbom, _restricted_tree

runner = CliRunner()


def _cve(primary, ref="dependency-0-torch", status="affected", aliases=()):
    finding = FindingClass(
        id=primary, title=primary, description=primary, action="Upgrade.",
        formats=frozenset(), aliases=tuple(aliases),
        reference_url=f"https://osv.dev/vulnerability/{primary}",
        source_name=osv.OSV_SOURCE_NAME,
    )
    return VexStatement(finding_class=finding, product_ref=ref, product_id="",
                        product_hash=None, status=status)


def _model_statement():
    return VexStatement(finding_class=VEX_FINDING_CLASSES[0],
                        product_ref="artifact-0-weights|v2.pt", product_id="x",
                        product_hash=None, status="affected")


STATEMENTS = [
    _cve("CVE-2025-1111"),
    _cve("GHSA-aaaa-bbbb-cccc", aliases=("CVE-2024-2222", "PYSEC-2024-9")),
    _cve("CVE-2023-3333", status="under_investigation"),
    _model_statement(),
]


def _pack(statements=STATEMENTS, added=None, catalog=None, note=None):
    return comply.build_fda_pack(
        _local_sbom(), target="./models", vex_statements=statements,
        vex_files=["sbom.openvex.json"],
        kev_added=added, kev_catalog_version=catalog, kev_note=note,
    )


def _rows(pack):
    return list(csv.DictReader(io.StringIO(pack[comply.VULNERABILITIES_FILE])))


# -- the table ----------------------------------------------------------------

def test_fda_pack_always_writes_the_vulnerability_table():
    assert comply.VULNERABILITIES_FILE in _pack(statements=[])
    assert _rows(_pack(statements=[])) == []


def test_one_row_per_dependency_cve_statement_and_no_model_findings():
    rows = _rows(_pack(added={}, catalog="2026.11.25"))
    assert [r["vulnerability_id"] for r in rows] == [
        "CVE-2025-1111", "GHSA-aaaa-bbbb-cccc", "CVE-2023-3333"]
    first = rows[0]
    assert first["component_bom_ref"] == "dependency-0-torch"
    assert first["component"] == "torch"
    assert first["component_version"] == "2.10.0"
    assert first["vex_status"] == "affected"
    assert rows[1]["aliases"] == "CVE-2024-2222;PYSEC-2024-9"


def test_listed_cves_carry_the_kev_date_and_absent_ones_are_blank():
    rows = _rows(_pack(added={"CVE-2025-1111": "2025-03-04"}, catalog="2026.11.25"))
    assert rows[0]["cisa_kev_date_added"] == "2025-03-04"
    assert rows[1]["cisa_kev_date_added"] == ""
    assert rows[2]["cisa_kev_date_added"] == ""


def test_a_cve_known_only_as_an_alias_still_matches():
    rows = _rows(_pack(added={"CVE-2024-2222": "2024-08-01"}, catalog="2026.11.25"))
    assert rows[1]["cisa_kev_date_added"] == "2024-08-01"


def test_when_the_lookup_did_not_run_the_column_is_todo():
    rows = _rows(_pack(added=None, note="skipped (--offline)"))
    assert {r["cisa_kev_date_added"] for r in rows} == {comply.TODO}


def test_the_kev_columns_list_every_cve_id_the_lookup_can_use():
    assert comply.kev_cve_ids(STATEMENTS) == [
        "CVE-2025-1111", "CVE-2024-2222", "CVE-2023-3333"]


def test_statements_without_a_finding_class_are_tolerated():
    class _S:
        status = "affected"

    assert comply.kev_cve_ids([_S()]) == []
    assert _rows(_pack(statements=[_S()])) == []


# -- the README ---------------------------------------------------------------

def _readme(**kw):
    return _pack(**kw)[comply.README_FILE]


def test_readme_counts_kev_listings_and_names_the_catalogue():
    readme = _readme(added={"CVE-2025-1111": "2025-03-04"}, catalog="2026.11.25")
    assert ("1 of 3 dependency CVE statement(s) name a CVE in CISA's Known "
            "Exploited Vulnerabilities catalogue (version 2026.11.25)") in readme
    assert comply.VULNERABILITIES_FILE in readme


def test_readme_does_not_turn_a_blank_into_a_verdict():
    readme = _readme(added={}, catalog="2026.11.25").lower()
    assert "not evidence that a vulnerability cannot be exploited" in readme


def test_readme_says_why_the_kev_lookup_did_not_run():
    readme = _readme(added=None, note="skipped (--no-kev-lookup)")
    assert "CISA KEV lookup: skipped (--no-kev-lookup)." in readme


def test_readme_with_no_cve_statements_says_kev_was_not_consulted():
    readme = _readme(statements=[], added={})
    assert "no dependency CVE statements, so the CISA KEV catalogue was not read" in readme


def test_readme_file_table_lists_the_vulnerability_table():
    assert f"| {comply.VULNERABILITIES_FILE} |" in _readme(statements=[])


# -- the CLI ------------------------------------------------------------------

def _fda_cli(tmp_path, monkeypatch, *flags, kev_result=None, statements=STATEMENTS[:3]):
    calls = []

    def fake_osv(deps, **kw):
        return osv.OsvLookupResult(statements=list(statements), queried=1)

    def fake_kev(ids, **kw):
        calls.append(list(ids))
        return kev_result or kev.KevLookupResult(
            added={"CVE-2025-1111": "2025-03-04"}, catalog_version="2026.11.25")

    monkeypatch.setattr(osv, "lookup_dependency_statements", fake_osv)
    monkeypatch.setattr(kev, "lookup_known_exploited", fake_kev)
    src = _restricted_tree(tmp_path)
    (src / "requirements.txt").write_text("torch==2.10.0\n")
    out = tmp_path / "pack"
    result = runner.invoke(app, ["comply", str(src), "--framework", "fda",
                                 "--output-dir", str(out), "--no-eol-lookup", *flags])
    assert result.exit_code == 0, result.stdout
    return calls, out, result


def _cli_rows(out):
    return list(csv.DictReader(io.StringIO((out / comply.VULNERABILITIES_FILE).read_text())))


def test_cli_marks_kev_listed_cves(tmp_path, monkeypatch):
    calls, out, _ = _fda_cli(tmp_path, monkeypatch)
    assert calls == [["CVE-2025-1111", "CVE-2024-2222", "CVE-2023-3333"]]
    rows = _cli_rows(out)
    assert rows[0]["cisa_kev_date_added"] == "2025-03-04"
    assert rows[1]["cisa_kev_date_added"] == ""
    assert "version 2026.11.25" in (out / comply.README_FILE).read_text()


@pytest.mark.parametrize("flags, env, note", [
    (("--no-kev-lookup",), {}, "skipped (--no-kev-lookup)"),
    ((), {"AISBOM_NO_KEV_LOOKUP": "1"}, "skipped (--no-kev-lookup)"),
])
def test_cli_opt_out_makes_no_request(tmp_path, monkeypatch, flags, env, note):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    calls, out, _ = _fda_cli(tmp_path, monkeypatch, *flags)
    assert calls == []
    assert {r["cisa_kev_date_added"] for r in _cli_rows(out)} == {comply.TODO}
    assert f"CISA KEV lookup: {note}." in (out / comply.README_FILE).read_text()


def test_cli_offline_makes_no_kev_request(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("KEV fetched with --offline")

    monkeypatch.setattr(kev, "lookup_known_exploited", boom)
    src = _restricted_tree(tmp_path)
    (src / "requirements.txt").write_text("torch==2.10.0\n")
    out = tmp_path / "pack"
    result = runner.invoke(app, ["comply", str(src), "--framework", "fda",
                                 "--output-dir", str(out), "--offline"])
    assert result.exit_code == 0, result.stdout
    assert "CISA KEV lookup: skipped (--offline)." in (out / comply.README_FILE).read_text()


def test_cli_no_cve_statements_makes_no_kev_request(tmp_path, monkeypatch):
    calls, out, _ = _fda_cli(tmp_path, monkeypatch, statements=[])
    assert calls == []


def test_cli_failed_kev_lookup_warns_and_still_writes_the_pack(tmp_path, monkeypatch):
    failed = kev.KevLookupResult(error="CISA KEV request failed (ConnectionError)")
    calls, out, result = _fda_cli(tmp_path, monkeypatch, kev_result=failed)
    assert "CISA KEV request failed" in result.stdout
    assert {r["cisa_kev_date_added"] for r in _cli_rows(out)} == {comply.TODO}
    assert ("CISA KEV lookup: CISA KEV request failed (ConnectionError)."
            in (out / comply.README_FILE).read_text())


def test_cli_scan_vex_never_reads_kev(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("KEV fetched by scan")

    monkeypatch.setattr(kev, "lookup_known_exploited", boom)
    monkeypatch.setattr(osv, "lookup_dependency_statements",
                        lambda deps, **kw: osv.OsvLookupResult(statements=STATEMENTS[:1]))
    src = _restricted_tree(tmp_path)
    (src / "requirements.txt").write_text("torch==2.10.0\n")
    result = runner.invoke(app, ["scan", str(src), "--vex", "--output",
                                 str(tmp_path / "sbom.json"), "--no-fail-on-risk"])
    assert result.exit_code == 0, result.stdout


def test_cli_eu_pack_never_reads_kev(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("KEV fetched for an EU pack")

    monkeypatch.setattr(kev, "lookup_known_exploited", boom)
    src = _restricted_tree(tmp_path)
    result = runner.invoke(app, ["comply", str(src), "--framework", "eu-ai-act",
                                 "--output-dir", str(tmp_path / "eu")])
    assert result.exit_code == 0, result.stdout
    assert not (tmp_path / "eu" / comply.VULNERABILITIES_FILE).exists()


def test_answers_cannot_overwrite_the_vulnerability_table(tmp_path):
    out = tmp_path / "pack"
    out.mkdir()
    target = out / comply.VULNERABILITIES_FILE
    target.write_text("version: 1\n")
    src = _restricted_tree(tmp_path)
    result = runner.invoke(app, ["comply", str(src), "--framework", "fda",
                                 "--output-dir", str(out), "--offline",
                                 "--answers", str(target)])
    assert result.exit_code == 1
    assert "own vulnerabilities.csv" in " ".join(result.stdout.split())
