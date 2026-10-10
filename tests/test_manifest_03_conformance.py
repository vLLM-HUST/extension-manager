from scripts.check_manifest_03_conformance import main, validate_vectors


def test_stable_manifest_03_vectors_are_conformant() -> None:
    assert validate_vectors() == []


def test_stable_manifest_03_checker_reports_coverage(capsys) -> None:
    assert main() == 0
    assert "6 conformance vectors, 1 migration vector" in capsys.readouterr().out
