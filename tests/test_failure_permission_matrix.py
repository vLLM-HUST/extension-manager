from scripts.check_failure_permission_matrix import main, validate_matrix


def test_release_failure_permission_matrix_is_executable() -> None:
    assert validate_matrix() == []


def test_release_failure_permission_matrix_reports_coverage(capsys) -> None:
    assert main() == 0
    assert "9 executable cases" in capsys.readouterr().out
