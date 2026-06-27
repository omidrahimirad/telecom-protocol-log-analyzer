from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.cli import main


def test_cli_analyze_smoke(capsys: object) -> None:
    exit_code = main(["analyze", "data/samples/registration_auth_failure.log"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "5G_REGISTRATION_AUTHENTICATION_FAILURE" in captured.out


def test_cli_export_and_explain(tmp_path: Path, capsys: object) -> None:
    output = tmp_path / "report.json"

    exit_code = main(
        [
            "export",
            "data/samples/handover_failure_target_cell_unavailable.log",
            "--format",
            "json",
            "--output",
            str(output),
        ]
    )
    assert exit_code == 0
    assert output.exists()

    explain_code = main(["explain-message", "RegistrationReject"])
    captured = capsys.readouterr()
    assert explain_code == 0
    assert "rejects registration" in captured.out


def test_cli_validate_log_reports_warnings(tmp_path: Path, capsys: object) -> None:
    log = tmp_path / "bad.log"
    log.write_text("not-a-valid-line\n", encoding="utf-8")

    exit_code = main(["validate-log", str(log)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Warnings: 1" in captured.out


def test_cli_json_markdown_list_generate_and_analyze_dir(tmp_path: Path, capsys: object) -> None:
    generated = tmp_path / "generated.log"

    generate_code = main(
        [
            "generate",
            "--scenario",
            "normal_5g_registration",
            "--ues",
            "1",
            "--output",
            str(generated),
        ]
    )
    assert generate_code == 0
    assert generated.exists()

    json_code = main(["analyze", str(generated), "--format", "json"])
    markdown_code = main(["analyze", str(generated), "--format", "markdown"])
    list_code = main(["explain-message", "--list"])
    dir_code = main(["analyze-dir", "data/samples"])
    captured = capsys.readouterr()

    assert json_code == 0
    assert markdown_code == 0
    assert list_code == 0
    assert dir_code == 1
    assert "RegistrationRequest" in captured.out
