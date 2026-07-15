from pathlib import Path

from iam_guardrails.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_validate_scp_exits_zero_on_clean_policy(capsys):
    exit_code = main(["validate-scp", str(FIXTURES / "scp_valid.json")])
    assert exit_code == 0


def test_validate_scp_exits_nonzero_on_high_severity_finding(capsys):
    exit_code = main(["validate-scp", str(FIXTURES / "scp_broad_allow.json")])
    assert exit_code == 1


def test_validate_scp_exits_nonzero_on_structural_error(capsys):
    exit_code = main(["validate-scp", str(FIXTURES / "scp_invalid.json")])
    assert exit_code == 1


def test_scan_trust_policy_json_output(capsys):
    exit_code = main(
        ["scan-trust-policy", str(FIXTURES / "trust_wildcard.json"), "--json"]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "trust_policy.wildcard_principal" in captured.out


def test_scan_ai_workloads_combines_findings(capsys):
    exit_code = main(
        [
            "scan-ai-workloads",
            str(FIXTURES / "trust_wildcard.json"),
            str(FIXTURES / "ai_policy_broad.json"),
            "--role-name",
            "ai-role",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "ai_workloads.broadly_trusted_ai_role" in captured.out
