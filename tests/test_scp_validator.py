import pytest

from iam_guardrails.scp.validator import SCPSyntaxError, validate_scp


def test_valid_scp_produces_no_findings(load_fixture):
    findings = validate_scp(load_fixture("scp_valid.json"))
    assert findings == []


def test_unconditioned_deny_all_is_critical(load_fixture):
    findings = validate_scp(load_fixture("scp_deny_all.json"))
    check_ids = {f.check_id for f in findings}
    assert "scp.full_deny_all" in check_ids


def test_unconditioned_broad_allow_is_flagged(load_fixture):
    findings = validate_scp(load_fixture("scp_broad_allow.json"))
    check_ids = {f.check_id for f in findings}
    assert "scp.unconditioned_broad_allow" in check_ids
    assert "scp.missing_sid" in check_ids


def test_structurally_invalid_scp_raises(load_fixture):
    with pytest.raises(SCPSyntaxError):
        validate_scp(load_fixture("scp_invalid.json"))
