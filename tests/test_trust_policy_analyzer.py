from iam_guardrails.findings import Severity
from iam_guardrails.trust_policy.analyzer import analyze_trust_policy


def test_wildcard_principal_is_critical(load_fixture):
    findings = analyze_trust_policy(load_fixture("trust_wildcard.json"), "my-role")
    assert len(findings) == 1
    assert findings[0].check_id == "trust_policy.wildcard_principal"
    assert findings[0].severity == Severity.CRITICAL


def test_external_account_without_condition_is_high(load_fixture):
    findings = analyze_trust_policy(
        load_fixture("trust_external_no_condition.json"),
        "my-role",
        own_account_id="111111111111",
    )
    assert len(findings) == 1
    assert findings[0].check_id == "trust_policy.external_account_no_condition"
    assert findings[0].severity == Severity.HIGH


def test_external_account_with_condition_is_downgraded(load_fixture):
    findings = analyze_trust_policy(
        load_fixture("trust_external_with_condition.json"),
        "my-role",
        own_account_id="111111111111",
    )
    assert len(findings) == 1
    assert findings[0].check_id == "trust_policy.external_account"
    assert findings[0].severity == Severity.MEDIUM


def test_same_account_role_principal_is_low_or_none(load_fixture):
    findings = analyze_trust_policy(
        load_fixture("trust_specific_role.json"),
        "my-role",
        own_account_id="111111111111",
    )
    assert len(findings) == 1
    assert findings[0].check_id == "trust_policy.specific_principal"
    assert findings[0].severity == Severity.LOW


def test_own_account_id_unknown_skips_external_check(load_fixture):
    findings = analyze_trust_policy(
        load_fixture("trust_external_no_condition.json"), "my-role", own_account_id=None
    )
    assert findings == []
