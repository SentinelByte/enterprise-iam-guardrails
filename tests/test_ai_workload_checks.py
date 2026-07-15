from iam_guardrails.ai_workloads.checks import (
    check_ai_service_permissions,
    combine_trust_and_permissions,
)
from iam_guardrails.findings import Finding, Severity
from iam_guardrails.trust_policy.analyzer import analyze_trust_policy


def test_scoped_ai_policy_produces_no_findings(load_fixture):
    findings = check_ai_service_permissions(load_fixture("ai_policy_scoped.json"), "role")
    assert findings == []


def test_broad_ai_policy_flags_wildcard_and_logging(load_fixture):
    findings = check_ai_service_permissions(load_fixture("ai_policy_broad.json"), "role")
    check_ids = {f.check_id for f in findings}
    assert "ai_workloads.wildcard_service_permissions" in check_ids
    assert "ai_workloads.logging_config_mutable" in check_ids


def test_combine_requires_both_weak_trust_and_permissions(load_fixture):
    trust_findings = analyze_trust_policy(load_fixture("trust_wildcard.json"), "ai-role")
    permission_findings = check_ai_service_permissions(
        load_fixture("ai_policy_broad.json"), "ai-role"
    )

    combined = combine_trust_and_permissions(trust_findings, permission_findings, "ai-role")

    assert len(combined) == 1
    assert combined[0].severity == Severity.CRITICAL
    assert combined[0].check_id == "ai_workloads.broadly_trusted_ai_role"


def test_combine_is_empty_without_permission_findings():
    trust_findings = [
        Finding(
            check_id="trust_policy.wildcard_principal",
            resource="role",
            severity=Severity.CRITICAL,
            message="wildcard",
            remediation="fix it",
        )
    ]
    assert combine_trust_and_permissions(trust_findings, [], "role") == []


def test_combine_is_empty_without_weak_trust(load_fixture):
    trust_findings = analyze_trust_policy(
        load_fixture("trust_specific_role.json"), "ai-role", own_account_id="111111111111"
    )
    permission_findings = check_ai_service_permissions(
        load_fixture("ai_policy_broad.json"), "ai-role"
    )
    assert combine_trust_and_permissions(trust_findings, permission_findings, "ai-role") == []
