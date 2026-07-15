"""Risk analysis of IAM role trust policies (who can assume this role).

A trust policy is a resource-based policy attached to a role, distinct from
the permission policies attached to it. It answers "who can call
sts:AssumeRole on this role", not "what can the role do once assumed" — that
second question is out of scope here and covered separately in
``iam_guardrails.ai_workloads`` where the two are deliberately recombined.
"""

from __future__ import annotations

from typing import Any, TypeVar, cast

import boto3

from iam_guardrails.findings import Finding, Severity

T = TypeVar("T")


def _as_list(value: T | list[T]) -> list[T]:
    return value if isinstance(value, list) else [value]


def analyze_trust_policy(
    policy: dict[str, Any], role_name: str, own_account_id: str | None = None
) -> list[Finding]:
    """Analyze a single role's trust policy document for risky principals.

    ``own_account_id`` enables the external-account check; pass ``None`` to
    skip it (e.g. when the caller account is unknown, as in offline use).
    """
    findings: list[Finding] = []
    statements: list[dict[str, Any]] = _as_list(policy.get("Statement", []))

    for statement in statements:
        effect = statement.get("Effect", "")
        actions: list[str] = _as_list(statement.get("Action", ""))
        if effect != "Allow" or "sts:AssumeRole" not in actions:
            continue

        principal = statement.get("Principal", {})
        has_condition = bool(statement.get("Condition"))

        if isinstance(principal, str) and principal == "*":
            findings.append(_wildcard_finding(role_name))
            continue

        if not isinstance(principal, dict):
            continue

        for principal_type, raw_value in principal.items():
            for entry in _as_list(raw_value):
                findings.extend(
                    _evaluate_principal_entry(
                        role_name, principal_type, entry, own_account_id, has_condition
                    )
                )

    return findings


def _wildcard_finding(role_name: str) -> Finding:
    return Finding(
        check_id="trust_policy.wildcard_principal",
        resource=role_name,
        severity=Severity.CRITICAL,
        message='Trust policy allows Principal "*" to assume this role.',
        remediation=(
            "Replace the wildcard with explicit account/role ARNs. If this "
            "is intentional (e.g. a public SAML/OIDC-fronted role), the "
            "restriction must happen entirely in the Condition block — "
            "verify one is present and sufficiently strict."
        ),
    )


def _evaluate_principal_entry(
    role_name: str,
    principal_type: str,
    entry: str,
    own_account_id: str | None,
    has_condition: bool,
) -> list[Finding]:
    if entry == "*":
        return [_wildcard_finding(role_name)]

    if principal_type == "Service":
        return [
            Finding(
                check_id="trust_policy.service_principal",
                resource=role_name,
                severity=Severity.LOW,
                message=f"Trust policy trusts AWS service principal: {entry}.",
                remediation="Expected for service-linked roles; confirm the service is intended.",
            )
        ]

    if principal_type == "Federated":
        return [
            Finding(
                check_id="trust_policy.federated_principal",
                resource=role_name,
                severity=Severity.LOW,
                message=f"Trust policy trusts a federated identity provider: {entry}.",
                remediation=(
                    "Confirm the IdP is expected and its audience/subject conditions are scoped."
                ),
            )
        ]

    if principal_type != "AWS":
        return []

    if not entry.startswith("arn:aws:iam::"):
        return [
            Finding(
                check_id="trust_policy.unusual_principal_format",
                resource=role_name,
                severity=Severity.MEDIUM,
                message=f"Unusual AWS principal format: {entry}.",
                remediation="Use a fully-qualified IAM ARN or account ID; investigate this value.",
            )
        ]

    if not entry.endswith(":root"):
        return [
            Finding(
                check_id="trust_policy.specific_principal",
                resource=role_name,
                severity=Severity.LOW,
                message=f"Trust policy scopes to a specific IAM principal: {entry}.",
                remediation=(
                    "No action needed; this is the preferred pattern over account-root trust."
                ),
            )
        ]

    account_id = entry.split("::")[1].split(":")[0]
    if own_account_id is None or account_id == own_account_id:
        return []

    if not has_condition:
        return [
            Finding(
                check_id="trust_policy.external_account_no_condition",
                resource=role_name,
                severity=Severity.HIGH,
                message=(
                    f"Trust policy grants account root {account_id} the ability to "
                    "assume this role with no Condition. Anyone with "
                    "sts:AssumeRole permission in that account can assume this "
                    "role — a classic confused-deputy setup."
                ),
                remediation=(
                    "Require sts:ExternalId (and ideally MFA via "
                    "aws:MultiFactorAuthPresent) in the trust policy Condition."
                ),
            )
        ]

    return [
        Finding(
            check_id="trust_policy.external_account",
            resource=role_name,
            severity=Severity.MEDIUM,
            message=(
                f"Trust policy grants external account {account_id} conditional "
                "assume-role access."
            ),
            remediation="Confirm this external account is an approved partner/vendor.",
        )
    ]


def scan_account(iam_client: Any | None = None) -> list[Finding]:
    """Scan every IAM role in the caller's account. Requires AWS credentials.

    Pass an existing boto3 IAM client (e.g. for moto-mocked tests); otherwise
    one is created from the default credential chain.
    """
    iam_client = iam_client or boto3.client("iam")
    account_id = boto3.client("sts").get_caller_identity()["Account"]

    findings: list[Finding] = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            trust_policy = cast(dict[str, Any], role["AssumeRolePolicyDocument"])
            findings.extend(analyze_trust_policy(trust_policy, role["RoleName"], account_id))
    return findings
