"""Structural and semantic validation of AWS Service Control Policies.

Structural validation (JSON Schema) catches malformed documents. Semantic
checks catch documents that are *valid* but defeat the purpose of an SCP —
these are the mistakes that pass a syntax check and still cause incidents.
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft7Validator

from iam_guardrails.findings import Finding, Severity
from iam_guardrails.scp.schema import SCP_SCHEMA


class SCPSyntaxError(Exception):
    """Raised when an SCP document fails structural (JSON Schema) validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"{len(errors)} structural issue(s) found")


def _as_list(value: str | list[str]) -> list[str]:
    return value if isinstance(value, list) else [value]


def check_structure(policy: dict[str, Any]) -> list[str]:
    """Validate an SCP document against the AWS SCP JSON Schema.

    Returns a list of human-readable error strings (empty if valid).
    """
    validator = Draft7Validator(SCP_SCHEMA)
    errors = sorted(validator.iter_errors(policy), key=lambda e: list(e.path))
    messages = []
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        messages.append(f"{location}: {error.message}")
    return messages


def check_semantics(policy: dict[str, Any], policy_name: str = "scp") -> list[Finding]:
    """Flag SCP documents that are syntactically valid but likely mistakes."""
    findings: list[Finding] = []

    for index, statement in enumerate(policy.get("Statement", [])):
        sid = statement.get("Sid") or f"statement[{index}]"
        resource = f"{policy_name}:{sid}"
        effect = statement.get("Effect")
        actions = _as_list(statement.get("Action", []))
        resources = _as_list(statement.get("Resource", []))
        has_condition = bool(statement.get("Condition"))
        is_full_action = "*" in actions or "*:*" in actions
        is_full_resource = "*" in resources

        if effect == "Deny" and is_full_action and is_full_resource and not has_condition:
            findings.append(
                Finding(
                    check_id="scp.full_deny_all",
                    resource=resource,
                    severity=Severity.CRITICAL,
                    message=(
                        "Statement denies every action on every resource with no "
                        "Condition. Attached to an OU or account, this disables "
                        "the entire scope, including emergency/break-glass access."
                    ),
                    remediation=(
                        "Scope Action/Resource to the specific guardrail you "
                        "intend to enforce, or add a Condition (e.g. "
                        "aws:PrincipalArn exceptions) for break-glass roles."
                    ),
                )
            )

        if effect == "Allow" and is_full_action and is_full_resource and not has_condition:
            findings.append(
                Finding(
                    check_id="scp.unconditioned_broad_allow",
                    resource=resource,
                    severity=Severity.HIGH,
                    message=(
                        "Statement allows every action on every resource with no "
                        "Condition. SCPs only filter permissions granted "
                        "elsewhere, so an unconditioned Allow '*' provides no "
                        "guardrail and often signals the policy's real intent "
                        "(an explicit allow-list) was never written."
                    ),
                    remediation=(
                        "Replace with an explicit list of allowed actions, or "
                        "convert this SCP to a Deny-based guardrail."
                    ),
                )
            )

        if not statement.get("Sid"):
            findings.append(
                Finding(
                    check_id="scp.missing_sid",
                    resource=resource,
                    severity=Severity.LOW,
                    message="Statement has no Sid, which makes change review and audit harder.",
                    remediation="Add a descriptive Sid to every statement.",
                )
            )

    return findings


def validate_scp(policy: dict[str, Any], policy_name: str = "scp") -> list[Finding]:
    """Validate structure, then run semantic checks.

    Raises SCPSyntaxError if the document is structurally invalid — semantic
    checks assume a well-formed document and would otherwise raise KeyError.
    """
    structural_errors = check_structure(policy)
    if structural_errors:
        raise SCPSyntaxError(structural_errors)
    return check_semantics(policy, policy_name)
