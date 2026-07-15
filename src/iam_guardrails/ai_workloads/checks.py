"""IAM posture checks specific to AI/ML workloads (Bedrock, SageMaker).

Most IAM scanners treat every service the same way. AI services deserve
dedicated checks because their blast radius is different from a typical
data-plane API:

- An over-broad ``bedrock:InvokeModel`` grant isn't just "too permissive" —
  it's unbounded inference spend, a path to model/prompt extraction, and (if
  the model has tool access) a foothold for prompt-injection-driven actions.
- Disabling Bedrock invocation logging removes the audit trail regulators
  and incident responders need to reconstruct what an AI system did.
- SageMaker notebook instances are internet-facing Jupyter environments
  with the training role's credentials on the underlying host — a notebook
  permission is a much bigger grant than it looks.

This module also composes with ``iam_guardrails.trust_policy``: a role that
merely has broad AI permissions is a policy hygiene issue, but a role that
has broad AI permissions *and* is assumable by an under-scoped trust policy
is a much higher-value target, so the two findings are recombined into a
single elevated finding by ``combine_trust_and_permissions``.
"""

from __future__ import annotations

from typing import Any

from iam_guardrails.findings import Finding, Severity

_WILDCARD_SERVICE_ACTIONS = {"bedrock:*", "sagemaker:*"}

_SENSITIVE_INVOKE_ACTIONS = {
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
    "bedrock:ConverseStream",
}

_LOGGING_CONTROL_ACTIONS = {
    "bedrock:PutModelInvocationLoggingConfiguration",
    "bedrock:DeleteModelInvocationLoggingConfiguration",
}

_NOTEBOOK_ACTIONS = {
    "sagemaker:CreateNotebookInstance",
    "sagemaker:CreatePresignedNotebookInstanceUrl",
    "sagemaker:CreatePresignedDomainUrl",
}


def _as_list(value: str | list[str]) -> list[str]:
    return value if isinstance(value, list) else [value]


def check_ai_service_permissions(policy: dict[str, Any], policy_name: str) -> list[Finding]:
    """Flag over-broad Bedrock/SageMaker grants in an IAM permission policy."""
    findings: list[Finding] = []

    for index, statement in enumerate(policy.get("Statement", [])):
        if statement.get("Effect") != "Allow":
            continue

        sid = statement.get("Sid") or f"statement[{index}]"
        resource_ref = f"{policy_name}:{sid}"
        actions = _as_list(statement.get("Action", []))
        resources = _as_list(statement.get("Resource", []))
        has_condition = bool(statement.get("Condition"))
        is_full_resource = "*" in resources

        for action in actions:
            if action in _WILDCARD_SERVICE_ACTIONS and is_full_resource:
                findings.append(
                    Finding(
                        check_id="ai_workloads.wildcard_service_permissions",
                        resource=resource_ref,
                        severity=Severity.HIGH,
                        message=(
                            f"Statement grants '{action}' on all resources — "
                            "unrestricted control over the AI service, including "
                            "model access, data, and configuration."
                        ),
                        remediation=(
                            "Enumerate the specific actions the workload needs "
                            "and scope Resource to approved model/endpoint ARNs."
                        ),
                    )
                )
            elif action in _SENSITIVE_INVOKE_ACTIONS and is_full_resource and not has_condition:
                findings.append(
                    Finding(
                        check_id="ai_workloads.unscoped_model_invocation",
                        resource=resource_ref,
                        severity=Severity.MEDIUM,
                        message=(
                            f"'{action}' is allowed on all model resources with no "
                            "Condition, enabling unbounded inference spend and "
                            "invocation of models outside the intended set."
                        ),
                        remediation=(
                            "Scope Resource to approved foundation model ARNs and "
                            "consider an aws:SourceVpce or request-tag Condition."
                        ),
                    )
                )
            elif action in _LOGGING_CONTROL_ACTIONS:
                findings.append(
                    Finding(
                        check_id="ai_workloads.logging_config_mutable",
                        resource=resource_ref,
                        severity=Severity.HIGH,
                        message=(
                            f"'{action}' lets this principal disable or rewrite "
                            "Bedrock invocation logging, removing the audit trail "
                            "for model usage."
                        ),
                        remediation=(
                            "Restrict logging-configuration actions to a "
                            "break-glass admin role, separate from workload roles."
                        ),
                    )
                )
            elif action in _NOTEBOOK_ACTIONS and is_full_resource:
                findings.append(
                    Finding(
                        check_id="ai_workloads.broad_notebook_access",
                        resource=resource_ref,
                        severity=Severity.MEDIUM,
                        message=(
                            f"'{action}' is allowed on all resources. SageMaker "
                            "notebook/domain URLs grant an internet-reachable "
                            "Jupyter environment running with the execution "
                            "role's credentials — treat this as a high-value grant."
                        ),
                        remediation=(
                            "Scope Resource to specific notebook/domain ARNs and "
                            "restrict who can create presigned URLs."
                        ),
                    )
                )

    return findings


def combine_trust_and_permissions(
    trust_findings: list[Finding],
    permission_findings: list[Finding],
    role_name: str,
) -> list[Finding]:
    """Elevate risk when a broadly-trusted role also carries AI permissions.

    A role's trust findings and permission findings are usually reviewed in
    isolation. Recombining them catches the case that matters most: an AI
    execution role that's both easy to assume and highly capable once
    assumed.
    """
    if not permission_findings:
        return []

    risky_trust = [f for f in trust_findings if f.severity.rank >= Severity.HIGH.rank]
    if not risky_trust:
        return []

    worst_permission = max(permission_findings, key=lambda f: f.severity.rank)
    trust_reasons = "; ".join(f.message for f in risky_trust)

    return [
        Finding(
            check_id="ai_workloads.broadly_trusted_ai_role",
            resource=role_name,
            severity=Severity.CRITICAL,
            message=(
                f"Role '{role_name}' combines a weak trust boundary ({trust_reasons}) "
                f"with broad AI-service permissions ({worst_permission.message}). "
                "Compromise or misuse of this role's trust relationship "
                "directly translates into AI-service impact, not just "
                "generic account access."
            ),
            remediation=(
                "Tighten the trust policy first (see trust_policy findings), "
                "then re-run this check — the permission grants may be "
                "acceptable once the role is no longer broadly assumable."
            ),
        )
    ]
