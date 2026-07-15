"""iam_guardrails: offline-first analysis of AWS IAM guardrails.

Three composable checks:

- ``scp``: structural + semantic validation of Service Control Policies.
- ``trust_policy``: risk analysis of IAM role trust relationships.
- ``ai_workloads``: IAM posture checks specific to Bedrock/SageMaker workloads,
  including cross-cutting checks that combine trust and permission findings.
"""

from iam_guardrails.findings import Finding, Severity

__all__ = ["Finding", "Severity"]
__version__ = "0.1.0"
