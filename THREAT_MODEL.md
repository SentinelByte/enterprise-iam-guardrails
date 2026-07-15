# Threat model

## What this is

`iam-guardrails` reads IAM documents — SCPs, role trust policies,
permission policies, either as local JSON files or via read-only
`iam:List*`/`iam:Get*` calls — and reports findings. It never calls a
mutating API and never touches AWS state. If you point it at your account,
the worst it can do is print something you didn't want to hear.

## What it's not trying to be

- Not a replacement for AWS Config, IAM Access Analyzer, or Security Hub —
  those do continuous, account-wide monitoring at a scale this project
  isn't aiming for.
- Not a least-privilege analyzer. It won't look at CloudTrail history to
  tell you a permission is unused; it flags patterns that are risky by
  construction, regardless of whether they're ever exercised.
- Not an auto-fixer. Every finding suggests a remediation, but nothing here
  writes to AWS on your behalf.

## What each check is actually looking for

| Check | Attack pattern | Rough ATT&CK mapping |
|---|---|---|
| `scp.full_deny_all` | Accidental blanket Deny locks an OU/account out of its own emergency access — an availability incident, not an intrusion. | — |
| `scp.unconditioned_broad_allow` | An SCP that allows everything provides no guardrail; it's a false sense of security that masks the fact no real boundary was ever written. | — |
| `trust_policy.wildcard_principal` | Any AWS principal on Earth can assume the role. | T1078.004 (Valid Accounts: Cloud Accounts) |
| `trust_policy.external_account_no_condition` | Classic confused-deputy setup: an external account's `sts:AssumeRole` permission is enough on its own, with no shared secret (`sts:ExternalId`) or MFA check. | T1078.004, T1548 |
| `ai_workloads.wildcard_service_permissions` | Unrestricted Bedrock/SageMaker control — model access, config, and data in one grant. | T1530-adjacent (cloud data/service access) |
| `ai_workloads.unscoped_model_invocation` | Unbounded `bedrock:InvokeModel` enables cost-abuse and invocation of models outside the intended set. | — |
| `ai_workloads.logging_config_mutable` | A principal that can disable Bedrock invocation logging can act without an audit trail. | T1562.008 (Disable Cloud Logs) |
| `ai_workloads.broad_notebook_access` | SageMaker notebook/domain URLs hand out an internet-reachable Jupyter environment running with the execution role's credentials. | T1210-adjacent (exploiting a reachable service) |
| `ai_workloads.broadly_trusted_ai_role` | Composition finding: weak trust boundary + high-blast-radius AI permissions on the same role. | T1078.004 → T1530 chain |

## Assumptions worth knowing about

- Input is assumed to be well-formed AWS policy JSON. Malformed input fails
  loudly (`SCPSyntaxError`, `json.JSONDecodeError`) instead of being
  silently accepted — nothing here ever `eval`s or `exec`s policy content.
- `--live` needs read-only IAM permissions (`iam:ListRoles`,
  `sts:GetCallerIdentity`, and friends). No credentials means it fails with
  the normal boto3 error, not a partial or misleading result.

## Where it falls short

- Findings are per-resource, so a trust-policy finding doesn't know whether
  an SCP elsewhere in the org already neutralizes it. That's a deliberate
  trade — completeness for something easy to reason about and test.
- AI-workload checks only know about the Bedrock/SageMaker actions listed
  in `ai_workloads/checks.py` today. It's a hand-maintained allow-list
  rather than a heuristic, so a new or unfamiliar action fails closed (no
  finding) instead of guessing.
- No batching beyond the boto3 paginator — fine for most accounts, not
  tuned for one with 10k+ roles.
