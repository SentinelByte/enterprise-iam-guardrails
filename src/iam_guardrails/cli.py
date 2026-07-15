"""Command-line entry point: `iam-guardrails <command> ...`

Every command prints a human-readable report and exits non-zero if any
HIGH or CRITICAL finding was produced, so this doubles as a CI gate:

    iam-guardrails validate-scp policy.json || fail-the-build
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from iam_guardrails.ai_workloads.checks import (
    check_ai_service_permissions,
    combine_trust_and_permissions,
)
from iam_guardrails.findings import Finding, Severity
from iam_guardrails.scp.validator import SCPSyntaxError, validate_scp
from iam_guardrails.trust_policy.analyzer import analyze_trust_policy, scan_account

_GATE_SEVERITY = Severity.HIGH


def _load_json(path: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    return data


def _report(findings: list[Finding], as_json: bool) -> int:
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif not findings:
        print("No findings.")
    else:
        for f in sorted(findings, key=lambda f: -f.severity.rank):
            print(f"[{f.severity.value}] {f.check_id} ({f.resource})")
            print(f"    {f.message}")
            print(f"    remediation: {f.remediation}")

    return 1 if any(f.severity.rank >= _GATE_SEVERITY.rank for f in findings) else 0


def _cmd_validate_scp(args: argparse.Namespace) -> int:
    policy = _load_json(args.file)
    try:
        findings = validate_scp(policy, policy_name=Path(args.file).stem)
    except SCPSyntaxError as e:
        print(f"Structural validation failed ({len(e.errors)} issue(s)):")
        for msg in e.errors:
            print(f"  - {msg}")
        return 1
    return _report(findings, args.json)


def _cmd_scan_trust_policy(args: argparse.Namespace) -> int:
    if args.live:
        findings = scan_account()
    else:
        if not args.file:
            print("error: FILE is required unless --live is given", file=sys.stderr)
            return 2
        policy = _load_json(args.file)
        role_name = args.role_name or Path(args.file).stem
        findings = analyze_trust_policy(policy, role_name, args.account_id)
    return _report(findings, args.json)


def _cmd_scan_ai_workloads(args: argparse.Namespace) -> int:
    trust_policy = _load_json(args.trust_policy)
    permission_policy = _load_json(args.permission_policy)
    role_name = args.role_name or Path(args.trust_policy).stem

    trust_findings = analyze_trust_policy(trust_policy, role_name, args.account_id)
    permission_findings = check_ai_service_permissions(permission_policy, role_name)
    combined = combine_trust_and_permissions(trust_findings, permission_findings, role_name)

    return _report(trust_findings + permission_findings + combined, args.json)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iam-guardrails")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scp = sub.add_parser("validate-scp", help="Validate an SCP JSON document.")
    p_scp.add_argument("file", help="Path to the SCP JSON file.")
    p_scp.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    p_scp.set_defaults(func=_cmd_validate_scp)

    p_trust = sub.add_parser("scan-trust-policy", help="Analyze IAM role trust policies.")
    p_trust.add_argument("file", nargs="?", help="Path to a trust policy JSON file.")
    p_trust.add_argument("--role-name", help="Role name for reporting (offline mode).")
    p_trust.add_argument("--account-id", help="Caller account ID, to detect external trust.")
    p_trust.add_argument(
        "--live", action="store_true", help="Scan every role in the current AWS account."
    )
    p_trust.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    p_trust.set_defaults(func=_cmd_scan_trust_policy)

    p_ai = sub.add_parser(
        "scan-ai-workloads",
        help="Combine trust + permission findings for an AI execution role.",
    )
    p_ai.add_argument("trust_policy", help="Path to the role's trust policy JSON file.")
    p_ai.add_argument("permission_policy", help="Path to the role's permission policy JSON file.")
    p_ai.add_argument("--role-name", help="Role name for reporting.")
    p_ai.add_argument("--account-id", help="Caller account ID, to detect external trust.")
    p_ai.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    p_ai.set_defaults(func=_cmd_scan_ai_workloads)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    exit_code: int = args.func(args)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
