import json
import os

import boto3
import pytest
from moto import mock_aws

from iam_guardrails.trust_policy.analyzer import scan_account


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    """Moto intercepts the HTTP calls, but boto3 still needs *some* credentials
    present to construct a client."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_scan_account_finds_wildcard_role_end_to_end():
    iam = boto3.client("iam", region_name=os.environ["AWS_DEFAULT_REGION"])
    wildcard_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName="wildcard-role",
        AssumeRolePolicyDocument=json.dumps(wildcard_trust),
    )

    findings = scan_account(iam)

    assert any(f.check_id == "trust_policy.wildcard_principal" for f in findings)
