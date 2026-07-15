"""JSON Schema for AWS Service Control Policy documents.

Reference:
https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html
"""

from __future__ import annotations

from typing import Any

SCP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "Version": {"type": "string", "enum": ["2012-10-17"]},
        "Statement": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "Sid": {"type": "string"},
                    "Effect": {"type": "string", "enum": ["Deny", "Allow"]},
                    "Action": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        ]
                    },
                    "Resource": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        ]
                    },
                    "Condition": {"type": "object"},
                },
                "required": ["Effect", "Action", "Resource"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["Version", "Statement"],
    "additionalProperties": False,
}
