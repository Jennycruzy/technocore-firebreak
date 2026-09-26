"""Deterministic policy classification; content never grants authority."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .did import is_did, verify_record

URL = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def signed_tuple(case: dict[str, Any]) -> tuple[str, str, int, str, str] | None:
    record = case["record"]
    fields = (record.get("from"), record.get("nonce"), record.get("text"), record.get("sig"))
    if not (isinstance(fields[0], str) and isinstance(fields[1], int)):
        return None
    if not (isinstance(fields[2], str) and isinstance(fields[3], str)):
        return None
    return case["room"], fields[0], fields[1], fields[2], fields[3]


@dataclass
class ReplayState:
    observed: dict[str, tuple[str, str, int, str, str] | None] = field(default_factory=dict)

    def classify(self, case: dict[str, Any], signature: str) -> str:
        if signature != "valid":
            return "not_applicable"
        current = signed_tuple(case)
        prior_ids = case.get("consumer_context", {}).get("prior_observed_case_ids", [])
        if any(self.observed.get(identifier) == current for identifier in prior_ids):
            result = "duplicate_signed_tuple"
        else:
            result = "first_seen"
        self.observed[case["id"]] = current
        return result


def classify(case: dict[str, Any], replay: ReplayState) -> dict[str, Any]:
    record = case["record"]
    sender = record.get("from")
    has_signature = "sig" in record
    if has_signature:
        signature = "valid" if verify_record(case["room"], record) else "invalid"
    elif is_did(sender) and "nonce" in record:
        signature = "not_reverifiable"
    else:
        signature = "absent"

    if signature == "valid":
        identity = "verified_did_key"
    elif signature == "invalid":
        identity = "invalid"
    elif is_did(sender):
        identity = "unverified_did_claim"
    else:
        identity = "unverified_claim"

    context = case["consumer_context"]
    generation = case["generation"]
    current_generation = context["current_generation"]
    freshness = "current_generation" if generation == current_generation else "prior_generation"
    text = record.get("text", "")
    result = {
        "signature": signature,
        "identity_evidence": identity,
        "authority": "none",
        "freshness": freshness,
        "replay": replay.classify(case, signature),
        "url_risk": "potential_side_effect" if isinstance(text, str) and URL.search(text) else "none",
        "automatic_action": False,
    }
    if freshness == "prior_generation" and signature == "valid":
        result["replay"] = "unknown"
    if signature == "not_reverifiable":
        result["replay"] = "unknown"
    return result
