#!/usr/bin/env python3
"""Validate an audit output and score a generated public-sample run."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

import main as audit  # noqa: E402

PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
STEP_FIELDS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def parse_steps(row: dict[str, str]) -> list[dict[str, Any]]:
    try:
        steps = json.loads(row["steps_json"])
    except (KeyError, json.JSONDecodeError) as error:
        raise ValueError(f"{row.get('case_id', '<unknown>')}: invalid steps_json") from error
    if not isinstance(steps, list):
        raise ValueError(f"{row.get('case_id', '<unknown>')}: steps_json must be an array")
    for number, step in enumerate(steps, start=1):
        if not isinstance(step, dict) or set(step) != STEP_FIELDS:
            raise ValueError(f"{row.get('case_id', '<unknown>')}: step {number} has invalid fields")
        if step["step_no"] != number or step["phase"] not in PHASES:
            raise ValueError(f"{row.get('case_id', '<unknown>')}: step {number} has invalid order")
        if step["operation"] not in audit.OPERATION_ORDER:
            raise ValueError(f"{row.get('case_id', '<unknown>')}: step {number} has invalid operation")
        if not all(isinstance(step[key], str) for key in STEP_FIELDS - {"step_no"}):
            raise ValueError(f"{row.get('case_id', '<unknown>')}: step {number} has invalid value types")
    return steps


def validate_output(requests: list[dict[str, str]], output: list[dict[str, str]]) -> None:
    expected_ids = sorted(row["case_id"] for row in requests)
    output_ids = [row["case_id"] for row in output]
    if output_ids != expected_ids:
        raise ValueError("Output case IDs must exactly match requests in sorted order")
    for row in output:
        if row.get("deletion_status") not in STATUSES:
            raise ValueError(f"{row.get('case_id')}: invalid deletion_status")
        steps = parse_steps(row)
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise ValueError(f"{row['case_id']}: NOT_APPLICABLE must have no steps")
        if row["deletion_status"] == "COMPLETE" and any(
            step["phase"] != "VERIFICATION" for step in steps
        ):
            raise ValueError(f"{row['case_id']}: COMPLETE may contain only verification steps")
        phase_indexes = [audit.PHASE_ORDER[step["phase"]] for step in steps]
        if phase_indexes != sorted(phase_indexes):
            raise ValueError(f"{row['case_id']}: phases are not ordered")


def score_samples(
    expected: list[dict[str, str]], actual: list[dict[str, str]]
) -> dict[str, int]:
    expected_by_id = {row["case_id"]: row for row in expected}
    actual_by_id = {row["case_id"]: row for row in actual}
    comparable_ids = sorted(expected_by_id.keys() & actual_by_id.keys())
    status_correct = sum(
        expected_by_id[case_id]["deletion_status"]
        == actual_by_id[case_id]["deletion_status"]
        for case_id in comparable_ids
    )
    exact_sequences = 0
    expected_step_count = 0
    matched_steps = 0
    matched_fields = 0
    expected_fields = 0
    for case_id in comparable_ids:
        expected_steps = parse_steps(expected_by_id[case_id])
        actual_steps = parse_steps(actual_by_id[case_id])
        exact_sequences += expected_steps == actual_steps
        expected_step_count += len(expected_steps)
        expected_fields += len(expected_steps) * len(STEP_FIELDS)
        for expected_step, actual_step in zip(expected_steps, actual_steps):
            matched_steps += expected_step == actual_step
            matched_fields += sum(
                expected_step[field] == actual_step[field] for field in STEP_FIELDS
            )
    return {
        "cases": len(comparable_ids),
        "status_correct": status_correct,
        "sequence_correct": exact_sequences,
        "expected_step_count": expected_step_count,
        "matched_steps": matched_steps,
        "expected_fields": expected_fields,
        "matched_fields": matched_fields,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    args = parser.parse_args()

    requests = read_rows(args.dataset / "deletion_requests.csv")
    output = read_rows(args.output)
    if not output or list(output[0].keys()) != ["case_id", "deletion_status", "steps_json"]:
        raise ValueError("Output columns do not match the required schema")
    validate_output(requests, output)
    print(f"Full-output validation: PASS ({len(output)} rows)")

    with tempfile.TemporaryDirectory(prefix="deletion-audit-evaluation-") as temp_dir:
        sample_actual_path = Path(temp_dir) / "sample_output.csv"
        sample_requests = args.dataset / "sample_deletion_requests.csv"
        audit.run(args.dataset, sample_requests, sample_actual_path)
        metrics = score_samples(
            read_rows(args.dataset / "sample_output.csv"),
            read_rows(sample_actual_path),
        )
    count = metrics["cases"]
    print(f"Public sample cases: {count}")
    print(
        f"Status accuracy: {metrics['status_correct']}/{count} "
        f"({metrics['status_correct'] / count:.1%})"
    )
    print(
        f"Exact sequence accuracy: {metrics['sequence_correct']}/{count} "
        f"({metrics['sequence_correct'] / count:.1%})"
    )
    print(
        f"Exact-step accuracy: {metrics['matched_steps']}/{metrics['expected_step_count']} "
        f"({metrics['matched_steps'] / metrics['expected_step_count']:.1%})"
    )
    print(
        f"Field accuracy: {metrics['matched_fields']}/{metrics['expected_fields']} "
        f"({metrics['matched_fields'] / metrics['expected_fields']:.1%})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())