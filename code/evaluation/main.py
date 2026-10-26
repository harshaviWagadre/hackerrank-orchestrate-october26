#!/usr/bin/env python3
"""Validate an audit output and score a generated public-sample run."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from collections import Counter
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
STEP_CONTRACT = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
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
        if (step["phase"], step["state"]) != STEP_CONTRACT[step["operation"]]:
            raise ValueError(
                f"{row.get('case_id', '<unknown>')}: step {number} violates operation/state contract"
            )
        if not all(isinstance(step[key], str) for key in STEP_FIELDS - {"step_no"}):
            raise ValueError(f"{row.get('case_id', '<unknown>')}: step {number} has invalid value types")
    return steps


def validate_output(
    requests: list[dict[str, str]],
    output: list[dict[str, str]],
    allowed_evidence_ids: set[str],
) -> None:
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
        if row["deletion_status"] == "COMPLETE" and any(
            not step["evidence_id"] for step in steps
        ):
            raise ValueError(f"{row['case_id']}: COMPLETE verification must cite evidence")
        if row["deletion_status"] == "INCOMPLETE":
            for step in steps:
                future_step = step["phase"] in {"REMEDIATION", "VERIFICATION"}
                if future_step and step["evidence_id"]:
                    raise ValueError(
                        f"{row['case_id']}: proposed/future step must have empty evidence_id"
                    )
                if step["phase"] == "FINDING" and step["evidence_id"] not in allowed_evidence_ids:
                    raise ValueError(f"{row['case_id']}: finding cites unknown evidence")
        for step in steps:
            if step["evidence_id"] and step["evidence_id"] not in allowed_evidence_ids:
                raise ValueError(f"{row['case_id']}: step cites unknown evidence")
        phase_indexes = [audit.PHASE_ORDER[step["phase"]] for step in steps]
        if phase_indexes != sorted(phase_indexes):
            raise ValueError(f"{row['case_id']}: phases are not ordered")
        ordering_keys = [
            (
                audit.PHASE_ORDER[step["phase"]],
                audit.OPERATION_ORDER[step["operation"]],
                step["system_id"],
                step["resource_id"],
            )
            for step in steps
        ]
        if ordering_keys != sorted(ordering_keys):
            raise ValueError(f"{row['case_id']}: steps violate operation/system/resource order")


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
        unmatched_actual = set(range(len(actual_steps)))
        for expected_step in expected_steps:
            candidates = [
                index
                for index in unmatched_actual
                if actual_steps[index]["system_id"] == expected_step["system_id"]
                and actual_steps[index]["resource_id"] == expected_step["resource_id"]
            ]
            if not candidates:
                continue
            actual_index = min(
                candidates,
                key=lambda index: (
                    actual_steps[index]["operation"] != expected_step["operation"],
                    actual_steps[index]["phase"] != expected_step["phase"],
                    actual_steps[index]["state"] != expected_step["state"],
                    index,
                ),
            )
            unmatched_actual.remove(actual_index)
            actual_step = actual_steps[actual_index]
            matched_fields += sum(
                expected_step[field] == actual_step[field] for field in STEP_FIELDS
            )
            matched_steps += expected_step == actual_step
    return {
        "cases": len(comparable_ids),
        "status_correct": status_correct,
        "sequence_correct": exact_sequences,
        "expected_step_count": expected_step_count,
        "matched_steps": matched_steps,
        "expected_fields": expected_fields,
        "matched_fields": matched_fields,
    }


def render_step(step: dict[str, Any]) -> str:
    return (
        f"{step['phase']} {step['system_id']}/{step['resource_id']} "
        f"{step['operation']}={step['state']} evidence={step['evidence_id']!r}"
    )


def missing_step_source(
    step: dict[str, Any],
    request: dict[str, str],
    evidence: list[audit.Evidence],
    manifest_times: dict[str, str],
    activities: list[dict[str, str]],
    users: dict[str, dict[str, Any]],
    aliases: dict[str, set[str]],
    history: list[dict[str, str]],
) -> str:
    audit_at = audit.parse_time(request["audit_at"])
    candidate_ids = aliases.get(audit.normalized(request.get("email", "")), set())
    user_id = next(iter(candidate_ids)) if len(candidate_ids) == 1 else ""
    identifiers = (
        audit.subject_identifiers(
            user_id,
            request.get("email", ""),
            audit_at,
            users[user_id],
            history,
        )
        if user_id and audit_at
        else set()
    )
    same_resource = [record for record in evidence if record.resource_id == step["resource_id"]]
    in_scope = [
        record
        for record in same_resource
        if audit_at
        and audit.evidence_at_cutoff(record, audit_at, manifest_times)
    ]
    same_system = [record for record in in_scope if record.system_id == step["system_id"]]
    linked = [
        record
        for record in same_system
        if user_id and audit.evidence_matches(record, user_id, identifiers)
    ]
    activity_refs = [
        item
        for item in activities
        if item.get("resource_id") == step["resource_id"]
        and item.get("target_system") == step["system_id"]
        and audit.parse_time(item.get("event_time")) is not None
        and audit_at
        and audit.parse_time(item["event_time"]) <= audit_at
    ]

    if linked:
        return "matching participant evidence exists at audit_at; the planner omitted the required step"
    if same_system:
        refs = ", ".join(
            f"{record.evidence_id} ({record.category}/{record.status})"
            for record in same_system
        )
        return f"resource is parsed at audit_at ({refs}) but not linked to the resolved subject"
    if in_scope:
        refs = ", ".join(
            f"{record.evidence_id} as {record.system_id}" for record in in_scope
        )
        return f"resource is parsed at audit_at under another system ({refs})"
    if same_resource:
        refs = ", ".join(record.evidence_id for record in same_resource)
        return f"resource appears only in evidence excluded by audit_at ({refs})"
    if activity_refs:
        refs = ", ".join(
            f"{item['activity_id']} ({item['event_type']}/{item.get('reported_result', '')})"
            for item in activity_refs
        )
        return f"activity target exists ({refs}), but activity alone does not prove record state or subject linkage"
    return "resource could not be located in parsed participant evidence or eligible activity"


def write_differential(
    expected: list[dict[str, str]],
    actual: list[dict[str, str]],
    path: Path,
    parsed_resource_ids: set[str],
    requests: list[dict[str, str]],
    evidence: list[audit.Evidence],
    manifest_times: dict[str, str],
    activities: list[dict[str, str]],
    users: dict[str, dict[str, Any]],
    aliases: dict[str, set[str]],
    history: list[dict[str, str]],
) -> None:
    expected_by_id = {row["case_id"]: row for row in expected}
    actual_by_id = {row["case_id"]: row for row in actual}
    request_by_id = {row["case_id"]: row for row in requests}
    lines = [
        "# Public Sample Differential",
        "",
        "Expected rows are from the official public `sample_output.csv`; actual rows are",
        "generated by the current audit pipeline. Steps are aligned by system and resource.",
        "The listed root-cause categories are diagnostic signals, not claims that the",
        "underlying participant evidence is sufficient to resolve every mismatch.",
        "",
    ]
    categories: Counter[str] = Counter()
    for case_id in sorted(expected_by_id.keys() | actual_by_id.keys()):
        expected_row = expected_by_id.get(case_id)
        actual_row = actual_by_id.get(case_id)
        if expected_row is None or actual_row is None:
            categories["identity resolution / missing case row"] += 1
            lines.extend(
                [f"## {case_id}", "", "Missing expected or actual case row.", ""]
            )
            continue
        expected_steps = parse_steps(expected_row)
        actual_steps = parse_steps(actual_row)
        if expected_row["deletion_status"] == actual_row["deletion_status"] and expected_steps == actual_steps:
            continue
        lines.extend(
            [
                f"## {case_id}",
                "",
                f"- Status: expected `{expected_row['deletion_status']}`, actual `{actual_row['deletion_status']}`.",
                f"- Step count: expected {len(expected_steps)}, actual {len(actual_steps)}.",
            ]
        )
        root_causes: set[str] = set()
        unmatched_actual = set(range(len(actual_steps)))
        aligned: list[tuple[int, int]] = []
        for expected_index, expected_step in enumerate(expected_steps):
            candidates = [
                index
                for index in unmatched_actual
                if actual_steps[index]["system_id"] == expected_step["system_id"]
                and actual_steps[index]["resource_id"] == expected_step["resource_id"]
            ]
            if candidates:
                actual_index = min(
                    candidates,
                    key=lambda index: (
                        actual_steps[index]["operation"] != expected_step["operation"],
                        actual_steps[index]["phase"] != expected_step["phase"],
                        actual_steps[index]["state"] != expected_step["state"],
                        actual_steps[index]["evidence_id"] != expected_step["evidence_id"],
                        index,
                    ),
                )
                unmatched_actual.remove(actual_index)
                aligned.append((expected_index, actual_index))
                actual_step = actual_steps[actual_index]
                changed = [
                    field
                    for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")
                    if expected_step[field] != actual_step[field]
                ]
                if changed:
                    lines.append(
                        f"- Expected step {expected_index + 1}, actual step {actual_index + 1}: "
                        f"expected `{render_step(expected_step)}`; actual `{render_step(actual_step)}`."
                    )
                    lines.append("  Changed fields: " + ", ".join(changed) + ".")
                if "operation" in changed:
                    root_causes.add("deletion policy / operation selection")
                if "state" in changed:
                    root_causes.add("audit-time reconstruction / evidence interpretation")
                if "evidence_id" in changed:
                    root_causes.add("evidence references / provenance")
                if "phase" in changed:
                    root_causes.add("phase ordering")
            else:
                root_causes.add("missing steps")
                if expected_step["operation"] == "VERIFY_RECORD_PRESENT":
                    root_causes.add("retained records")
                if expected_step["operation"] in {
                    "REPORT_ACTIVE_DATA_FLOW",
                    "DISABLE_DATA_FLOW",
                    "VERIFY_DATA_FLOW_DISABLED",
                }:
                    root_causes.add("active data flows")
                if expected_step["operation"] in {
                    "REPORT_RESTORE_RISK",
                    "BLOCK_RESTORE",
                    "VERIFY_RESTORE_BLOCKED",
                }:
                    root_causes.add("restore risks")
                if expected_step["system_id"] == "account_service":
                    root_causes.add("identity resolution / account evidence linkage")
                else:
                    root_causes.add("evidence extraction/linkage")
                lines.append(
                    f"- Expected step {expected_index + 1}: expected "
                    f"`{render_step(expected_step)}`; actual `<no matching system/resource step>`."
                )
                request = request_by_id.get(case_id)
                if request:
                    lines.append(
                        "  Source trace: "
                        + missing_step_source(
                            expected_step,
                            request,
                            evidence,
                            manifest_times,
                            activities,
                            users,
                            aliases,
                            history,
                        )
                        + "."
                    )
        for actual_index in sorted(unmatched_actual):
            root_causes.add("extra steps")
            lines.append(
                f"- Actual step {actual_index + 1}: unexpected "
                f"`{render_step(actual_steps[actual_index])}`."
            )
        actual_order = [actual_index for _, actual_index in aligned]
        if actual_order != sorted(actual_order):
            root_causes.add("sequence ordering")
            lines.append("- Matched steps appear in a different sequence order.")
        categories.update(root_causes)
        lines.extend(
            ["- Diagnostic categories: " + ", ".join(sorted(root_causes)) + ".", ""]
        )
        lines.append("")
    lines.extend(["## Aggregate Diagnostic Categories", ""])
    for category, count in sorted(categories.items()):
        lines.append(f"- {category}: {count} case-level differences.")
    expected_resource_ids = {
        step["resource_id"]
        for row in expected
        for step in parse_steps(row)
    }
    unextracted_ids = sorted(expected_resource_ids - parsed_resource_ids)
    lines.extend(
        [
            "",
            "## Resource Identifiers Not Extracted from Participant Evidence",
            "",
            "This is a diagnostic inventory only. The identifiers below occur in the",
            "public sample oracle but were not emitted by the current evidence readers;",
            "they were not used to generate predictions.",
            "",
        ]
    )
    if unextracted_ids:
        lines.extend(f"- `{resource_id}`" for resource_id in unextracted_ids)
    else:
        lines.append("- None.")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    parser.add_argument("--differential-report", type=Path, default=None)
    args = parser.parse_args()

    requests = read_rows(args.dataset / "deletion_requests.csv")
    output = read_rows(args.output)
    if not output or list(output[0].keys()) != ["case_id", "deletion_status", "steps_json"]:
        raise ValueError("Output columns do not match the required schema")
    manifest_ids = {
        row["file_id"] for row in read_rows(args.dataset / "evidence_files.csv")
    }
    activity_ids = {
        row["activity_id"] for row in read_rows(args.dataset / "system_activity.csv")
    }
    audit_ids = {
        row["audit_id"] for row in read_rows(args.dataset / "user_audit_log.csv")
    }
    validate_output(requests, output, manifest_ids | activity_ids | audit_ids)
    print(f"Full-output validation: PASS ({len(output)} rows)")

    with tempfile.TemporaryDirectory(prefix="deletion-audit-evaluation-") as temp_dir:
        sample_actual_path = Path(temp_dir) / "sample_output.csv"
        sample_requests = args.dataset / "sample_deletion_requests.csv"
        audit.run(args.dataset, sample_requests, sample_actual_path)
        expected_samples = read_rows(args.dataset / "sample_output.csv")
        actual_samples = read_rows(sample_actual_path)
        metrics = score_samples(expected_samples, actual_samples)
        if args.differential_report:
            parsed_evidence = audit.load_evidence(args.dataset)
            parsed_resource_ids = {record.resource_id for record in parsed_evidence}
            parsed_resource_ids.update(
                resource_id
                for record in parsed_evidence
                for resource_id in audit.account_resource_references(record)
            )
            manifest_times = {
                row["file_id"]: row["captured_at"]
                for row in read_rows(args.dataset / "evidence_files.csv")
            }
            users, aliases = audit.identity_index(args.dataset)
            write_differential(
                expected_samples,
                actual_samples,
                args.differential_report,
                parsed_resource_ids,
                requests=read_rows(sample_requests),
                evidence=parsed_evidence,
                manifest_times=manifest_times,
                activities=read_rows(args.dataset / "system_activity.csv"),
                users=users,
                aliases=aliases,
                history=read_rows(args.dataset / "user_audit_log.csv"),
            )
            print(f"Detailed differential report: {args.differential_report}")
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
