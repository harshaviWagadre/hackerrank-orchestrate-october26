#!/usr/bin/env python3
"""Build deterministic, evidence-cited deletion audits from the participant dataset."""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import json
import re
import shutil
import shlex
import sqlite3
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "dataset"
DEFAULT_OUTPUT = ROOT / "output.csv"

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

DIRECT_IDENTIFIER_KEYS = {
    "name",
    "full_name",
    "customer_name",
    "display_name",
    "email",
    "email_address",
    "phone",
    "phone_number",
    "email_hash",
    "hashed_email",
    "owner_email",
    "requester_email",
    "lookup_key",
    "match_key",
    "subject_key",
}
EMPTY_IDENTIFIER_VALUES = {
    "",
    "null",
    "none",
    "redacted",
    "[redacted]",
    "anonymized",
    "[anonymized]",
    "deleted",
}


@dataclass(frozen=True)
class Evidence:
    system_id: str
    resource_id: str
    category: str
    status: str
    evidence_id: str
    observed_at: str
    fields: dict[str, Any]
    text: str


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    text = re.sub(
        r"^(\d{4})[:\-]\s*(\d{2})[-:]\s*(\d{2})(?=T)",
        r"\1-\2-\3",
        text,
    )
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def iso_time(value: dt.datetime | None) -> str:
    if value is None:
        return ""
    return value.isoformat()


def normalized(value: Any) -> str:
    return " ".join(str(value).casefold().strip().split())


def digits(value: Any) -> str:
    return re.sub(r"\D", "", str(value))


def flatten_values(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).casefold(), child
            yield from flatten_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from flatten_values(child)


def canonical_category(system: str, hint: str, fields: dict[str, Any]) -> str:
    explicit = str(fields.get("data_category") or fields.get("record_type") or "").upper()
    candidates = " ".join((explicit, hint, system, str(fields.get("resource_id") or ""))).upper()
    if "TOMBSTONE" in candidates:
        return "ACCOUNT_TOMBSTONE"
    if "SECURITY_AUDIT" in candidates or "AUDIT_RECORD" in candidates:
        return "SECURITY_AUDIT_LOG"
    if "LEGAL_HOLD" in candidates:
        return "LEGAL_HOLD_RECORD"
    if "BACKUP" in candidates or "RESTORE" in candidates:
        return "BACKUP_ARCHIVE"
    if "DATA_FLOW" in candidates or "CONNECTOR" in candidates or "INTEGRATION" in candidates:
        return "DATA_FLOW"
    if "EXPORT" in candidates:
        return "USER_EXPORT"
    if "MARKETING" in candidates:
        return "MARKETING_PROFILE"
    if "EMAIL_DELIVERY" in candidates or "NOTIFICATION" in candidates:
        return "EMAIL_DELIVERY_LOG"
    if "SUPPORT_ATTACHMENT" in candidates or "ATTACHMENT" in candidates:
        return "SUPPORT_ATTACHMENT"
    if "SUPPORT_MESSAGE" in candidates or "SUPPORT" in candidates:
        return "SUPPORT_MESSAGE"
    if "ANALYTICS" in candidates:
        return "ANALYTICS_PROFILE"
    if "TELEMETRY" in candidates:
        return "PRODUCT_TELEMETRY"
    if "SEARCH" in candidates or "INDEX" in candidates:
        return "SEARCH_INDEX_ENTRY"
    if "CACHE" in candidates:
        return "CACHE_ENTRY"
    if "ACCOUNT" in candidates or "PROFILE" in candidates or "IDENTITY" in candidates:
        return "USER_PROFILE"
    return ""


def normalize_system(system: str, category: str) -> str:
    value = system.casefold()
    aliases = {
        "account_service": "account_service",
        "account_replication_cluster": "account_service",
        "account_failover_replica": "account_service",
        "search_service": "search_service",
        "analytics_platform": "analytics_platform",
        "support_platform": "support_platform",
        "support_replica": "support_platform",
        "export_service": "export_service",
        "integration_service": "integration_service",
        "backup_service": "backup_service",
        "security_service": "security_service",
        "identity_service": "identity_service",
        "marketing_platform": "marketing_platform",
        "cache_service": "cache_service",
        "email_delivery_service": "email_delivery_service",
        "notification_service": "email_delivery_service",
        "object_storage": "object_store",
        "object_store": "object_store",
    }
    if value in aliases:
        return aliases[value]
    category_systems = {
        "USER_PROFILE": "account_service",
        "SECONDARY_IDENTIFIER": "identity_service",
        "SEARCH_INDEX_ENTRY": "search_service",
        "CACHE_ENTRY": "cache_service",
        "SUPPORT_MESSAGE": "support_platform",
        "SUPPORT_ATTACHMENT": "support_platform",
        "ANALYTICS_PROFILE": "analytics_platform",
        "PRODUCT_TELEMETRY": "analytics_platform",
        "USER_EXPORT": "export_service",
        "MARKETING_PROFILE": "marketing_platform",
        "EMAIL_DELIVERY_LOG": "email_delivery_service",
        "SECURITY_AUDIT_LOG": "security_service",
        "LEGAL_HOLD_RECORD": "legal_service",
        "BACKUP_ARCHIVE": "backup_service",
        "ACCOUNT_TOMBSTONE": "identity_service",
        "DATA_FLOW": "integration_service",
    }
    return category_systems.get(category, value)


def status_from_fields(fields: dict[str, Any], category: str, text: str) -> str:
    values = {key.casefold(): value for key, value in flatten_values(fields)}
    for key in ("status", "result", "state", "record_state", "deletion_state"):
        value = values.get(key)
        if isinstance(value, str):
            status = value.strip().upper().replace(" ", "_")
            if status in {"NOT_FOUND", "NOTFOUND", "ABSENT", "DELETED", "MISSING"}:
                return "ABSENT"
            if status in {"FOUND", "PRESENT", "IDENTIFIABLE", "EXPOSED", "ACTIVE", "ENABLED"}:
                return "ACTIVE" if status in {"ACTIVE", "ENABLED"} and category == "DATA_FLOW" else "PRESENT"
            if status in {"ANONYMIZED", "ANONYMISED"}:
                return "ANONYMIZED"
            if status in {"REDACTED", "MASKED"}:
                return "REDACTED"
            if status in {"DISABLED", "INACTIVE", "STOPPED"}:
                return "DISABLED"
            if status in {"BLOCKED", "RESTORE_BLOCKED"}:
                return "BLOCKED"
    status_code = values.get("status_code") or values.get("http_status")
    if str(status_code) == "404":
        return "ABSENT"
    if str(status_code) in {"200", "201"}:
        return "PRESENT"
    result = str(values.get("result") or "").casefold()
    event = str(values.get("event") or "").casefold()
    if "profile_lookup_completed" in event:
        rows = str(values.get("rows") or "")
        if rows == "0":
            return "ABSENT"
        if rows.isdigit() and int(rows) > 0:
            return "PRESENT"
    if event in {"index_query_completed", "search_query_completed"} and result == "hit":
        return "PRESENT"
    if "restore_allowed" in values:
        return "ACTIVE" if str(values["restore_allowed"]).casefold() in {"1", "true", "yes"} else "BLOCKED"
    if "eligible" in values and str(values["eligible"]).casefold() in {"1", "true", "yes"}:
        return "ACTIVE" if str(values.get("deletion_block", "")).casefold() in {"0", "false", "no"} else "BLOCKED"
    if "enabled" in values or "scheduler_registered" in values:
        active = any(
            str(values.get(key, "")).casefold() in {"1", "true", "yes", "active", "enabled"}
            for key in ("enabled", "scheduler_registered", "active")
        )
        return "ACTIVE" if active else "DISABLED"

    direct = has_direct_identifiers(fields)
    if category == "ANALYTICS_PROFILE" and not direct:
        return "ANONYMIZED"
    if category == "ACCOUNT_TOMBSTONE":
        return "PRESENT" if direct else "REDACTED"
    if category in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "EMAIL_DELIVERY_LOG"} and not direct:
        return "REDACTED"
    if category == "ACCOUNT_TOMBSTONE":
        return "PRESENT" if direct else "REDACTED"
    if direct or any(
        key in values
        and values[key] is not None
        and normalized(values[key]) not in EMPTY_IDENTIFIER_VALUES
        for key in ("subject_reference", "user_id", "customer_reference")
    ):
        return "PRESENT"
    if re.search(r"\b(?:active|enabled|running)\b", text, re.I) and category == "DATA_FLOW":
        return "ACTIVE"
    return "UNKNOWN"


def has_direct_identifiers(fields: dict[str, Any]) -> bool:
    for key, value in flatten_values(fields):
        if key not in DIRECT_IDENTIFIER_KEYS or value is None:
            continue
        if isinstance(value, (dict, list)):
            continue
        if normalized(value) not in EMPTY_IDENTIFIER_VALUES:
            return True
    return False


def infer_system(fields: dict[str, Any], inherited: str = "") -> str:
    for key in ("origin_system", "data_store", "system", "source_system", "service"):
        value = fields.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().casefold()
    return inherited.casefold()


def infer_record_time(fields: dict[str, Any], inherited: str) -> str:
    for key in ("observed_at", "captured_at", "recorded_at", "event_time", "timestamp"):
        value = fields.get(key)
        if isinstance(value, str) and parse_time(value):
            return value
    return inherited


def build_evidence(
    fields: dict[str, Any],
    evidence_id: str,
    inherited_system: str,
    hint: str,
    observed_at: str,
    text: str = "",
) -> Evidence | None:
    resource_id = str(fields.get("resource_id") or fields.get("id") or "").strip()
    if not resource_id:
        return None
    system_hint = infer_system(fields, inherited_system)
    category = canonical_category(system_hint, hint, fields)
    if not category:
        return None
    system = normalize_system(system_hint, category)
    combined_text = text or json.dumps(fields, ensure_ascii=False, sort_keys=True, default=str)
    status = status_from_fields(fields, category, combined_text)
    timestamp = infer_record_time(fields, observed_at)
    return Evidence(system, resource_id, category, status, evidence_id, timestamp, fields, combined_text)


def decode_pdf_text(path: Path) -> str:
    data = path.read_bytes()
    pieces: list[str] = []
    stream_pattern = re.compile(rb"(<<.*?>>)\s*stream\r?\n", re.S)
    for match in stream_pattern.finditer(data):
        start = match.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        stream = data[start:end].rstrip(b"\r\n")
        filters = match.group(1)
        try:
            if b"ASCII85Decode" in filters:
                stream = base64.a85decode(stream, adobe=True)
            if b"FlateDecode" in filters:
                stream = zlib.decompress(stream)
        except (ValueError, zlib.error):
            continue
        if b"BT" not in stream:
            continue
        for token in re.finditer(rb"\(((?:\\.|[^\\)])*)\)\s*(?:Tj|TJ|')", stream):
            raw = token.group(1)
            raw = re.sub(
                rb"\\([0-7]{1,3})",
                lambda octal: bytes([int(octal.group(1), 8)]),
                raw,
            )
            raw = raw.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
            pieces.append(raw.decode("latin-1", "replace"))
        for token in re.finditer(rb"\(((?:\\.|[^\\)])*)\)", stream):
            raw = token.group(1)
            raw = raw.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
            text = raw.decode("latin-1", "replace")
            if text and text not in pieces:
                pieces.append(text)
    return "\n".join(pieces)


def read_sql_records(path: Path, evidence_id: str, captured_at: str) -> list[Evidence]:
    source = path.read_text(encoding="utf-8")
    connection = sqlite3.connect(":memory:")
    allowed = {
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_RECURSIVE,
    }

    def authorize(action: int, _arg1: str | None, _arg2: str | None, _db: str | None, _trigger: str | None) -> int:
        if action == sqlite3.SQLITE_UPDATE and _arg1 == "sqlite_master":
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and _arg1 == "foreign_keys" and _arg2 == "ON":
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_REINDEX and _arg1 and _arg1.startswith("idx_"):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY

    connection.set_authorizer(authorize)
    try:
        connection.executescript(source)
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        output: list[Evidence] = []
        account_resource_ids: set[str] = set()
        has_account_snapshot = False
        for (table_name,) in tables:
            quoted = '"' + str(table_name).replace('"', '""') + '"'
            cursor = connection.execute(f"SELECT * FROM {quoted}")
            columns = [column[0] for column in cursor.description or ()]
            if "customer_profiles" in str(table_name).casefold() or "account_profiles" in str(table_name).casefold():
                has_account_snapshot = True
            for row in cursor.fetchall():
                fields = dict(zip(columns, row))
                raw_json = fields.get("record_json")
                if isinstance(raw_json, str):
                    decoded = json.loads(raw_json)
                    if isinstance(decoded, dict):
                        fields = {**fields, **decoded}
                is_account_table = (
                    "customer_profiles" in str(table_name).casefold()
                    or "account_profiles" in str(table_name).casefold()
                )
                if is_account_table:
                    resource_id = str(fields.get("resource_id") or "")
                    if resource_id.startswith("account_"):
                        account_resource_ids.add(resource_id)
                system = infer_system(fields) or system_for_table(str(table_name))
                hint = " ".join((str(table_name), str(fields.get("collection_name") or "")))
                evidence = build_evidence(fields, evidence_id, system, hint, captured_at)
                if evidence:
                    output.append(evidence)
        if has_account_snapshot:
            output.append(
                Evidence(
                    "account_service",
                    "__account_snapshot__",
                    "ACCOUNT_SNAPSHOT",
                    "PRESENT",
                    evidence_id,
                    captured_at,
                    {"resource_ids": sorted(account_resource_ids)},
                    "",
                )
            )
        return output
    finally:
        connection.close()


def parse_log_file(path: Path, evidence_id: str, captured_at: str) -> list[Evidence]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^\s*(\S+)\s+(\{.*\})\s*$", line)
        if match:
            try:
                fields = json.loads(match.group(2))
            except json.JSONDecodeError:
                continue
            fields.setdefault("timestamp", match.group(1))
        else:
            if not re.match(r"^\s*\d{4}-\d{2}-\d{2}T", line):
                continue
            pieces = shlex.split(line)
            fields = {}
            for piece in pieces[1:]:
                if "=" in piece:
                    key, value = piece.split("=", 1)
                    fields[key] = value
            if not fields:
                continue
            fields.setdefault("timestamp", pieces[0])
        if not isinstance(fields, dict):
            continue
        events.append(fields)

    trace_fields: dict[str, dict[str, Any]] = {}
    trace_keys = {
        "lookup_key",
        "match_key",
        "subject_key",
        "subject_ref",
        "correlation_key",
        "email",
        "email_address",
        "phone",
        "user_id",
    }
    for fields in events:
        trace_id = fields.get("trace_id")
        if trace_id:
            merged = trace_fields.setdefault(str(trace_id), {})
            for key in trace_keys:
                if fields.get(key) not in (None, ""):
                    merged[key] = fields[key]

    output: list[Evidence] = []
    for fields in events:
        trace_id = fields.get("trace_id")
        if trace_id and fields.get("resource_id"):
            merged = dict(trace_fields.get(str(trace_id), {}))
            merged.update(fields)
            fields = merged
        system = infer_system(fields)
        evidence = build_evidence(fields, evidence_id, system, str(fields.get("event") or ""), captured_at)
        if evidence:
            output.append(evidence)
    return output


def parse_text_file(path: Path, evidence_id: str, captured_at: str) -> list[Evidence]:
    output: list[Evidence] = []
    row_pattern = re.compile(
        r"^\s*-\s*(?P<time>\S+)\s*\|\s*(?P<system>[^|]+)\s*\|\s*"
        r"(?P<resource>[^|]+)\s*\|\s*(?P<category>[^|]+)\s*\|\s*"
        r"(?P<status>[^|]+)\s*\|\s*(?P<subject>.*?)\s*$",
        re.I,
    )
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = row_pattern.match(line)
        if not match:
            continue
        fields = {
            "resource_id": match.group("resource").strip(),
            "system": match.group("system").strip(),
            "record_type": match.group("category").strip(),
            "status": match.group("status").strip(),
            "subject_reference": match.group("subject").strip(),
            "observed_at": match.group("time").strip(),
        }
        evidence = build_evidence(
            fields, evidence_id, fields["system"], fields["record_type"], captured_at, line
        )
        if evidence:
            output.append(evidence)
    return output


def optional_image_text(path: Path) -> str:
    executable = shutil.which("tesseract")
    if not executable:
        return ""
    result = subprocess.run(
        [executable, str(path), "stdout"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"OCR failed for {path}: {result.stderr.strip()}")
    return result.stdout


def document_evidence(
    text: str, path: Path, evidence_id: str, captured_at: str
) -> list[Evidence]:
    if not text.strip():
        return []
    category_hint = path.stem.replace("_", " ")
    matches = re.findall(r"\b(?:account|search|analytics|support|export|backup|data_flow|tombstone|audit_record)_\d+\b", text, re.I)
    if not matches:
        return []
    output: list[Evidence] = []
    unique_ids = list(dict.fromkeys(matches))
    for resource_id in unique_ids:
        fields = {"resource_id": resource_id, "document_text": text}
        emails = re.findall(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text)
        if emails:
            fields["email"] = emails[0]
        category = canonical_category("", category_hint, fields)
        system = {
            "ACCOUNT_TOMBSTONE": "identity_service",
            "SECURITY_AUDIT_LOG": "security_service",
            "BACKUP_ARCHIVE": "backup_service",
            "DATA_FLOW": "integration_service",
            "USER_EXPORT": "export_service",
            "ANALYTICS_PROFILE": "analytics_platform",
            "SEARCH_INDEX_ENTRY": "search_service",
            "SUPPORT_ATTACHMENT": "support_platform",
            "SUPPORT_MESSAGE": "support_platform",
            "USER_PROFILE": "account_service",
        }.get(category, "")
        if not system or not category:
            continue
        if category == "SUPPORT_ATTACHMENT":
            fields["record_type"] = "SUPPORT_ATTACHMENT"
        evidence = build_evidence(fields, evidence_id, system, category_hint, captured_at, text)
        if evidence:
            output.append(evidence)
    return output


def load_evidence(dataset: Path) -> list[Evidence]:
    manifest = read_csv(dataset / "evidence_files.csv")
    output: list[Evidence] = []
    for item in manifest:
        path = (dataset / item["file_path"]).resolve()
        captured_at = item["captured_at"]
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file listed in manifest is missing: {path}")
        suffix = path.suffix.casefold()
        if suffix == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("snapshots"), list):
                for snapshot in payload["snapshots"]:
                    if not isinstance(snapshot, dict):
                        continue
                    system = str(snapshot.get("data_store") or snapshot.get("system") or "")
                    category = str(snapshot.get("collection") or "")
                    observed = str(snapshot.get("captured_at") or captured_at)
                    for record in snapshot.get("records", []):
                        if isinstance(record, dict):
                            evidence = build_evidence(record, item["file_id"], system, category, observed)
                            if evidence:
                                output.append(evidence)
            elif isinstance(payload, dict) and isinstance(payload.get("service_exports"), dict):
                for system, groups in payload["service_exports"].items():
                    if not isinstance(groups, dict):
                        continue
                    for group_name, records in groups.items():
                        if not isinstance(records, list):
                            continue
                        for record in records:
                            if isinstance(record, dict):
                                evidence = build_evidence(
                                    record,
                                    item["file_id"],
                                    str(system),
                                    str(group_name),
                                    captured_at,
                                )
                                if evidence:
                                    output.append(evidence)
            else:
                records = payload.get("records", []) if isinstance(payload, dict) else []
                for record in records:
                    if isinstance(record, dict):
                        evidence = build_evidence(
                            record,
                            item["file_id"],
                            infer_system(record),
                            str(record.get("record_type") or record.get("data_category") or ""),
                            captured_at,
                        )
                        if evidence:
                            output.append(evidence)
        elif suffix == ".sql":
            output.extend(read_sql_records(path, item["file_id"], captured_at))
        elif suffix == ".log":
            output.extend(parse_log_file(path, item["file_id"], captured_at))
        elif suffix == ".txt":
            output.extend(parse_text_file(path, item["file_id"], captured_at))
        elif suffix == ".pdf":
            output.extend(
                document_evidence(decode_pdf_text(path), path, item["file_id"], captured_at)
            )
        elif suffix == ".png":
            output.extend(
                document_evidence(optional_image_text(path), path, item["file_id"], captured_at)
            )
    return output


def identity_index(dataset: Path) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
    current = read_csv(dataset / "user_identities.csv")
    history = read_csv(dataset / "user_audit_log.csv")
    users = {row["user_id"]: row for row in current}
    aliases: dict[str, set[str]] = {}
    for row in current:
        if row.get("email"):
            aliases.setdefault(normalized(row["email"]), set()).add(row["user_id"])
    for row in history:
        if row.get("field_name", "").casefold() == "email":
            for value in (row.get("old_value", ""), row.get("new_value", "")):
                if value:
                    aliases.setdefault(normalized(value), set()).add(row["user_id"])
    return users, aliases


def load_policy(dataset: Path) -> dict[str, str]:
    policy: dict[str, str] = {}
    for row in read_csv(dataset / "deletion_rules.csv"):
        category = row["data_category"].strip().upper()
        action = row["required_action"].strip().upper()
        if category in policy and policy[category] != action:
            raise ValueError(f"Conflicting deletion rules for {category}")
        policy[category] = action
    if not policy:
        raise ValueError("No deletion rules found")
    return policy


def system_for_table(table_name: str) -> str:
    table = table_name.casefold()
    mappings = (
        (("customer_profiles", "account_profiles"), "account_service"),
        (("customer_search", "search_documents"), "search_service"),
        (("customer_analytics", "analytics_profiles", "analytics_reports"), "analytics_platform"),
        (("support_records", "support_messages", "support_attachments"), "support_platform"),
        (("customer_exports", "export_jobs"), "export_service"),
        (("connector", "data_flows"), "integration_service"),
        (("backup", "restore"), "backup_service"),
        (("security_audit", "security_records"), "security_service"),
        (("tombstone", "deleted_customer_reference"), "identity_service"),
        (("email_delivery",), "email_delivery_service"),
        (("marketing",), "marketing_platform"),
        (("cache",), "cache_service"),
    )
    for needles, system in mappings:
        if any(needle in table for needle in needles):
            return system
    return ""


def subject_identifiers(
    user_id: str,
    request_email: str,
    audit_at: dt.datetime,
    user: dict[str, Any],
    history: list[dict[str, str]],
) -> set[str]:
    values = {request_email.strip()}
    updated_at = parse_time(user.get("updated_at"))
    if updated_at and updated_at <= audit_at:
        values.update((user.get("email", ""), user.get("phone", ""), user.get("email_hash", ""), user.get("name", "")))
    for row in history:
        if row.get("user_id") != user_id:
            continue
        event_time = parse_time(row.get("event_time"))
        if event_time is None or event_time > audit_at:
            continue
        if row.get("field_name", "").casefold() in {
            "email",
            "email_hash",
            "phone",
            "name",
            "full_name",
        }:
            values.update((row.get("old_value", ""), row.get("new_value", "")))
    return {str(value).strip() for value in values if value and str(value).strip()}


def evidence_matches(record: Evidence, user_id: str, identifiers: set[str]) -> bool:
    values = list(flatten_values(record.fields))
    folded_values = {normalized(value) for _, value in values if value is not None}
    id_fields = {
        normalized(value)
        for key, value in values
        if key in {
            "user_id",
            "customer_reference",
            "subject_reference",
            "subject_ref",
            "user_reference",
            "customer_id",
            "correlation_key",
        }
        and value is not None
    }
    if normalized(user_id) in id_fields:
        return True
    for identifier in identifiers:
        needle = normalized(identifier)
        if not needle:
            continue
        if needle in folded_values:
            return True
        if "@" in needle or re.fullmatch(r"[0-9a-f]{40,}", needle):
            if re.search(rf"(?<![\w.+-]){re.escape(needle)}(?![\w.+-])", normalized(record.text)):
                return True
        elif not re.fullmatch(r"user_\d+", needle):
            if re.search(rf"(?<!\w){re.escape(needle)}(?!\w)", normalized(record.text)):
                return True
        number = digits(identifier)
        if len(number) >= 7 and any(number == digits(value) for _, value in values if value is not None):
            return True
    return False


def evidence_at_cutoff(record: Evidence, audit_at: dt.datetime, manifest: dict[str, str]) -> bool:
    capture = parse_time(manifest.get(record.evidence_id))
    observation = parse_time(record.observed_at)
    return bool(capture and capture <= audit_at and (observation is None or observation <= audit_at))


def deduplicate_latest(records: list[Evidence]) -> list[Evidence]:
    latest: dict[tuple[str, str, str], Evidence] = {}
    for record in records:
        key = (record.system_id, record.resource_id, record.category)
        previous = latest.get(key)
        if previous is None or (parse_time(record.observed_at) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) >= (
            parse_time(previous.observed_at) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)
        ):
            latest[key] = record
    return list(latest.values())


def request_authorizes_deletion(text: str) -> bool:
    value = normalized(text)
    if re.search(r"\b(?:do not|don't|dont|not|never)\s+(?:delete|erase|remove|close)\b", value):
        return False
    non_delete = re.search(
        r"\b(?:access|export|download|correct|correction|rectif\w*|update|opt\s*out|unsubscribe|"
        r"stop\s+(?:sending|marketing)|marketing\s+(?:emails|messages)|"
        r"acceso|exportar|descargar|corregir|actualizar|baja\s+de\s+marketing|"
        r"accès|exporter|télécharger|corriger|rectifier|désabonner|"
        r"zugriff|exportieren|berichtigen|abmelden|accedere|esportare|"
        r"acessar|corrigir|cancelar\s+inscrição)\b",
        value,
    )
    delete = re.search(
        r"\b(?:delet\w*|eras\w*|remov\w*|clos(?:e|ing|ure)\s+(?:(?:my|the|this)\s+)?account|"
        r"delete\s+my\s+account|forget\s+me|right\s+to\s+be\s+forgotten|"
        r"elimin\w*|borr\w*|suprim\w*|suppression|effac\w*|lösch\w*|cancell\w*|"
        r"apagar|excluir|削除|消去)\b",
        value,
    )
    if not delete and re.search(
        r"\b(?:verify|confirm|check|audit)\b.{0,80}\b(?:account|profile|data)\b.{0,45}\b(?:deleted|removed|gone|erased)\b",
        value,
    ):
        delete = True
    if not delete and any(token in value for token in ("削除", "消去", "抹消")):
        delete = True
    if non_delete and not delete:
        return False
    return bool(delete)


def evidence_state(record: Evidence) -> str:
    if record.category == "ACCOUNT_SNAPSHOT":
        return "UNKNOWN"
    event = str(record.fields.get("event") or "").casefold()
    if event == "message_pii_scan" or record.fields.get("matched_value"):
        return "PRESENT"
    if event == "contact_query_completed" and str(record.fields.get("rows")) in {"1", "2", "3"}:
        return "PRESENT"
    if event == "deletion_marker_check" and str(record.fields.get("marker_found", "")).casefold() == "false":
        return "PRESENT"
    if record.status != "UNKNOWN":
        return record.status
    if record.category in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "EMAIL_DELIVERY_LOG"} and re.search(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", record.text, re.I
    ):
        return "PRESENT"
    if has_direct_identifiers(record.fields):
        return "PRESENT"
    if record.category == "ANALYTICS_PROFILE":
        return "ANONYMIZED"
    if record.category in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ACCOUNT_TOMBSTONE"}:
        return "REDACTED"
    return "UNKNOWN"


def finding_for(record: Evidence, state: str) -> tuple[str, str] | None:
    category = record.category
    if category == "DATA_FLOW":
        return ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE") if state == "ACTIVE" else None
    if category == "BACKUP_ARCHIVE":
        return ("REPORT_RESTORE_RISK", "ACTIVE") if state in {"ACTIVE", "PRESENT"} else None
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
        return None
    if state == "UNKNOWN":
        return None
    if category == "ACCOUNT_TOMBSTONE":
        return ("REPORT_EXPOSED_PII", "PRESENT") if state in {"PRESENT", "ACTIVE"} and has_direct_identifiers(record.fields) else None
    if str(record.fields.get("event") or "").casefold() == "contact_lookup_completed":
        rows = str(record.fields.get("rows", ""))
        if rows.isdigit() and int(rows) > 0:
            return "REPORT_REMAINING_RECORD", "PRESENT"
    if state in {"ABSENT", "ANONYMIZED", "REDACTED", "DISABLED", "BLOCKED"}:
        return None
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        return ("REPORT_EXPOSED_PII", "PRESENT")
    if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
        if str(record.fields.get("event", "")).casefold() == "deletion_marker_check":
            return ("REPORT_REMAINING_RECORD", "PRESENT") if state == "PRESENT" else None
        return ("REPORT_EXPOSED_PII", "PRESENT")
    if category == "SUPPORT_ATTACHMENT":
        return ("REPORT_REMAINING_RECORD", "PRESENT")
    return ("REPORT_REMAINING_RECORD", "PRESENT")


def remediation_for(
    record: Evidence, finding: str, policy: dict[str, str]
) -> tuple[str, str]:
    if finding == "REPORT_ACTIVE_DATA_FLOW":
        return "DISABLE_DATA_FLOW", "DISABLED"
    if finding == "REPORT_RESTORE_RISK":
        return "BLOCK_RESTORE", "BLOCKED"
    event = str(record.fields.get("event") or "").casefold()
    if event == "deletion_marker_check" and str(
        record.fields.get("marker_found", "")
    ).casefold() == "false":
        return "DELETE_RECORD", "ABSENT"
    if event in {"contact_query_completed", "contact_lookup_completed"}:
        rows = str(record.fields.get("rows", ""))
        if rows.isdigit() and int(rows) > 0:
            return "DELETE_RECORD", "ABSENT"
    action = policy.get(record.category)
    policy_operations = {
        "DELETE": ("DELETE_RECORD", "ABSENT"),
        "REDACT": ("REDACT_RECORD", "REDACTED"),
        "ANONYMIZE": ("ANONYMIZE_RECORD", "ANONYMIZED"),
    }
    if action not in policy_operations:
        raise ValueError(
            f"No actionable deletion policy for {record.category}: {action or 'missing'}"
        )
    return policy_operations[action]


def verification_for(record: Evidence, state: str, remediation: str = "") -> tuple[str, str] | None:
    if remediation:
        return {
            "DELETE_RECORD": ("VERIFY_RECORD_ABSENT", "ABSENT"),
            "REDACT_RECORD": ("VERIFY_RECORD_REDACTED", "REDACTED"),
            "ANONYMIZE_RECORD": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
            "DISABLE_DATA_FLOW": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
            "BLOCK_RESTORE": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
        }[remediation]
    if record.category == "DATA_FLOW" and state == "DISABLED":
        return "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
    if record.category == "BACKUP_ARCHIVE" and state == "BLOCKED":
        return "VERIFY_RESTORE_BLOCKED", "BLOCKED"
    if record.category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"} and state in {"PRESENT", "ACTIVE"}:
        return "VERIFY_RECORD_PRESENT", "PRESENT"
    if record.category == "ACCOUNT_TOMBSTONE" and state == "REDACTED":
        return "VERIFY_RECORD_REDACTED", "REDACTED"
    if state == "ABSENT":
        return "VERIFY_RECORD_ABSENT", "ABSENT"
    if state == "REDACTED":
        return "VERIFY_RECORD_REDACTED", "REDACTED"
    if state == "ANONYMIZED":
        return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
    if record.category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"} and state == "UNKNOWN":
        return "VERIFY_RECORD_PRESENT", "PRESENT"
    return None


def step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def ordered_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps.sort(
        key=lambda item: (
            PHASE_ORDER[item["phase"]],
            OPERATION_ORDER[item["operation"]],
            item["system_id"],
            item["resource_id"],
        )
    )
    for number, item in enumerate(steps, start=1):
        item["step_no"] = number
    return steps


def build_case(
    request: dict[str, str],
    users: dict[str, dict[str, Any]],
    aliases: dict[str, set[str]],
    history: list[dict[str, str]],
    evidence: list[Evidence],
    manifest_times: dict[str, str],
    activities: list[dict[str, str]],
    policy: dict[str, str],
) -> tuple[str, list[dict[str, Any]]]:
    if not request_authorizes_deletion(request.get("request_text", "")):
        return "NOT_APPLICABLE", []

    audit_at = parse_time(request["audit_at"])
    if audit_at is None:
        raise ValueError(f"Invalid audit_at for {request.get('case_id')}: {request.get('audit_at')}")
    candidate_ids = aliases.get(normalized(request.get("email", "")), set())
    if len(candidate_ids) != 1:
        return "INCOMPLETE", []
    user_id = next(iter(candidate_ids))
    identifiers = subject_identifiers(
        user_id, request.get("email", ""), audit_at, users[user_id], history
    )
    matching = [
        record
        for record in evidence
        if record.category != "ACCOUNT_SNAPSHOT"
        and evidence_at_cutoff(record, audit_at, manifest_times)
        and evidence_matches(record, user_id, identifiers)
    ]
    correlated_hashes = {
        normalized(value)
        for value in identifiers
        if re.fullmatch(r"[0-9a-fA-F]{40,}", value)
    }
    matching = [
        Evidence(
            record.system_id,
            record.resource_id,
            record.category,
            "PRESENT",
            record.evidence_id,
            record.observed_at,
            {**record.fields, "email_hash": record.fields.get("correlation_key")},
            record.text,
        )
        if record.category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
        and normalized(record.fields.get("correlation_key", "")) in correlated_hashes
        else record
        for record in matching
    ]
    linked_resources = {
        (record.system_id, record.resource_id, record.category)
        for record in matching
    }
    matched_keys = {
        (record.system_id, record.resource_id, record.category, record.evidence_id)
        for record in matching
    }
    matching.extend(
        record
        for record in evidence
        if record.category != "ACCOUNT_SNAPSHOT"
        and (record.system_id, record.resource_id, record.category) in linked_resources
        and evidence_at_cutoff(record, audit_at, manifest_times)
        and (record.system_id, record.resource_id, record.category, record.evidence_id)
        not in matched_keys
    )
    account_records = [record for record in matching if record.category == "USER_PROFILE"]
    account_id = next((record.resource_id for record in account_records), "")
    if not account_records:
        reported_at = parse_time(request.get("reported_at"))
        linked_activities: list[tuple[float, str]] = []
        for activity in activities:
            if (
                activity.get("event_type") != "DELETE_RECORD"
                or activity.get("target_system") != "account_service"
                or activity.get("source_system") != "deletion_worker"
            ):
                continue
            event_time = parse_time(activity.get("event_time"))
            resource_id = activity.get("resource_id", "")
            if event_time is None or event_time > audit_at or not resource_id.startswith("account_"):
                continue
            details = normalized(activity.get("details", ""))
            if normalized(user_id) in details or any(
                "@" in value and normalized(value) in details for value in identifiers
            ):
                linked_activities.append((0.0, resource_id))
            elif reported_at:
                distance = abs((event_time - reported_at).total_seconds())
                if distance <= 600:
                    linked_activities.append((distance, resource_id))
        unique_resources = {resource_id for _, resource_id in linked_activities}
        if len(unique_resources) == 1:
            account_id = next(iter(unique_resources))

    if account_id and not account_records:
        snapshots = [
            record
            for record in evidence
            if record.category == "ACCOUNT_SNAPSHOT"
            and evidence_at_cutoff(record, audit_at, manifest_times)
        ]
        snapshots.sort(key=lambda record: parse_time(record.observed_at) or dt.datetime.min.replace(tzinfo=dt.timezone.utc))
        if snapshots and account_id not in snapshots[-1].fields.get("resource_ids", []):
            snapshot = snapshots[-1]
            matching.append(
                Evidence(
                    "account_service",
                    account_id,
                    "USER_PROFILE",
                    "ABSENT",
                    snapshot.evidence_id,
                    snapshot.observed_at,
                    {"resource_id": account_id, "user_id": user_id, "status": "NOT_FOUND"},
                    f"Account profile {account_id} absent from captured profile snapshot.",
                )
            )
    current = deduplicate_latest(matching)
    account_absent = [
        record
        for record in current
        if record.category == "USER_PROFILE" and evidence_state(record) == "ABSENT"
    ]
    if len(account_absent) > 1:
        latest_account = max(
            account_absent,
            key=lambda record: parse_time(record.observed_at)
            or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
        )
        current = [
            record
            for record in current
            if record.category != "USER_PROFILE"
            or evidence_state(record) != "ABSENT"
            or record is latest_account
        ]

    findings: list[dict[str, Any]] = []
    remedies: list[tuple[Evidence, str, str]] = []
    current_verifications: list[dict[str, Any]] = []
    account_evidence: list[Evidence] = []
    retained_records: list[Evidence] = []
    for record in current:
        state = evidence_state(record)
        if record.category == "USER_PROFILE":
            account_evidence.append(record)
        if record.category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"} and state in {"PRESENT", "ACTIVE", "UNKNOWN"}:
            retained_records.append(record)
        violation = finding_for(record, state)
        if violation:
            operation, finding_state = violation
            findings.append(
                step("FINDING", record.system_id, record.resource_id, operation, finding_state, record.evidence_id)
            )
            remediation, remediation_state = remediation_for(record, operation, policy)
            remedies.append((record, remediation, remediation_state))
        else:
            verification = verification_for(record, state)
            if verification:
                operation, verify_state = verification
                current_verifications.append(
                    step(
                        "VERIFICATION",
                        record.system_id,
                        record.resource_id,
                        operation,
                        verify_state,
                        record.evidence_id,
                    )
                )

    account_present = any(evidence_state(record) in {"PRESENT", "ACTIVE"} for record in account_evidence)
    has_violation = bool(findings)
    if has_violation:
        steps = list(findings)
        for record, operation, state in remedies:
            steps.append(
                step("REMEDIATION", record.system_id, record.resource_id, operation, state, "")
            )
        verified_resources: set[tuple[str, str]] = set()
        for record, operation, _state in remedies:
            verified_resources.add((record.system_id, record.resource_id))
            verify_op, verify_state = verification_for(record, "", operation) or ("", "")
            if verify_op:
                steps.append(
                    step("VERIFICATION", record.system_id, record.resource_id, verify_op, verify_state, "")
                )
        for check in current_verifications:
            key = (check["system_id"], check["resource_id"])
            if key not in verified_resources:
                steps.append({**check, "evidence_id": ""})
                verified_resources.add(key)
        for record in account_evidence:
            key = (record.system_id, record.resource_id)
            if not account_present and key not in verified_resources:
                steps.append(
                    step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", "")
                )
                verified_resources.add(key)
        for record in retained_records:
            key = (record.system_id, record.resource_id)
            if key not in verified_resources:
                steps.append(
                    step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_PRESENT", "PRESENT", "")
                )
                verified_resources.add(key)
        return "INCOMPLETE", ordered_steps(steps)

    if account_present:
        return "INCOMPLETE", ordered_steps(
            [
                step(
                    "FINDING",
                    record.system_id,
                    record.resource_id,
                    "REPORT_REMAINING_RECORD",
                    "PRESENT",
                    record.evidence_id,
                )
                for record in account_evidence
                if evidence_state(record) in {"PRESENT", "ACTIVE"}
            ]
        )
    if not current_verifications:
        return "INCOMPLETE", []
    return "COMPLETE", ordered_steps(current_verifications)


def run(dataset: Path, input_path: Path, output_path: Path) -> int:
    requests = read_csv(input_path)
    users, aliases = identity_index(dataset)
    history = read_csv(dataset / "user_audit_log.csv")
    policy = load_policy(dataset)
    evidence = load_evidence(dataset)
    activities = read_csv(dataset / "system_activity.csv")
    manifest_times = {
        row["file_id"]: row["captured_at"] for row in read_csv(dataset / "evidence_files.csv")
    }
    output: list[dict[str, str]] = []
    for request in requests:
        status, steps = build_case(
            request, users, aliases, history, evidence, manifest_times, activities, policy
        )
        output.append(
            {
                "case_id": request["case_id"],
                "deletion_status": status,
                "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
            }
        )
    output.sort(key=lambda row: row["case_id"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["case_id", "deletion_status", "steps_json"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(output)
    return len(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--input", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    dataset = args.dataset.resolve()
    input_path = (args.input or dataset / "deletion_requests.csv").resolve()
    output_path = args.output.resolve()
    row_count = run(dataset, input_path, output_path)
    print(f"Wrote {row_count} audit rows to {output_path}")
    if shutil.which("tesseract") is None and any((dataset / "evidence").rglob("*.png")):
        print("Note: tesseract is unavailable; image evidence was not OCR-scanned.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
