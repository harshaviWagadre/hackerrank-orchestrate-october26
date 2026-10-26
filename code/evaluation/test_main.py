import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main  # noqa: E402
from evaluation import main as evaluation  # noqa: E402


class DeletionIntentTests(unittest.TestCase):
    def test_explicit_erasure_request_is_authorized(self) -> None:
        self.assertTrue(main.request_authorizes_deletion("Please erase my account."))

    def test_export_request_is_not_deletion(self) -> None:
        self.assertFalse(main.request_authorizes_deletion("Please export my account data."))

    def test_explicit_do_not_delete_is_not_authorized(self) -> None:
        self.assertFalse(main.request_authorizes_deletion("Do not delete my account."))

    def test_nonstandard_timestamp_is_parsed_for_historical_identity(self) -> None:
        event_time = main.parse_time("2026:08- 27T10:00:00Z")
        cutoff = main.parse_time("2026-08-28T00:00:00Z")
        self.assertIsNotNone(event_time)
        self.assertIsNotNone(cutoff)
        identifiers = main.subject_identifiers(
            "user_7",
            "new@example.test",
            cutoff,
            {"updated_at": "2026-08-27T12:00:00Z"},
            [
                {
                    "user_id": "user_7",
                    "event_time": "2026:08- 27T10:00:00Z",
                    "field_name": "email",
                    "old_value": "old@example.test",
                    "new_value": "new@example.test",
                }
            ],
        )
        self.assertIn("old@example.test", identifiers)

    def test_historical_identity_after_cutoff_is_excluded(self) -> None:
        cutoff = main.parse_time("2026-08-27T09:00:00Z")
        self.assertIsNotNone(cutoff)
        identifiers = main.subject_identifiers(
            "user_7",
            "new@example.test",
            cutoff,
            {"updated_at": "2026-08-28T12:00:00Z"},
            [
                {
                    "user_id": "user_7",
                    "event_time": "2026:08- 27T10:00:00Z",
                    "field_name": "email",
                    "old_value": "old@example.test",
                    "new_value": "new@example.test",
                }
            ],
        )
        self.assertNotIn("old@example.test", identifiers)


class EvidenceAndOrderingTests(unittest.TestCase):
    def test_remediation_uses_the_loaded_policy_action(self) -> None:
        rules = main.load_policy(Path(__file__).resolve().parents[2] / "dataset")
        analytics = main.Evidence(
            "analytics_platform",
            "analytics_1",
            "ANALYTICS_PROFILE",
            "PRESENT",
            "evidence_1",
            "2026-01-01T00:00:00Z",
            {},
            "",
        )
        self.assertEqual(
            main.remediation_for(analytics, "REPORT_EXPOSED_PII", rules),
            ("ANONYMIZE_RECORD", "ANONYMIZED"),
        )

    def test_subject_reference_matches_stable_user_id(self) -> None:
        record = main.Evidence(
            "security_service",
            "audit_record_9",
            "SECURITY_AUDIT_LOG",
            "PRESENT",
            "evidence_1",
            "2026-01-01T00:00:00Z",
            {"subject_reference": "user_9"},
            "",
        )
        self.assertTrue(main.evidence_matches(record, "user_9", set()))

    def test_correlation_key_matches_stable_user_id(self) -> None:
        record = main.Evidence(
            "security_service",
            "audit_record_10",
            "SECURITY_AUDIT_LOG",
            "PRESENT",
            "evidence_2",
            "2026-01-01T00:00:00Z",
            {"correlation_key": "user_10"},
            "",
        )
        self.assertTrue(main.evidence_matches(record, "user_10", set()))

    def test_stale_contact_lookup_requires_delete_not_redaction(self) -> None:
        record = main.Evidence(
            "support_platform",
            "support_2",
            "SUPPORT_MESSAGE",
            "PRESENT",
            "evidence_3",
            "2026-01-01T00:00:00Z",
            {"event": "deletion_marker_check", "marker_found": "false"},
            "",
        )
        self.assertEqual(
            main.finding_for(record, main.evidence_state(record)),
            ("REPORT_REMAINING_RECORD", "PRESENT"),
        )
        self.assertEqual(
            main.remediation_for(record, "REPORT_REMAINING_RECORD", {"SUPPORT_MESSAGE": "REDACT"}),
            ("DELETE_RECORD", "ABSENT"),
        )

    def test_contact_query_row_is_reported_and_deleted(self) -> None:
        record = main.Evidence(
            "analytics_platform",
            "analytics_11",
            "ANALYTICS_PROFILE",
            "PRESENT",
            "evidence_4",
            "2026-01-01T00:00:00Z",
            {"event": "contact_lookup_completed", "rows": "1"},
            "",
        )
        self.assertEqual(
            main.finding_for(record, main.evidence_state(record)),
            ("REPORT_REMAINING_RECORD", "PRESENT"),
        )
        self.assertEqual(
            main.remediation_for(record, "REPORT_REMAINING_RECORD", {"ANALYTICS_PROFILE": "ANONYMIZE"}),
            ("DELETE_RECORD", "ABSENT"),
        )

    def test_order_matches_all_operation_priorities(self) -> None:
        operation_phases = {
            "REPORT_REMAINING_RECORD": "FINDING",
            "REPORT_EXPOSED_PII": "FINDING",
            "REPORT_ACTIVE_DATA_FLOW": "FINDING",
            "REPORT_RESTORE_RISK": "FINDING",
            "DISABLE_DATA_FLOW": "REMEDIATION",
            "BLOCK_RESTORE": "REMEDIATION",
            "DELETE_RECORD": "REMEDIATION",
            "REDACT_RECORD": "REMEDIATION",
            "ANONYMIZE_RECORD": "REMEDIATION",
            "VERIFY_RECORD_ABSENT": "VERIFICATION",
            "VERIFY_RECORD_PRESENT": "VERIFICATION",
            "VERIFY_RECORD_REDACTED": "VERIFICATION",
            "VERIFY_RECORD_ANONYMIZED": "VERIFICATION",
            "VERIFY_DATA_FLOW_DISABLED": "VERIFICATION",
            "VERIFY_RESTORE_BLOCKED": "VERIFICATION",
        }
        operation_names = [
            "REPORT_RESTORE_RISK",
            "REPORT_REMAINING_RECORD",
            "REPORT_ACTIVE_DATA_FLOW",
            "REPORT_EXPOSED_PII",
            "DISABLE_DATA_FLOW",
            "BLOCK_RESTORE",
            "DELETE_RECORD",
            "REDACT_RECORD",
            "ANONYMIZE_RECORD",
            "VERIFY_RESTORE_BLOCKED",
            "VERIFY_RECORD_ANONYMIZED",
            "VERIFY_RECORD_PRESENT",
            "VERIFY_RECORD_ABSENT",
            "VERIFY_RECORD_REDACTED",
            "VERIFY_DATA_FLOW_DISABLED",
        ]
        self.assertEqual(
            [
                item[0]
                for item in sorted(
                    [(name, "a", "z") for name in operation_names],
                    key=lambda item: (
                        main.PHASE_ORDER[operation_phases[item[0]]],
                        main.OPERATION_ORDER[item[0]],
                        item[1],
                        item[2],
                    ),
                )
            ],
            [
                "REPORT_REMAINING_RECORD",
                "REPORT_EXPOSED_PII",
                "REPORT_ACTIVE_DATA_FLOW",
                "REPORT_RESTORE_RISK",
                "DISABLE_DATA_FLOW",
                "BLOCK_RESTORE",
                "DELETE_RECORD",
                "REDACT_RECORD",
                "ANONYMIZE_RECORD",
                "VERIFY_RECORD_ABSENT",
                "VERIFY_RECORD_PRESENT",
                "VERIFY_RECORD_REDACTED",
                "VERIFY_RECORD_ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED",
                "VERIFY_RESTORE_BLOCKED",
            ],
        )
        operations = [
            ("VERIFY_RESTORE_BLOCKED", "backup_service", "b"),
            ("VERIFY_RECORD_ANONYMIZED", "analytics_platform", "a"),
            ("VERIFY_RECORD_PRESENT", "security_service", "s"),
            ("VERIFY_RECORD_ABSENT", "account_service", "a"),
            ("VERIFY_RECORD_REDACTED", "support_platform", "r"),
            ("VERIFY_DATA_FLOW_DISABLED", "integration_service", "d"),
        ]
        steps = [
            main.step("VERIFICATION", system, resource, operation, "PRESENT", "")
            for operation, system, resource in operations
        ]
        ordered = main.ordered_steps(steps)
        self.assertEqual(
            [step["operation"] for step in ordered],
            [
                "VERIFY_RECORD_ABSENT",
                "VERIFY_RECORD_PRESENT",
                "VERIFY_RECORD_REDACTED",
                "VERIFY_RECORD_ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED",
                "VERIFY_RESTORE_BLOCKED",
            ],
        )

    def test_same_operation_sorts_by_system_then_resource(self) -> None:
        steps = [
            main.step("FINDING", "z", "b", "REPORT_REMAINING_RECORD", "PRESENT", ""),
            main.step("FINDING", "a", "z", "REPORT_REMAINING_RECORD", "PRESENT", ""),
            main.step("FINDING", "a", "a", "REPORT_REMAINING_RECORD", "PRESENT", ""),
        ]
        ordered = main.ordered_steps(steps)
        self.assertEqual(
            [(step["system_id"], step["resource_id"]) for step in ordered],
            [("a", "a"), ("a", "z"), ("z", "b")],
        )

    def test_audit_cutoff_excludes_later_evidence(self) -> None:
        record = main.Evidence(
            "account_service",
            "account_9",
            "USER_PROFILE",
            "ABSENT",
            "evidence_1",
            "2026-01-02T00:00:00Z",
            {},
            "",
        )
        cutoff = main.parse_time("2026-01-01T00:00:00Z")
        self.assertIsNotNone(cutoff)
        self.assertFalse(
            main.evidence_at_cutoff(record, cutoff, {"evidence_1": "2026-01-01T00:00:00Z"})
        )

    def test_step_order_is_phase_operation_then_resource(self) -> None:
        steps = [
            main.step("VERIFICATION", "a", "z", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
            main.step("FINDING", "b", "z", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_1"),
            main.step("FINDING", "a", "a", "REPORT_EXPOSED_PII", "PRESENT", "evidence_2"),
        ]
        ordered = main.ordered_steps(steps)
        self.assertEqual(
            [(item["phase"], item["operation"], item["system_id"]) for item in ordered],
            [
                ("FINDING", "REPORT_REMAINING_RECORD", "b"),
                ("FINDING", "REPORT_EXPOSED_PII", "a"),
                ("VERIFICATION", "VERIFY_RECORD_ABSENT", "a"),
            ],
        )


class OutputContractTests(unittest.TestCase):
    def test_operation_must_use_its_allowed_phase_and_state(self) -> None:
        valid_row = {
            "case_id": "case_001",
            "steps_json": (
                '[{"step_no":1,"phase":"REMEDIATION","system_id":"account_service",'
                '"resource_id":"account_1","operation":"DELETE_RECORD",'
                '"state":"ABSENT","evidence_id":""}]'
            ),
        }
        evaluation.parse_steps(valid_row)

        invalid_row = {
            **valid_row,
            "steps_json": valid_row["steps_json"].replace('"state":"ABSENT"', '"state":"PRESENT"'),
        }
        with self.assertRaisesRegex(ValueError, "operation/state contract"):
            evaluation.parse_steps(invalid_row)


if __name__ == "__main__":
    unittest.main()
