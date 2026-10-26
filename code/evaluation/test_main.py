import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main  # noqa: E402


class DeletionIntentTests(unittest.TestCase):
    def test_explicit_erasure_request_is_authorized(self) -> None:
        self.assertTrue(main.request_authorizes_deletion("Please erase my account."))

    def test_export_request_is_not_deletion(self) -> None:
        self.assertFalse(main.request_authorizes_deletion("Please export my account data."))

    def test_explicit_do_not_delete_is_not_authorized(self) -> None:
        self.assertFalse(main.request_authorizes_deletion("Do not delete my account."))


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
        self.assertEqual([item["step_no"] for item in ordered], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
