# Evaluation Report

## Results

The full-dataset run generated 518 rows, sorted by `case_id`, with the required header and valid JSON steps. The output validator passed all 518 rows.

The public benchmark contains 32 cases. Against `dataset/sample_output.csv`:

| Metric | Result |
| --- | ---: |
| Case-level deletion-status accuracy | 31/32 (96.9%) |
| Exact step-sequence accuracy | 15/32 (46.9%) |
| Exact-step accuracy, matched by system/resource | 126/193 (65.3%) |
| Field accuracy, matched by system/resource | 1,110/1,351 (82.2%) |

The sample is small and public; these figures do not establish hidden-set accuracy. Step/field metrics match rows by `system_id` plus `resource_id`, then compare their fields. The exact-sequence metric compares the complete ordered JSON arrays.

The per-case and per-field comparison, including extra/missing steps and diagnostic categories, is in [`sample_differential.md`](./sample_differential.md). One case still has a status disagreement. Seventeen resource IDs present in the public oracle are not emitted by the current parsers from participant-facing evidence. The differential report lists them; the pipeline does not use the oracle's IDs to fill them in. Several other IDs are extracted but are anonymous/unlinked, so a subject-to-resource association cannot be justified from the available participant-facing evidence.

## Latest Changes and Before/After

The measured baseline before this work was 31/32 status matches and 15/32 exact sequences. This turn added a per-resource absence-verification fix and macOS Vision OCR fallback for screenshots, plus normalized OCR extraction for spaced resource identifiers and retained subject references. Re-running the same public benchmark produced **the same measured results**: 31/32 statuses and 15/32 exact sequences. These changes improve coverage and a regression-tested planning edge case, but they did not resolve the 17 public sequence mismatches; no accuracy improvement is claimed.

The refreshed differential report identifies all 17 mismatching cases and each missing or extra step, including its phase, system/resource, operation, state, evidence reference, and ordering. It also traces missing resources against eligible parsed evidence and activity. The most common unresolved cause is subject-to-resource provenance: some records are present at `audit_at` but have no participant-visible identifier connecting them to the resolved user. Other expected account or retained-record checks are supported only by unlinked activity targets, evidence captured after `audit_at`, or no locatable participant-facing resource. Activity claims and future-captured evidence are not promoted to proof.

## Additional Evaluation Cases

The 18 automated tests include these independently constructed checks:

1. An explicit account-erasure request is authorized for deletion.
2. An account-data export request is `NOT_APPLICABLE`.
3. An explicit “do not delete” instruction is not authorized.
4. Evidence observed after `audit_at` is excluded.
5. A stable `subject_reference` links a retained record to the user.
6. Steps are sorted by phase and operation, and then numbered consecutively.
7. An analytics record uses the action loaded from `deletion_rules.csv`.
8. A failing support deletion-marker check requires deletion rather than generic support-message redaction.
9. A positive contact lookup is treated as a remaining record and planned for deletion.
10. The operation-priority table matches `problem_statement.md`; ties sort by system then resource.
11. An already-absent account copy still receives a future verification when another account copy remains present.
12. OCR text normalizes spaced security-record IDs and links a unique subject reference; marketing-profile IDs are recognized.

All 18 tests pass using Python's standard-library `unittest` runner.

## Failures and Improvements

- Remaining public-sample differences include missed or extra records and incomplete verification plans. Exact sequence accuracy is only 46.9%; the output must not be represented as fully correct.
- The evidence linker was tightened to avoid re-adding an untransformed duplicate after a correlation-based match. Owner/requester email and lookup-key fields were added to direct-identifier detection.
- Remediation actions are now loaded from `deletion_rules.csv` instead of being selected from a category-only fallback.
- Added support for the dataset's non-ISO timestamp forms, allowing historical identifiers and event cutoffs to be evaluated consistently; stable user IDs in `correlation_key` fields now link retained evidence.
- Corrected positive contact lookup/deletion-marker events to report a remaining record and select deletion rather than PII exposure/redaction when the event establishes a live contact row.
- In incomplete cases, existing compliant evidence verifications are retained as future checks with empty evidence references.
- Verified the operation ordering in `problem_statement.md`: findings (`REPORT_REMAINING_RECORD`, `REPORT_EXPOSED_PII`, `REPORT_ACTIVE_DATA_FLOW`, `REPORT_RESTORE_RISK`), remediation (`DISABLE_DATA_FLOW`, `BLOCK_RESTORE`, `DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD`), and verification (`VERIFY_RECORD_ABSENT`, `VERIFY_RECORD_PRESENT`, `VERIFY_RECORD_REDACTED`, `VERIFY_RECORD_ANONYMIZED`, `VERIFY_DATA_FLOW_DISABLED`, `VERIFY_RESTORE_BLOCKED`); each tie-breaks by system and resource.
- OCR now uses Tesseract when installed and falls back to Apple's Vision framework through `code/vision_ocr.swift` on macOS. OCR improves ingestion coverage but did not change public-sample accuracy in the latest run; screenshots without a recognized resource identifier remain unusable for resource-level steps.
- The sample benchmark was used for evaluation, not as a source of hardcoded predictions. No hidden organizer data or golden answers were used.

## Reproduction

From the repository root:

```bash
python3 code/main.py
python3 -m unittest discover -s code/evaluation -p 'test_*.py'
python3 code/evaluation/main.py --differential-report code/evaluation/sample_differential.md
```
