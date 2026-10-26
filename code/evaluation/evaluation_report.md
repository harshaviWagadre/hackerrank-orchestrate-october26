# Evaluation Report

## Results

The full-dataset run generated 518 rows, sorted by `case_id`, with the required header and valid JSON steps. The output validator passed all 518 rows.

The public benchmark contains 32 cases. Against `dataset/sample_output.csv`:

| Metric | Result |
| --- | ---: |
| Case-level deletion-status accuracy | 31/32 (96.9%) |
| Exact step-sequence accuracy | 12/32 (37.5%) |
| Exact-step accuracy | 118/193 (61.1%) |
| Field accuracy, aligned against expected steps | 983/1,351 (72.8%) |

The sample is small and public; these figures do not establish hidden-set accuracy. Field accuracy compares fields in positionally aligned steps and does not count extra predicted steps as expected fields.

## Additional Evaluation Cases

The automated tests include these independently constructed checks:

1. An explicit account-erasure request is authorized for deletion.
2. An account-data export request is `NOT_APPLICABLE`.
3. An explicit “do not delete” instruction is not authorized.
4. Evidence observed after `audit_at` is excluded.
5. A stable `subject_reference` links a retained record to the user.
6. Steps are sorted by phase and operation, and then numbered consecutively.
7. An analytics record uses the action loaded from `deletion_rules.csv`.

All seven tests pass using Python's standard-library `unittest` runner.

## Failures and Improvements

- Remaining public-sample differences include missed or extra records and incomplete verification plans. Exact sequence accuracy is only 40.6%; the output must not be represented as fully correct.
- The evidence linker was tightened to avoid re-adding an untransformed duplicate after a correlation-based match. Owner/requester email and lookup-key fields were added to direct-identifier detection.
- Remediation actions are now loaded from `deletion_rules.csv` instead of being selected from a category-only fallback.
- The current document reader can extract text from supported PDFs but does not OCR PNG screenshots when Tesseract is unavailable. Screenshot evidence may therefore be missed.
- The sample benchmark was used for evaluation, not as a source of hardcoded predictions. No hidden organizer data or golden answers were used.

## Reproduction

From the repository root:

```bash
python3 code/main.py
python3 -m unittest discover -s code/evaluation -p 'test_*.py'
python3 code/evaluation/main.py
```
