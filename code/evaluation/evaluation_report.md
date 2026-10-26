# Evaluation Report

## Results

The current deterministic Python implementation generated the 518-request candidate at `/private/tmp/ghost-final-output.csv`. The official evaluator validated the full file: required columns, 518 sorted request rows, valid step structure, evidence references, allowed operations/states, and ordering. The candidate contains 346 `INCOMPLETE`, 140 `COMPLETE`, and 32 `NOT_APPLICABLE` results (2,315 total steps); after validation, this exact candidate was promoted to root `output.csv`.

The official public benchmark compares the generated outputs with `dataset/sample_output.csv`:

| Metric | Result |
| --- | ---: |
| Case-level deletion-status accuracy | 29/32 (90.6%) |
| Exact step-sequence accuracy | 10/32 (31.2%) |
| Exact-step accuracy, matched by system/resource | 118/193 (61.1%) |
| Field accuracy, matched by system/resource | 1,072/1,351 (79.3%) |

This is a public-sample measurement only and does not establish hidden-set accuracy. The differential is in [`sample_differential.md`](./sample_differential.md). It records 22 cases with sequence differences, including status mismatches for `case_01`, `case_02`, and `case_04`; it lists 34 expected steps without a matching system/resource step and no extra actual steps or out-of-order matched steps.

## Current Change and Comparison

Compared with the preceding evidence-conservative implementation, the cross-source account-reference rule preserved the time-only ownership safeguard and restored the supported `case_06` account verification; `case_06` now exactly matches all four reference steps. Measured changes were neutral in status accuracy (29/32 to 29/32), +1 exact sequence (9/32 to 10/32), +2 exact steps (116/193 to 118/193), and +8 exact fields (1,064/1,351 to 1,072/1,351). No sample IDs or expected output rows are used by the implementation.

The account link requires an eligible, identity-matched record with a typed account resource reference and eligible snapshot evidence showing that account absent. Explicit conflicting identity evidence blocks the inferred link. The five time-only cases (`case_01`, `case_02`, `case_07`, `case_08`, and `case_10`) remain unlinked. Retention logic was not changed.

## Additional Evaluation Cases

All 31 standard-library regression tests pass. Focused ownership cases include:

1. A uniquely timed deletion activity plus an absent account snapshot is insufficient to establish ownership.
2. An identity-linked `source_resource_id` with eligible account snapshot evidence supports the account verification.
3. A resource reference captured after `audit_at` cannot establish the link.
4. Eligible evidence attributing that account to another identity blocks the inferred link.

The other regression tests cover identity history cutoffs, evidence cutoffs, deletion intent, policy actions, ordering, OCR parsing, retained records, and output contract validation.

## Remaining Failures and Improvements

The public benchmark remains imperfect. `case_01` and `case_02` expect COMPLETE despite lacking a verified subject-to-account link; `case_04` also remains a status mismatch. The expected checks for the five time-only cases are not inferred from temporal proximity. Other sequence differences are itemized in the differential report. The cross-source rule recovers the evidence-supported `case_06` check without changing retention behavior or adding sample-specific logic.

## Reproduction

From the repository root:

```bash
python3 -m unittest discover -s code/evaluation -p 'test_main.py' -v
python3 code/main.py --dataset dataset --input dataset/deletion_requests.csv --output /private/tmp/ghost-final-output.csv
python3 code/evaluation/main.py --dataset dataset --output /private/tmp/ghost-final-output.csv --differential-report /private/tmp/ghost-final-differential.md
```
