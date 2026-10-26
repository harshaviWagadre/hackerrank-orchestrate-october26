# Model Usage Report

## Full-Dataset Run

The final deterministic Python pipeline processed all 518 requests from `dataset/deletion_requests.csv` and wrote the candidate CSV to `/private/tmp/ghost-final-output.csv`. The candidate passed full-output validation before being promoted to root `output.csv`.

| Provider / model | Model calls | Input tokens | Output tokens | Total tokens | Estimated inference cost |
| --- | ---: | ---: | ---: | ---: | ---: |
| None (local deterministic pipeline; no model invoked) | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | **0** | **0** | **0** | **0** | **$0.00** |

- Requests processed: 518
- Total tokens: 0
- Average tokens per request: 0
- Estimated total inference cost: $0.00
- Estimated inference cost per request: $0.00

The implementation made no model-provider calls, so token usage and inference cost are zero. Local CPU, OCR, and storage costs were not measured and are not estimated here.
