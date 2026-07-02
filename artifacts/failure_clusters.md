# Failure Mode Clustering Report

Systematically grouped tracing errors and user corrections.

## Cluster 0
**Identified Theme**: API Rate Limiting & Quota Exceeded

| Session ID | Status | Failure Details |
|---|---|---|
| `session-2` | **FAILED** | Rate limit 429 hit. Too many requests per minute for gemini-flash model. |
| `session-6` | **ABANDONED** | Injection payload detected. System instruction override attempt rejected. |

## Cluster 1
**Identified Theme**: API Rate Limiting & Quota Exceeded

| Session ID | Status | Failure Details |
|---|---|---|
| `session-1` | **FAILED** | 429 API rate limits exceeded. Vertex AI prediction service quota reached. |

## Cluster 2
**Identified Theme**: AST Sandbox Gating & Syntax Blocks

| Session ID | Status | Failure Details |
|---|---|---|
| `session-3` | **CORRECTION** | AST gating failure: prohibited builtin function 'eval' detected in generated code. |
| `session-4` | **CORRECTION** | Gating check blocked: eval used on untrusted string variables. |
| `session-5` | **ABANDONED** | Indirect prompt injection: untrusted input attempting to overwrite context. |
