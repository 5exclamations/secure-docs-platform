# Security review

A manual review performed after the automated suites were green, looking for what tests written by the same author tend to miss. Scope: the application, its database role model, the container and compose setup, and the Terraform. No testing was done against external infrastructure; everything below was exercised locally or reasoned from the code and configuration.

Status values: **Fixed** (code changed, regression test added), **Documented** (accepted trade-off, described honestly), **Verified** (examined, no issue found, evidence given).

## Findings that changed the code

| # | Area | Finding | Status |
|---|---|---|---|
| 1 | Logs, traces | The share-link token is a bearer secret that lives in the URL path. The OpenTelemetry FastAPI instrumentation recorded the raw path in `http.target` and `http.url`, so tokens reached the collector and Jaeger. The error log also printed the raw path. | **Fixed.** A span hook scrubs `/shared/<token>` to `/shared/{token}` and the error log uses the same scrubber. Tests: `test_share_token_never_reaches_traces`, `test_scrub_url`; the compose smoke test also scans real Jaeger traces. |
| 2 | RLS, DB roles | Row level security is silently skipped for superusers, `BYPASSRLS` roles and table owners. Starting the API with the migration (owner) credentials would have dropped tenant isolation to the application layer with no signal. | **Fixed.** On startup the API checks its own role and refuses to start outside `ENVIRONMENT=local` (it logs a warning there). Test: `test_api_refuses_to_start_with_a_role_that_bypasses_rls`. |
| 3 | Metrics | `/metrics` was open when `METRICS_TOKEN` was unset, including in production configuration. | **Fixed.** Settings validation requires a token in staging and production. Test: `test_production_config_is_validated`. |
| 4 | Deployment correctness | Host header validation applied to the ALB health check, which addresses targets by private IP. Every target would have been marked unhealthy and the deployment would never have served traffic. | **Fixed.** `/health` and `/health/ready` are exempt; all other paths still require the configured host. Test: `test_trusted_host_enforced_but_health_checks_exempt`. |
| 5 | Storage consistency | If the database commit failed after the object was uploaded, the object stayed behind with no row referencing it. | **Fixed for the commit step.** `_commit_or_cleanup` deletes the object on failure or cancellation. Residual: an exception in the audit insert that precedes the commit still leaves the object; it is unreferenced and unreachable but not cleaned automatically. |
| 6 | Tests | The role bootstrap test re-keyed the shared `docs_app` role to a hardcoded password, which broke every later test whenever CI used a different password. | **Fixed.** The test restores the original password. Found by GitHub Actions, not locally. |

## Limits that are documented, not fixable in code

### Revoking an already-issued presigned URL

A presigned URL is a bearer credential evaluated by the object store, not by this service. Once issued it works until it expires, and nothing in the application can cancel it. Concretely, for up to `PRESIGN_TTL_SECONDS` (default 60, hard cap 300) after issuance:

* revoking a user grant, revoking or expiring a share link, deactivating the user, freezing the organization, or soft-deleting the document does **not** invalidate URLs already handed out;
* the URL is not bound to an IP address or a session, so anyone who obtains it in that window can fetch the object;
* a share link limited to N downloads limits how many **URLs are issued**. Each issued URL can be fetched repeatedly until it expires, so N caps issuances, not byte transfers.

New requests are refused immediately after revocation; only URLs already in someone's hands survive, and only for the TTL. Mitigations in place: a short default TTL, a hard server-side cap, `Content-Disposition: attachment`, the audit row written at issuance, and signatures bound to the exact object key (tested against real MinIO). If a use case cannot tolerate that window, the options are a lower TTL (minimum 5 s), proxying downloads through the API (loses the "no file bytes through the API" property and adds load), or fronting storage with a CDN that supports revocable signed cookies. In AWS, URLs signed with instance-role credentials also stop working when those temporary credentials rotate, which can shorten the effective lifetime; that behaviour is AWS-specific and was not tested here.

### Hard delete on a versioned bucket

The bucket is versioned (for accidental-overwrite recovery). The API role can delete objects but not object versions (`s3:DeleteObjectVersion` is deliberately not granted), so an admin "hard delete" removes the database rows and writes S3 delete markers, while the previous object versions stay recoverable until the lifecycle rule expires non-current versions (90 days by default). If you must erase data sooner (for example a right-to-erasure request), an operator with a separate privileged role has to delete the versions. The same applies to the local MinIO bucket, where the init job also enables versioning.

### Other accepted limits

| Area | Limit |
|---|---|
| Tables without RLS | `organizations` and `users` have no row level security because login must find a user by email before any tenant is known. Every query on them filters by `org_id` in code (tests cover cross-tenant user listing and updates), but there is no second layer. |
| Upload content | The declared type must be on the allowlist and match the file's magic bytes. OOXML types accept any file starting with the ZIP signature, text types only need to be valid UTF-8, and there is no malware scanning or macro inspection. Files are always served as attachments. |
| Rate limiting | Fixed window per Redis key (allows up to 2x burst across a window boundary). Per-IP limits do not stop a botnet or IPv6 address rotation inside one /64. `TRUSTED_PROXY_COUNT` must match the real proxy chain: 0 behind a proxy makes every client share the proxy's address, too high allows spoofing. The AWS user data sets 1 for the single ALB. |
| Account lockout | Per account, regardless of source IP, so an attacker can lock a known email for 15 minutes (see threat T17). |
| Credentials lifecycle | There is no password change or reset endpoint and no MFA. Deactivation by an admin is the recovery path. |
| Refresh rotation | A legitimate client that loses the response to a refresh and retries with the old token looks identical to a replay and loses its session. This is the intended fail-safe. |
| Access tokens | Valid until expiry (15 minutes) unless the user is deactivated, the organization frozen or the session family revoked; those three checks run on every request. |
| RS256 | One signing key, no overlapping key rotation. |
| Secrets in local compose | Secrets pass through container environment variables (visible with `docker inspect`), the API uses the MinIO root credentials instead of a scoped user, and the Prometheus token file is world-readable. This is a local development stack bound to 127.0.0.1. |
| Secrets in AWS | Terraform state contains the generated JWT, app DB, metrics and Redis secrets (not the RDS master password, which RDS manages), so the state bucket must be encrypted and access-controlled. On the instance they sit in a root-only `0600` env file and the container environment. |

## Examined with no issue found

| Area | What was checked | Evidence |
|---|---|---|
| RLS design | Policies use `current_setting('app.org_id', true)` set with `set_config(..., is_local => true)` in each transaction, re-applied by an `after_begin` hook; no tenant bound means no rows; `WITH CHECK` blocks cross-tenant writes; the audit trigger also stops the owner | `test_rls_*`, `test_audit_log_is_append_only`, `test_parallel_tenants_do_not_bleed_context` |
| Privileged vs unprivileged connections | Migrations run as the owner, the API as `docs_app` (not owner, no `BYPASSRLS`, no DDL); the bootstrap script is idempotent and quote-safe | `test_runtime_role_is_not_privileged`, `test_bootstrap_role_*`, finding 2 |
| Cross-tenant access | Every document, version, grant, link and audit path returns 404 for foreign ids; composite foreign keys reject cross-org references even for the owner | `test_tenant_isolation.py` (13 scenarios) |
| JWT | Algorithm is pinned server-side (no `none`, no HS/RS confusion), `iss`, `aud`, `exp`, `nbf`, `sub`, `jti` required, token type enforced, `org_id` claim cross-checked against the stored user | `test_forged_expired_and_wrong_audience_tokens_rejected`, `test_rs256_*` |
| Refresh tokens | Single use via atomic `GETDEL`, replay revokes the whole family, concurrent use yields exactly one winner, logout revokes the family | `test_refresh_*`, `test_concurrent_refresh_only_one_wins` |
| Concurrency | Version numbers under a row lock, share-link cap as one conditional `UPDATE`, grants as an upsert | `test_concurrent_*`, `test_max_downloads_holds_under_concurrency` |
| Object-level authorization | S3 keys are `{org}/{doc}/{uuid}` and never derived from input; the API is the only authorization point and the bucket is private, so access is through the API or a short-lived signed URL | `test_object_key_is_not_user_controlled` |
| Expired and revoked links | Validity is one atomic statement against the database clock; each refusal is audited with its reason | `test_expired_link_*`, `test_revoked_link_*` |
| Upload validation | Streamed size cap (also without `Content-Length`), type allowlist, magic-byte match, sanitized names | `test_upload_validation`, size and filename tests |
| Logs, metrics, traces | Request bodies are never logged; secrets are redacted by key; metrics use route templates (bounded labels, no ids or tokens); span SQL carries placeholders only | `test_log_redaction`, `test_traces_do_not_contain_credentials_or_bound_values`, finding 1 |
| Containers | API image runs as UID 10001 with a read-only root filesystem, all capabilities dropped and `no-new-privileges`; the CI asserts non-root | `Dockerfile`, `docker-compose.yml`, CI job |

## Method note

All of this was reviewed by the same author that wrote the code, with automated scanners (Bandit, Semgrep, CodeQL, Checkov, Trivy, gitleaks, pip-audit) as an independent signal. An external review or penetration test would still be the right step before real customer data.
