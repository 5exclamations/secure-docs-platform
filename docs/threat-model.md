# Threat model

Method: STRIDE over the data flows in [architecture.md](architecture.md). Scope is the API, its data stores and the AWS reference deployment. Out of scope: the client application, the AWS account's own governance (SCPs, CloudTrail organization trails), and endpoint security of operators.

## Assets

| Asset | Why it matters |
|---|---|
| Document contents | The product. Confidentiality across tenants is the primary security property. |
| Document metadata, tags, titles | Often as sensitive as the content. |
| Credentials, refresh tokens, JWT signing key | Compromise gives impersonation. |
| Audit log | Evidence for incident response; must not be editable. |
| Availability | Single-instance reference deployment; see accepted risks. |

## Trust boundaries

1. Internet to ALB. Everything is hostile here.
2. ALB to API instance. Only the ALB security group may reach port 8000.
3. API to PostgreSQL, Redis and S3. Data stores trust only the app tier.
4. Authenticated tenant user to another tenant's data. The central boundary.
5. Anonymous share-link holder to a single document.
6. Operator to infrastructure (SSM Session Manager, Terraform).

## Threats and mitigations

IDs are referenced from [security-controls.md](security-controls.md).

| ID | STRIDE | Threat | Mitigation | Verified by |
|---|---|---|---|---|
| T1 | Information disclosure | User of org B reads, downloads or lists org A documents by guessing ids (IDOR) | Org-scoped queries, 404 for foreign ids, composite FKs, RLS | `test_tenant_isolation.py` (7 application-level and 6 database-level attack scenarios) |
| T2 | Elevation | A bug drops a `WHERE org_id` filter | Row level security as second layer, unprivileged runtime role | `test_rls_*`, `test_runtime_role_is_not_privileged` |
| T3 | Spoofing | Stolen or forged JWT | Pinned algorithm, `iss`/`aud`/`exp`/`nbf` required, type claim, server-side org check, 15 minute lifetime | `test_forged_expired_and_wrong_audience_tokens_rejected`, `test_rs256_*` |
| T4 | Spoofing | Refresh token theft | Rotation with replay detection that kills the whole session family | `test_refresh_rotation_and_reuse_detection`, `test_concurrent_refresh_only_one_wins` |
| T5 | Spoofing | Credential stuffing, brute force | 5 logins/min/IP, 10 failures/15 min/account, argon2id, no user enumeration, constant-work verification | `test_login_rate_limited_per_ip`, `test_account_lockout_*`, `test_login_failure_is_generic_*` |
| T6 | Spoofing | Rate-limit evasion with a forged `X-Forwarded-For` | Only the right-most trusted-proxy entries are honoured | `test_spoofed_forwarded_for_*`, `test_client_ip_resolution` |
| T7 | Tampering | Malicious upload (HTML/SVG for stored XSS, polyglots, executables) | Content-type allowlist, magic-byte match, downloads forced to `attachment` with the stored type, CSP `default-src 'none'` | `test_upload_validation` |
| T8 | Tampering | Path traversal through filenames or keys | Object key is `{org}/{doc}/{uuid}`, never derived from user input; filenames sanitized | `test_object_key_is_not_user_controlled`, `test_filename_sanitization` |
| T9 | Tampering | Mass assignment (`owner_id`, `org_id`, `role` in a body) | Pydantic models with `extra="forbid"` | `test_unknown_fields_are_rejected`, metadata update test |
| T10 | Tampering | SQL injection | ORM and bound parameters only; full-text search through `plainto_tsquery` | search test with injection payload |
| T11 | Repudiation | An admin or attacker edits the audit trail | Append-only trigger (also blocks the table owner), no UPDATE/DELETE grant, audit row written in the same transaction as the action | `test_audit_log_is_append_only` |
| T12 | Information disclosure | Leaked download URL | 60 second lifetime (max 300), signature bound to the object key, `Content-Disposition: attachment`. **A URL that has already been issued cannot be revoked**: it stays valid until it expires even if the grant, share link or user is revoked meanwhile (see [security-review.md](security-review.md)) | `test_presigned_url_lifetime_*`, `test_presigned_url_expiry_and_tamper_*` (real MinIO) |
| T13 | Information disclosure | Leaked share link | 256-bit token, hash-only storage, mandatory expiry (max 30 days), optional cap on **issued download URLs** (each URL can be fetched repeatedly until it expires), revocation, per-IP limit on the public endpoint, token scrubbed from traces and logs | `test_expired_link_*`, `test_revoked_link_*`, `test_max_downloads_holds_under_concurrency`, `test_share_token_never_reaches_traces` |
| T14 | Information disclosure | Stale access after a grant expires or is revoked | Expiry evaluated per request; role and active flag read from the database, not the token | `test_expired_permission_denies_access`, `test_deactivated_user_loses_access_immediately` |
| T15 | Information disclosure | Verbose errors, stack traces, server banner | Generic error bodies, `--no-server-header`, docs disabled in staging/production | `test_error_bodies_do_not_leak_internals`, config validation test |
| T16 | Denial of service | Oversized or endless request bodies | 1 MiB cap for JSON, 50 MB streamed cap for uploads (also without `Content-Length`), per-user and per-IP rate limits, WAF rate rule | `test_json_body_size_limit`, `test_oversize_upload_rejected_while_streaming` |
| T17 | Denial of service | Abuse of the lockout to lock a victim out | Accepted: lockout is per account and expires after 15 minutes; the IP limit still applies. See residual risks. | n/a |
| T18 | Elevation | Viewer escalates through a write grant | Role ceiling intersects every grant | `test_viewer_role_caps_a_write_grant` |
| T19 | Elevation | Last admin removed, org locked out | Guard against demoting or deactivating the last active admin | `test_cannot_remove_last_admin` |
| T20 | Elevation | Instance credential theft through SSRF | IMDSv2 required (hop limit 2 so the containerised API can reach it; host-network or IMDS proxying would allow 1); instance role scoped to one bucket, its KMS key and three secrets | Terraform `metadata_options`, IAM policy |
| T21 | Tampering | Cross-origin attacks from a hostile site | No CORS unless origins are configured, no wildcard in staging/production, bearer tokens (no cookies, so no CSRF surface) | `test_cors_locked_to_configured_origins`, `test_no_cors_by_default` |
| T22 | Information disclosure | Metrics endpoint exposes internals | Bearer token, plus ALB rule that returns 404 for `/metrics` on the public listener | `test_metrics_requires_token_when_configured` |
| T23 | Tampering | Supply chain: vulnerable dependency or base image | Pinned requirements, Dependabot, pip-audit, Trivy (fs and image), CodeQL, Semgrep, gitleaks, ECR scan on push | CI workflows |
| T24 | Availability | Redis outage | Rate limiter fails closed (503) rather than running unthrottled; sessions need re-login | `test_rate_limiter_fails_closed_when_redis_is_down` |

## Residual risks and accepted trade-offs

* **Single application instance.** The reference deployment trades availability for cost. Adding a second instance in the other AZ and a launch template is the next step; the code is stateless.
* **Lockout can be abused** to annoy a specific user for 15 minutes. The alternative (no lockout) leaves distributed guessing against one account unbounded. Argon2id plus the lockout was chosen; monitor `LoginFailureSpike`.
* **HS256 shared secret.** A leaked secret allows forging tokens for any tenant. RS256 is implemented and recommended for any deployment with more than one verifying service; rotating the secret invalidates all sessions.
* **Uploaded content is not virus-scanned.** Files are never rendered by the service, are served as attachments, and the type is verified by magic bytes, but malware inside a valid PDF or Office file is not detected. Integrating ClamAV or GuardDuty Malware Protection for S3 is the standard next step.
* **Hard delete is not erasure on a versioned bucket.** The API role cannot delete object versions, so earlier versions remain recoverable until the lifecycle rule expires them (90 days by default).
* **Metadata search only.** Document bodies are not indexed, which avoids a second copy of sensitive text in a search index.
* **Application-layer encryption** is not used; protection relies on S3 SSE-KMS and RDS encryption with a customer managed key. Tenants do not have separate keys.
* **Audit log tamper evidence.** The log is append-only inside PostgreSQL, but a database owner with infrastructure access could still alter it. Streaming audit rows to an object-locked bucket would close that gap.
* **Share links bypass user authentication by design.** Anyone holding the link can download until it expires; use short lifetimes and download caps for sensitive files.
