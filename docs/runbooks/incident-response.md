# Incident response runbook

Audience: whoever is on call for the service. Commands assume shell access through SSM Session Manager (`aws ssm start-session --target <instance_id>`), no SSH. In the local compose stack, replace `docker exec` targets accordingly.

## Severity and first response

| Severity | Examples | Target response |
|---|---|---|
| SEV1 | Suspected cross-tenant data exposure, leaked signing secret, public bucket | Start now; contain within 1 hour |
| SEV2 | Account takeover of a user, leaked share link to sensitive data, sustained credential stuffing | Same business day |
| SEV3 | Single failed deployment, rate-limit tuning, noisy alert | Next business day |

First five minutes, always: open an incident channel, name an incident lead, write down the time you were alerted, and preserve evidence before changing anything (export the relevant audit rows and `docker logs`/CloudWatch ranges).

## Signals

| Signal | Source | Likely meaning |
|---|---|---|
| `RefreshTokenReuse` | Prometheus | A refresh token was replayed: stolen token or a buggy client |
| `AuthorizationDenialSpike` | Prometheus | Someone probing document ids (IDOR scanning) |
| `LoginFailureSpike`, `RateLimitingActive` | Prometheus | Credential stuffing or a runaway client |
| `HighErrorRate`, `ApiDown`, ALB 5xx alarm | Prometheus, CloudWatch | Outage or bad release |
| `authz.denied`, `share.download_denied`, `auth.refresh_reuse_detected` rows | `audit_logs` | Per-organization evidence for the above |
| WAF blocked-request metrics | CloudWatch | Scanner traffic |

## Useful queries

Run as the database owner (the owner is not subject to row level security, so these see all tenants). Credentials: the RDS-managed secret in Secrets Manager.

```sql
-- what did one user do in the last 24 hours
SELECT timestamp, action, resource_type, resource_id, ip, details
FROM audit_logs WHERE user_id = '<user-uuid>' AND timestamp > now() - interval '24 hours' ORDER BY id;

-- everything that touched one document
SELECT timestamp, user_id, action, ip, details FROM audit_logs
WHERE resource_type = 'document' AND resource_id = '<doc-uuid>' ORDER BY id;

-- denied attempts per source address
SELECT ip, count(*) FROM audit_logs WHERE action IN ('authz.denied','auth.login_failed')
AND timestamp > now() - interval '1 hour' GROUP BY ip ORDER BY 2 DESC LIMIT 20;

-- anonymous downloads through a link
SELECT timestamp, ip, details FROM audit_logs WHERE action LIKE 'share.download%' AND details->>'link_id' = '<link-uuid>';
```

Correlate with application logs by `request_id` (every audit row carries it) and `trace_id`.

## Containment toolbox

| Goal | Action | Effect |
|---|---|---|
| Lock one user out now | `PATCH /api/v1/users/{id}` with `{"is_active": false}` as an org admin, or `UPDATE users SET is_active=false WHERE id=...` | Next request returns 401, even with a valid access token |
| Freeze a whole organization | `UPDATE organizations SET is_active=false WHERE id='...'` | All its tokens and share links stop working immediately |
| Kill refresh tokens everywhere | `redis-cli -a "$REDIS_PASSWORD" --scan --pattern 'refresh:*' \| xargs redis-cli -a "$REDIS_PASSWORD" del` | No session can refresh; access tokens die within 15 minutes |
| Kill every session | Rotate the JWT secret (playbook C) | All tokens invalid at once |
| Revoke a share link | `DELETE /api/v1/documents/{id}/share-links/{link_id}` | 410 from then on |
| Stop a noisy source | Add an IP set rule to the WAF ACL, or tighten `allowed_ingress_cidr` | Blocked before the app |
| Take the API out of rotation | Deregister the target in the ALB target group | Users get 503; data stores untouched |

## Playbooks

### A. Suspected cross-tenant data exposure (SEV1)

1. Contain: freeze the reporting and suspected organizations (above) if the path is unknown; otherwise deregister the instance from the ALB.
2. Scope: query `audit_logs` for `document.download`, `document.version_download` and `share.download` by the suspect user, and S3 server events from CloudTrail data events if enabled. Presigned URLs live 60 seconds, so object access after that window means a new authorization decision, which is in the audit trail.
3. Verify the isolation layers independently: run `pytest tests/test_tenant_isolation.py` against a copy of the production schema; check `SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname='docs_app'` is `f, f`; check policies exist with `SELECT tablename, policyname FROM pg_policies`.
4. Fix, add a regression test to `test_tenant_isolation.py`, deploy.
5. Notify affected tenants per your contractual and legal obligations (the audit rows list exactly which documents were accessed and from which address).

### B. Refresh token replay or account takeover (SEV2)

1. The replay already revoked that session family. Confirm with `auth.refresh_reuse_detected` rows (note `user_id`, `ip`, `details.family`).
2. Ask the user to change their password; deactivate and reactivate the account to force a clean state if needed.
3. Review what the user and the replaying address did (`audit_logs` by `user_id`). Revoke any share links and grants they created during the window.
4. If several users are affected, treat it as a possible secret or client compromise and continue with playbook C.

### C. Signing secret compromised (SEV1)

1. Rotate through Terraform so state and Secrets Manager agree (a value edited by hand would be overwritten by the next apply):
   `terraform apply -replace=module.compute.random_password.jwt -replace=module.compute.aws_instance.app`
   (from `infra/environments/dev`). The secret version is rewritten and the replacement instance reads it at boot.
2. Wait for the new target to pass ALB health checks; the old instance drains.
3. Flush the refresh-token keys in Redis so no stale family entries remain.
4. Result: every access and refresh token is invalid; all users log in again.
5. Find the leak (repository history, CI logs, instance access) and close it. For multi-service setups, move to `JWT_ALGORITHM=RS256`: the private key stays on the issuer and verifiers only need the public JWKS.

### D. Credential committed to git (SEV2)

1. Treat the credential as public. Rotate it first, rewrite history second.
2. Database owner or app password: change in RDS or Secrets Manager (`aws rds modify-db-instance --manage-master-user-password --rotate-master-user-password`; for `docs_app`, `terraform apply -replace=module.compute.random_password.app_db -replace=module.compute.aws_instance.app`, because boot runs `scripts/bootstrap_db_role.py`, which re-keys the role), then restart the service.
3. AWS access keys: deactivate and delete in IAM; review CloudTrail for use between commit and revocation.
4. gitleaks runs in CI on every push; find out why it did not block, and fix the rule or the workflow.

### E. Leaked share link (SEV2)

1. Revoke it (above). The link is hash-only in the database; match by `details.link_id` from the creation audit row.
2. Query `share.download` rows for that link to see who fetched the file and when.
3. If the content was sensitive, notify the owner and consider replacing the document version.

### F. Object storage misconfiguration (SEV1)

1. Re-apply Terraform to restore `block_public_acls`, `block_public_policy`, TLS-only and encryption-required policies (`terraform plan` shows the drift).
2. Check CloudTrail for `PutBucketPolicy`, `PutBucketAcl`, `DeletePublicAccessBlock` and who made the call.
3. Versioning is on: restore deleted or overwritten objects from previous versions; noncurrent versions are retained 90 days.

### G. Data loss or corruption

1. RDS: point-in-time restore to a new instance (backups are retained 7 days), verify, then repoint the service by changing the database secret and `db_host`.
2. S3: restore the previous object version. Each `document_versions` row stores the SHA-256 to validate the restored bytes.
3. Redis loss needs no restore: users sign in again.

### H. Denial of service

1. Confirm in WAF and `RateLimitingActive` which scope is hit (`login`, `user`, `public`).
2. Add the offending ranges to the WAF; enable `enable_waf` if it was off.
3. If the load is legitimate, raise `RATE_LIMIT_*` and scale: replace the instance type or add instances behind the ALB (the service is stateless).

## After the incident

Within five working days: a blameless write-up (timeline, impact, root cause, what worked), a regression test for the failing control, updated alert rules if detection was late, and updates to [threat-model.md](../threat-model.md) when a new threat or a weakened assumption was found.

## Routine checks

Quarterly: rotate the Redis AUTH token and the app secret by runbook, review IAM and security-group drift with `terraform plan`, restore a backup into a scratch instance and run the test suite against it, read the Dependabot and Trivy backlog.
