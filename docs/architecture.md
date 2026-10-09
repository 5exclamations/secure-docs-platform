# Architecture

## System context

```mermaid
flowchart LR
  user([Browser / API client]) -->|HTTPS| alb[ALB + optional WAF]
  anon([Anonymous recipient]) -->|HTTPS share link| alb
  alb --> api[FastAPI service<br/>EC2 / docker]
  api -->|asyncpg, TLS, role docs_app| pg[(PostgreSQL 16<br/>RDS)]
  api -->|rediss, AUTH| redis[(Redis 7<br/>rate limits, refresh tokens)]
  api -->|upload, delete<br/>IAM role| s3[(S3 bucket<br/>SSE-KMS, versioned)]
  user -. "presigned GET, 60 s" .-> s3
  anon -. "presigned GET, 60 s" .-> s3
  api -->|OTLP| otel[OTel collector] --> traces[(Jaeger / X-Ray)]
  prom[Prometheus] -->|bearer token| api
  graf[Grafana] --> prom
```

File bytes never flow through the API on download: the API authorizes, writes an audit row, and returns a presigned URL that the client fetches directly from object storage. Uploads do pass through the API so that size limits, content sniffing and checksums are enforced before anything is stored.

## Local development stack

`docker compose up` starts PostgreSQL, Redis, MinIO (built from source, see `deploy/minio/Dockerfile`), a one-shot migration job, the API, an OpenTelemetry collector with Jaeger, Prometheus and Grafana. Everything binds to `127.0.0.1`. No cloud account is involved.

## AWS reference deployment

```mermaid
flowchart TB
  subgraph vpc[VPC 10.20.0.0/16, two AZs]
    subgraph pub[Public subnets]
      alb[ALB<br/>TLS 1.3 policy]
      nat[NAT gateway]
    end
    subgraph app[Private app subnets]
      ec2[EC2 t4g.small<br/>IMDSv2, no SSH, SSM only]
    end
    subgraph data[Private data subnets, no default route]
      rds[(RDS PostgreSQL)]
      ec[(ElastiCache Redis<br/>optional)]
    end
  end
  internet((Internet)) --> alb --> ec2
  ec2 --> rds
  ec2 --> ec
  ec2 --> nat --> internet
  ec2 -->|gateway endpoint| s3[(S3 + KMS CMK)]
  ec2 --> sm[Secrets Manager]
  ec2 --> ecr[ECR]
  ec2 --> cw[CloudWatch Logs]
```

Security groups form a chain: internet to ALB (443, 80 redirect), ALB to app (8000), app to RDS (5432) and Redis (6379). Nothing else is open. See [infrastructure.md](infrastructure.md) for resources, costs and accepted risks.

## Tenant isolation, four layers deep

1. **Application**: every query filters on `org_id` taken from the authenticated user, never from the request. Cross-tenant ids answer `404`, identical to a missing id, so identifiers cannot be enumerated.
2. **Schema**: child tables reference `(id, org_id)` pairs through composite foreign keys. A permission, version or share link cannot point at a parent or a user that belongs to a different organization, even for a superuser.
3. **Row level security**: `documents`, `document_versions`, `document_permissions`, `share_links` and `audit_logs` carry a policy `org_id = current_setting('app.org_id')`. The API sets that value with `set_config(..., is_local => true)` at the start of each transaction (a SQLAlchemy `after_begin` hook), so it can never leak across pooled connections. With no tenant bound the policy matches nothing. The runtime role is neither owner, superuser nor `BYPASSRLS`.
4. **Tokens**: the JWT carries `org_id`, and the server rejects a token whose claim differs from the user's stored organization.

## Authentication and sessions

```mermaid
sequenceDiagram
  participant C as Client
  participant A as API
  participant R as Redis
  participant D as PostgreSQL
  C->>A: POST /auth/login (email, password)
  A->>A: IP limit 5/min, per-account lockout check
  A->>D: load user, argon2id verify (dummy hash if unknown)
  A->>D: audit auth.login (same transaction)
  A->>R: SET refresh:{jti} = family (TTL 7d)
  A-->>C: access JWT (15 min) + refresh JWT
  C->>A: POST /auth/refresh (refresh JWT)
  A->>R: GETDEL refresh:{jti}
  alt token known
    A->>R: SET refresh:{new jti}
    A-->>C: new pair, same family
  else already used (replay)
    A->>R: SET revoked_fam:{family}
    A->>D: audit auth.refresh_reuse_detected
    A-->>C: 401, whole session family is dead
  end
```

Tokens are HS256 by default. Setting `JWT_ALGORITHM=RS256` signs with an RSA key, publishes `/.well-known/jwks.json` and `/.well-known/openid-configuration`, so another service can verify tokens without a shared secret. The verification algorithm is pinned server-side, so algorithm-confusion and `alg: none` tokens are refused (both are tested).

The service issues its own tokens; it is not an OIDC provider and does not federate to one. Adding an external IdP means validating its ID token in `get_current_user` and mapping the subject to a `users` row; the rest of the authorization path does not change.

## Authorization model

Effective rights on a document are the intersection of the caller's relationship to it and the ceiling of their role.

| Role | Ceiling | Relationship that grants access |
|---|---|---|
| admin | everything in own organization | automatic |
| editor | read, write, delete, share | owner, or an unexpired grant |
| viewer | read | owner, or an unexpired grant |

A `write` grant given to a viewer is capped to read by the role ceiling; demoting an owner immediately removes their write access. Grants carry an optional `expires_at` that is evaluated on every request, in SQL for listings and in Python for single documents.

## Upload and download flows

```mermaid
sequenceDiagram
  participant C as Client
  participant A as API
  participant S as Object store
  participant D as PostgreSQL
  C->>A: POST /documents (multipart)
  A->>A: stream to temp file, count bytes (413 over 50 MB), sha256
  A->>A: type allowlist + magic-byte check, sanitize filename
  A->>S: PUT {org}/{doc}/{random uuid}  (SSE-KMS)
  A->>D: BEGIN; lock document row; version = current + 1; INSERT version; audit; COMMIT
  Note over A,S: if the DB step fails the object is deleted
  C->>A: GET /documents/{id}/download
  A->>D: authorize, audit document.download
  A-->>C: presigned URL (60 s, attachment disposition, stored content type)
  C->>S: GET presigned URL
```

The row lock on the document is what makes concurrent uploads receive distinct, gap-free version numbers (found and fixed through the concurrency test).

## Share links

A share link is `{org_id_hex}.{256-bit random}`. Only the SHA-256 of the token is stored. The organization prefix lets the public endpoint bind the correct tenant for row level security before it looks anything up. Validity checks and the download counter are a single `UPDATE ... WHERE revoked_at IS NULL AND expires_at > now() AND download_count < max_downloads RETURNING`, so a link limited to N downloads yields exactly N under concurrency (25 parallel requests against a limit of 5 produce 5 successes in the test suite).

## Data model

```mermaid
erDiagram
  organizations ||--o{ users : has
  organizations ||--o{ documents : owns
  users ||--o{ documents : "owner (id, org_id)"
  documents ||--o{ document_versions : has
  documents ||--o{ document_permissions : "granted via"
  users ||--o{ document_permissions : grantee
  documents ||--o{ share_links : "exposed by"
  organizations ||--o{ audit_logs : records
  documents {
    uuid id PK
    uuid org_id
    uuid owner_id
    text title
    text description
    varchar_array tags
    int current_version
    timestamptz deleted_at
  }
  document_versions {
    uuid id PK
    int version
    text s3_key
    bigint size_bytes
    text checksum_sha256
  }
  share_links {
    uuid id PK
    text token_hash
    timestamptz expires_at
    int max_downloads
    int download_count
    timestamptz revoked_at
  }
  audit_logs {
    bigint id PK
    uuid org_id
    uuid user_id
    text action
    jsonb details
  }
```

## Observability

| Signal | Implementation |
|---|---|
| Logs | structlog JSON on stdout: request id, user id, organization id, trace id; secrets are redacted by key name |
| Metrics | `/metrics` (bearer-token protected, blocked at the ALB): request count and latency by route template, auth events, document events, authorization denials, rate-limit rejections |
| Traces | OpenTelemetry for FastAPI and SQLAlchemy, exported over OTLP; health and metrics endpoints excluded |
| Health | `/health` (liveness), `/health/ready` (PostgreSQL, Redis, bucket) |
| Alerts | Prometheus rules in `deploy/prometheus/alerts.yml`; CloudWatch alarms in `infra/modules/observability` |
