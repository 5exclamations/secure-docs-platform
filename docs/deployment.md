# Deployment

## Local (no cloud account)

Requirements: Docker with the Compose plugin.

```bash
make secrets          # writes .env with random secrets and .secrets/metrics_token (both git-ignored)
docker compose up --build -d
curl localhost:8000/health/ready
python scripts/demo.py --base-url http://localhost:8000
```

| URL | What |
|---|---|
| http://localhost:8000/docs | Swagger UI (OAuth2 "Authorize" uses `/api/v1/auth/token`) |
| http://localhost:9001 | MinIO console (credentials in `.env`) |
| http://localhost:9090 | Prometheus |
| http://localhost:3000 | Grafana (admin password in `.env`), dashboard "Secure Docs API" |
| http://localhost:16686 | Jaeger traces |

The first build compiles MinIO from source (a few minutes) because the project no longer publishes container images. If you have access to a MinIO image you trust, replace the `build:` entry of the `minio` service with `image:`.

Tear down with `docker compose down -v`.

### Without Docker

`TEST_S3=minio MINIO_BIN=/path/to/minio python scripts/local_stack.py` starts throwaway PostgreSQL, Redis, MinIO (or moto when `MINIO_BIN` is unset) and the API on port 8000. It needs the PostgreSQL and Redis server binaries on the machine.

### Running the tests

```bash
make venv && make lint typecheck test
```

The integration tests start their own PostgreSQL, Redis and S3 server when the binaries exist, or use `TEST_DATABASE_OWNER_URL`, `TEST_DATABASE_APP_URL` and `TEST_REDIS_URL` (as CI does). `TEST_S3=minio MINIO_BIN=...` runs them against real MinIO, which additionally verifies presigned URL expiry.

## AWS

Prerequisites: AWS credentials with rights to create the resources in [infrastructure.md](infrastructure.md), Terraform 1.6+, Docker, an ACM certificate in the target region for your host name.

1. **Bootstrap state.** Create a versioned, encrypted S3 bucket for state and enable the `backend "s3"` block in `infra/environments/dev/versions.tf`.
2. **Create the registry first.**
   ```bash
   cd infra/environments/dev
   cp terraform.tfvars.example terraform.tfvars   # edit: certificate_arn, public_hostname, image_tag
   terraform init
   terraform apply -target=module.compute.aws_ecr_repository.api
   ```
3. **Build and push the image** with an immutable tag (the git SHA):
   ```bash
   REPO=$(terraform output -raw ecr_repository_url)
   aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%%/*}"
   docker build -t "$REPO:$(git rev-parse HEAD)" ../../.. && docker push "$REPO:$(git rev-parse HEAD)"
   ```
4. **Apply everything** with `image_tag` set to that SHA: `terraform apply`. On first boot the instance pulls the image, creates the unprivileged `docs_app` role (`scripts/bootstrap_db_role.py`), runs `alembic upgrade head` as the owner, and starts the service under systemd.
5. **DNS.** Point your host name at the `alb_dns_name` output (ALIAS or CNAME).
6. **Verify.** `curl https://<host>/health/ready`, then register an organization through the API. Use `aws ssm start-session --target <instance_id>` for shell access; there is no SSH.

Rolling out a new version: push a new immutable tag, change `image_tag`, apply. `user_data_replace_on_change` replaces the instance (the ALB drains the old target). Database migrations run on every boot and are idempotent; make them backward compatible so a rollback to the previous image keeps working.

Set `enable_waf = true` and `enable_elasticache = true` for a production-shaped stack, and `protect_from_deletion = false` only for throwaway environments (it also lets Terraform empty and delete the bucket).

## What has and has not been exercised

| Path | Status |
|---|---|
| Application, migrations, RLS, share links, concurrency | Tested against real PostgreSQL 16 and Redis; S3 through moto and through a MinIO server built from source |
| `scripts/local_stack.py` plus `scripts/demo.py` | Run end to end locally (output in `docs/demo-output.txt`) |
| Terraform | `fmt`, `validate`, Checkov. Never planned or applied |
| `docker compose up`, the Dockerfile, `minio` source build inside Docker | `docker compose config` validates the file; images were not built because no Docker daemon was available in the sandbox |
| GitHub Actions workflows | YAML parsed; not executed |
| EC2 user-data boot script | Reviewed only |
