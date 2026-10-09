# Optional ElastiCache Redis. Redis holds only rate-limit counters and the refresh-token
# allowlist, so losing it logs everyone out but loses no documents.
resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name}-redis"
  subnet_ids = var.subnet_ids
}

resource "aws_security_group" "redis" {
  name_prefix = "${var.name}-redis-"
  description = "Redis from the application tier only"
  vpc_id      = var.vpc_id
  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "from_app" {
  security_group_id            = aws_security_group.redis.id
  description                  = "Redis TLS from app tier"
  referenced_security_group_id = var.app_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
}

resource "random_password" "auth" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "auth" {
  #checkov:skip=CKV2_AWS_57:ElastiCache AUTH tokens cannot be rotated without a maintenance window; rotate through the runbook.
  name_prefix             = "${var.name}/redis-auth-"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "auth" {
  secret_id     = aws_secretsmanager_secret.auth.id
  secret_string = random_password.auth.result
}

resource "aws_elasticache_replication_group" "this" {
  #checkov:skip=CKV2_AWS_50:Single node on purpose: Redis only holds rate-limit counters and refresh-token allowlist entries.
  replication_group_id       = "${var.name}-redis"
  description                = "${var.name} rate limiting and token store"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.node_type
  num_cache_clusters         = 1
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = [aws_security_group.redis.id]
  at_rest_encryption_enabled = true
  kms_key_id                 = var.kms_key_arn
  transit_encryption_enabled = true
  auth_token                 = random_password.auth.result
  automatic_failover_enabled = false
  snapshot_retention_limit   = 0
}
