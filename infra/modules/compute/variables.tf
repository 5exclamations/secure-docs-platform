variable "name" { type = string }
variable "region" { type = string }
variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "app_subnet_ids" { type = list(string) }
variable "kms_key_arn" { type = string }
variable "bucket_name" { type = string }
variable "bucket_arn" { type = string }
variable "db_host" { type = string }
variable "db_master_secret_arn" { type = string }
variable "redis_endpoint" {
  type    = string
  default = ""
}
variable "redis_auth_secret_arn" {
  type    = string
  default = ""
}
variable "certificate_arn" { type = string }
variable "image_tag" { type = string }
variable "instance_type" {
  type    = string
  default = "t4g.small"
}
variable "allowed_ingress_cidr" {
  type        = string
  description = "CIDR allowed to reach the ALB. Narrow it for private deployments."
  default     = "0.0.0.0/0"
}
variable "cors_origins" {
  type    = string
  default = ""
}
variable "allowed_hosts" {
  type        = string
  description = "Public host name served by the ALB (used for Host header validation)."
}
variable "deletion_protection" {
  type    = bool
  default = true
}
variable "log_retention_days" {
  type    = number
  default = 30
}
