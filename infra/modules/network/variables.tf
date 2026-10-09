variable "name" { type = string }
variable "region" { type = string }
variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}
variable "az_count" {
  type    = number
  default = 2
}
variable "log_retention_days" {
  type    = number
  default = 30
}
variable "kms_key_arn" { type = string }
