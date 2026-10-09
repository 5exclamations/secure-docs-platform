variable "name" { type = string }
variable "kms_key_arn" { type = string }
variable "alb_arn_suffix" { type = string }
variable "target_group_arn_suffix" { type = string }
variable "instance_id" { type = string }
variable "db_identifier" { type = string }
variable "alert_email" {
  type    = string
  default = ""
}
