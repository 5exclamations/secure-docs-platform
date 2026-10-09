variable "name" { type = string }
variable "region" { type = string }
variable "force_destroy" {
  type    = bool
  default = false
}
variable "noncurrent_version_days" {
  type    = number
  default = 90
}
