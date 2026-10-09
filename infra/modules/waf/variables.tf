variable "name" { type = string }
variable "alb_arn" { type = string }
variable "rate_limit_per_5min" {
  type    = number
  default = 2000
}
