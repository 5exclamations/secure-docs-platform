variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate for the public host name (must exist in the same region)."
}

variable "public_hostname" {
  type        = string
  description = "DNS name that will point at the ALB, e.g. docs.example.com."
}

variable "image_tag" {
  type        = string
  description = "Immutable tag of the image pushed to the ECR repository (for example a git SHA)."
}

variable "enable_elasticache" {
  type    = bool
  default = false
}

variable "enable_waf" {
  type    = bool
  default = false
}

variable "multi_az_database" {
  type    = bool
  default = false
}

variable "alert_email" {
  type    = string
  default = ""
}

variable "allowed_ingress_cidr" {
  type    = string
  default = "0.0.0.0/0"
}

variable "cors_origins" {
  type    = string
  default = ""
}

variable "protect_from_deletion" {
  type        = bool
  description = "Deletion protection on the database and ALB. Set false for throwaway dev stacks."
  default     = true
}
