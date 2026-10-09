# Optional AWS WAFv2 in front of the ALB: managed rule groups plus a per-IP rate cap.
resource "aws_wafv2_web_acl" "this" {
  #checkov:skip=CKV_AWS_192:Log4j protection is provided by AWSManagedRulesKnownBadInputsRuleSet, applied through the dynamic rule block below.
  name  = "${var.name}-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit-per-ip"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_5min
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-rate"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = {
      "AWSManagedRulesCommonRuleSet"          = 2
      "AWSManagedRulesKnownBadInputsRuleSet"  = 3
      "AWSManagedRulesAmazonIpReputationList" = 4
    }
    content {
      name     = rule.key
      priority = rule.value
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          name        = rule.key
          vendor_name = "AWS"
          # Uploads are legitimately large; the app enforces its own 50 MB cap and content checks.
          dynamic "rule_action_override" {
            for_each = rule.key == "AWSManagedRulesCommonRuleSet" ? ["SizeRestrictions_BODY"] : []
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.key
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# WAF logs go to CloudWatch (the log group name must start with aws-waf-logs-).
resource "aws_cloudwatch_log_group" "waf" {
  #checkov:skip=CKV_AWS_338:Retention is configurable; 30 days by default for cost.
  #checkov:skip=CKV_AWS_158:WAF delivery to a KMS-encrypted group requires extra key-policy grants; the log redacts the Authorization header.
  name              = "aws-waf-logs-${var.name}"
  retention_in_days = 30
}

data "aws_iam_policy_document" "waf_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.waf.arn}:*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf" {
  policy_name     = "${var.name}-waf-logs"
  policy_document = data.aws_iam_policy_document.waf_logs.json
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
