output "alb_dns_name" { value = aws_lb.this.dns_name }
output "alb_arn_suffix" { value = aws_lb.this.arn_suffix }
output "target_group_arn_suffix" { value = aws_lb_target_group.api.arn_suffix }
output "app_security_group_id" { value = aws_security_group.app.id }
output "instance_id" { value = aws_instance.app.id }
output "ecr_repository_url" { value = aws_ecr_repository.api.repository_url }
output "alb_arn" { value = aws_lb.this.arn }
