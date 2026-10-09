output "alb_dns_name" {
  description = "Point the public host name (CNAME/ALIAS) at this."
  value       = module.compute.alb_dns_name
}

output "ecr_repository_url" {
  description = "Push the application image here before the first apply."
  value       = module.compute.ecr_repository_url
}

output "bucket_name" {
  value = module.storage.bucket_name
}

output "instance_id" {
  description = "Connect with: aws ssm start-session --target <id>"
  value       = module.compute.instance_id
}
