output "bucket_name" { value = aws_s3_bucket.docs.id }
output "bucket_arn" { value = aws_s3_bucket.docs.arn }
output "kms_key_arn" { value = aws_kms_key.this.arn }
