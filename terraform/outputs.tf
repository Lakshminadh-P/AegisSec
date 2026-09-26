# Outputs
output "secure_bucket_name" {
  description = "Name of the secure S3 bucket"
  value       = aws_s3_bucket.secure_bucket.id
}

output "insecure_bucket_name" {
  description = "Name of the insecure demo S3 bucket"
  value       = aws_s3_bucket.insecure_bucket.id
}
