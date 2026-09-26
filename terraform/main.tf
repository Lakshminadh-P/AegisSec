# AegisSec — Terraform Infrastructure Example
#
# This demonstrates Infrastructure-as-Code (IaC) security scanning with Checkov.
# It defines example AWS resources with INTENTIONAL misconfigurations
# for Checkov to detect.
#
# ⚠️  This is a DEMO configuration — it will NOT provision real infrastructure
# unless you configure an AWS provider and run terraform apply.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Provider — NOT configured with real credentials
provider "aws" {
  region = var.aws_region
  
  # Skip credential validation for demo purposes
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# ============================================
# SECURE EXAMPLE — S3 Bucket with best practices
# ============================================
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "aegissec-secure-data-${var.environment}"
  
  tags = {
    Name        = "AegisSec Secure Bucket"
    Environment = var.environment
    Project     = "AegisSec"
    ManagedBy   = "Terraform"
  }
}

# Enable versioning (security best practice)
resource "aws_s3_bucket_versioning" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable access logging
resource "aws_s3_bucket_logging" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  target_bucket = aws_s3_bucket.secure_bucket.id
  target_prefix = "access-logs/"
}


# ============================================
# INSECURE EXAMPLE — Intentional misconfigurations
# Checkov will flag these issues
# ============================================

# INSECURE: S3 bucket WITHOUT encryption, versioning, or public access block
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "aegissec-insecure-demo-${var.environment}"
  
  tags = {
    Name      = "INSECURE DEMO BUCKET"
    Security  = "intentionally-misconfigured"
  }
}
# Checkov will detect:
# - CKV_AWS_145: S3 bucket encryption not configured
# - CKV_AWS_21: S3 bucket versioning not enabled
# - CKV_AWS_53: S3 bucket public access block not configured
# - CKV_AWS_18: S3 bucket access logging not enabled


# INSECURE: Security group with overly permissive rules
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-demo-sg"
  description = "INSECURE — intentionally overly permissive for demo"

  # INSECURE: Allows all inbound traffic from anywhere
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Checkov: CKV_AWS_260
    description = "INSECURE: All TCP ports open to the world"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name     = "INSECURE DEMO SG"
    Security = "intentionally-misconfigured"
  }
}
