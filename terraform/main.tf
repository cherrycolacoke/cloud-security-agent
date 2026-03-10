terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

# ── Data ──────────────────────────────────────────────────────────────────────
data "aws_caller_identity" "current" {}

# ── IAM Role for the Security Agent ──────────────────────────────────────────
resource "aws_iam_role" "security_agent" {
  name        = "CloudSecurityAgentRole"
  description = "Role used by the AI Cloud Security Agent to scan this account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Allow the role to be assumed by EC2 (if running on an instance)
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        # Allow cross-account assumption from a trusted account (optional)
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = var.external_id != "" ? {
          StringEquals = { "sts:ExternalId" = var.external_id }
        } : {}
      }
    ]
  })

  tags = local.tags
}

# ── Attach AWS managed SecurityAudit policy ───────────────────────────────────
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.security_agent.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# ── Attach ReadOnlyAccess for Steampipe inventory queries ─────────────────────
resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.security_agent.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ── Inline policy: SSM (Trivy scans) + Bedrock (LLM) + S3 results ─────────────
resource "aws_iam_role_policy" "agent_extras" {
  name = "CloudSecurityAgentExtras"
  role = aws_iam_role.security_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMForTrivyScans"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceInformation",
          "ssm:ListCommandInvocations"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ForTrivyResults"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.trivy_results.arn,
          "${aws_s3_bucket.trivy_results.arn}/*"
        ]
      },
      {
        Sid    = "BedrockForLLMAgent"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── S3 bucket for Trivy scan results ─────────────────────────────────────────
resource "aws_s3_bucket" "trivy_results" {
  bucket        = "cloud-sec-agent-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "trivy_results" {
  bucket                  = aws_s3_bucket.trivy_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trivy_results" {
  bucket = aws_s3_bucket.trivy_results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trivy_results" {
  bucket = aws_s3_bucket.trivy_results.id
  rule {
    id     = "expire-old-results"
    status = "Enabled"
    expiration {
      days = 30
    }
  }
}

# ── Locals ────────────────────────────────────────────────────────────────────
locals {
  tags = {
    Project     = "cloud-security-agent"
    ManagedBy   = "terraform"
    Environment = var.environment
  }
}
