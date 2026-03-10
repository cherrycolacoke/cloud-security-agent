variable "aws_region" {
  description = "AWS region to deploy resources in"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use for authentication"
  type        = string
  default     = "default"
}

variable "environment" {
  description = "Environment name (e.g. production, staging, dev)"
  type        = string
  default     = "production"
}

variable "external_id" {
  description = "Optional STS ExternalId for cross-account role assumption (leave empty if not needed)"
  type        = string
  default     = ""
  sensitive   = true
}
