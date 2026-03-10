output "account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "role_arn" {
  description = "IAM Role ARN — paste this into accounts.yaml as role_arn"
  value       = aws_iam_role.security_agent.arn
}

output "s3_bucket" {
  description = "S3 bucket name for Trivy results — already configured in the agent"
  value       = aws_s3_bucket.trivy_results.bucket
}

output "region" {
  description = "AWS region"
  value       = var.aws_region
}

output "next_steps" {
  description = "What to do after terraform apply"
  value       = <<-EOT

    ✅ Infrastructure created! Add this to your accounts.yaml:

    accounts:
      - id: "${data.aws_caller_identity.current.account_id}"
        name: my-account
        region: "${var.aws_region}"
        role_arn: "${aws_iam_role.security_agent.arn}"

    Then run:
      python3 account_manager.py --verify
      python3 run_full_scan.py
  EOT
}
