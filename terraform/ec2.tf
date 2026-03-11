# ── EC2 instance for the Cloud Security Agent ────────────────────────────────
# Optional: only created when var.deploy_ec2 = true

variable "deploy_ec2" {
  description = "Set to true to provision an EC2 instance for the dashboard + scanner"
  type        = bool
  default     = false
}

variable "ec2_instance_type" {
  description = "EC2 instance type (t3.small is enough for most accounts)"
  type        = string
  default     = "t3.small"
}

variable "ec2_allowed_cidr" {
  description = "CIDR allowed to access the dashboard on port 80. Defaults to your IP only — change to 0.0.0.0/0 to allow all."
  type        = string
  default     = "0.0.0.0/0"
}

variable "key_pair_name" {
  description = "EC2 key pair name for SSH access (must already exist in your account). Leave empty to skip SSH."
  type        = string
  default     = ""
}

# ── Latest Amazon Linux 2023 AMI ─────────────────────────────────────────────
data "aws_ami" "al2023" {
  count       = var.deploy_ec2 ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── Default VPC ───────────────────────────────────────────────────────────────
data "aws_vpc" "default" {
  count   = var.deploy_ec2 ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.deploy_ec2 ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }
}

# ── Security group ────────────────────────────────────────────────────────────
resource "aws_security_group" "agent" {
  count       = var.deploy_ec2 ? 1 : 0
  name        = "cloud-security-agent-sg"
  description = "Security group for Cloud Security Agent dashboard"
  vpc_id      = data.aws_vpc.default[0].id

  # Dashboard
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.ec2_allowed_cidr]
    description = "Dashboard HTTP"
  }

  # SSH (only if key pair specified)
  dynamic "ingress" {
    for_each = var.key_pair_name != "" ? [1] : []
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [var.ec2_allowed_cidr]
      description = "SSH"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = local.tags
}

# ── IAM instance profile ──────────────────────────────────────────────────────
resource "aws_iam_instance_profile" "agent" {
  count = var.deploy_ec2 ? 1 : 0
  name  = "CloudSecurityAgentProfile"
  role  = aws_iam_role.security_agent.name
}

# ── User data — installs Docker + clones repo + starts everything ─────────────
locals {
  user_data = <<-EOF
    #!/bin/bash
    set -e

    # System updates
    dnf update -y
    dnf install -y git docker

    # Start Docker
    systemctl enable docker
    systemctl start docker

    # Docker Compose v2
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
      -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

    # Clone repo
    cd /opt
    git clone https://github.com/cherrycolacoke/cloud-security-agent.git
    cd cloud-security-agent

    # Write .env from instance metadata / environment
    cat > .env << 'ENVFILE'
export PGHOST=postgres
export PGPORT=5432
export PGDATABASE=cloud_security
export PGUSER=secadmin
export PGPASSWORD=changeme
export AWS_DEFAULT_REGION=${var.aws_region}
export AWS_ACCOUNT_ID=${data.aws_caller_identity.current.account_id}
export BEDROCK_MODEL_ID=meta.llama3-70b-instruct-v1:0
ENVFILE

    # Start the stack
    docker compose up -d --build

    # Set up nightly scan cron (1am UTC)
    echo "0 1 * * * root cd /opt/cloud-security-agent && docker compose run --rm scanner >> /var/log/security-scan.log 2>&1" \
      > /etc/cron.d/cloud-security-agent
    chmod 644 /etc/cron.d/cloud-security-agent

    echo "Cloud Security Agent deployed successfully" > /var/log/agent-deploy.log
  EOF
}

# ── EC2 instance ──────────────────────────────────────────────────────────────
resource "aws_instance" "agent" {
  count                  = var.deploy_ec2 ? 1 : 0
  ami                    = data.aws_ami.al2023[0].id
  instance_type          = var.ec2_instance_type
  subnet_id              = data.aws_subnets.default[0].ids[0]
  vpc_security_group_ids = [aws_security_group.agent[0].id]
  iam_instance_profile   = aws_iam_instance_profile.agent[0].name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null

  user_data = local.user_data

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  tags = merge(local.tags, {
    Name = "cloud-security-agent"
  })
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "dashboard_url" {
  description = "Dashboard URL — open this in your browser (may take 2-3 min after apply)"
  value       = var.deploy_ec2 ? "http://${aws_instance.agent[0].public_ip}" : "EC2 not deployed (set deploy_ec2 = true)"
}

output "ec2_instance_id" {
  description = "EC2 instance ID"
  value       = var.deploy_ec2 ? aws_instance.agent[0].id : "N/A"
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = var.deploy_ec2 && var.key_pair_name != "" ? "ssh -i ~/.ssh/${var.key_pair_name}.pem ec2-user@${aws_instance.agent[0].public_ip}" : "No key pair configured"
}
