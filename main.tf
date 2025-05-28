# Provider Configuration
provider "aws" {
  region = var.region
}

# Variables
variable "region" {
  default = "us-east-1"
}

variable "domain_name" {
  default = "yourdomain.com"
}

variable "app_subdomain" {
  default = "app"
}

variable "landing_subdomain" {
  default = "landing"
}

variable "cidr_vpc1" {
  default = "10.0.0.0/16"
}

variable "cidr_vpc2" {
  default = "10.1.0.0/16"
}

# VPC-1 (App Tier)
module "vpc_app" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "app-vpc"
  cidr = var.cidr_vpc1

  azs             = ["${var.region}a", "${var.region}b"]
  public_subnets  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnets = ["10.0.3.0/24", "10.0.4.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true # Cost optimization
  enable_vpn_gateway = false

  tags = {
    Environment = "Production"
  }
}

# VPC-2 (Data/Analytics)
module "vpc_data" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "data-vpc"
  cidr = var.cidr_vpc2

  azs             = ["${var.region}a", "${var.region}b"]
  public_subnets  = ["10.1.1.0/24", "10.1.2.0/24"]
  private_subnets = ["10.1.3.0/24", "10.1.4.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true
  enable_vpn_gateway = false

  tags = {
    Environment = "Production"
  }
}

# VPC Peering
resource "aws_vpc_peering_connection" "app_to_data" {
  vpc_id        = module.vpc_app.vpc_id
  peer_vpc_id   = module.vpc_data.vpc_id
  auto_accept   = true

  tags = {
    Name = "app-data-peering"
  }
}

# Update Route Tables for Peering
resource "aws_route" "app_to_data" {
  route_table_id         = module.vpc_app.private_route_table_ids[0]
  destination_cidr_block = module.vpc_data.vpc_cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.app_to_data.id
}

resource "aws_route" "data_to_app" {
  route_table_id         = module.vpc_data.private_route_table_ids[0]
  destination_cidr_block = module.vpc_app.vpc_cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.app_to_data.id
}

# KMS Key for Encryption
resource "aws_kms_key" "ecommerce_key" {
  description             = "KMS key for e-commerce platform"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action = "kms:*"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = module.vpc_app.vpc_id
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "ecommerce_key_alias" {
  name          = "alias/ecommerce-key"
  target_key_id = aws_kms_key.ecommerce_key.key_id
}

# EC2 Auto Scaling Group
resource "aws_launch_template" "app" {
  name_prefix   = "app-server-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  network_interfaces {
    associate_public_ip_address = false
    subnet_id                   = module.vpc_app.private_subnets[0]
    security_groups             = [aws_security_group.app.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 20
      encrypted   = true
      kms_key_id  = aws_kms_key.ecommerce_key.arn
    }
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              echo "Starting Node.js app..."
              # Placeholder for app deployment
              EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "app-server"
    }
  }
}

resource "aws_autoscaling_group" "app" {
  desired_capacity = 2
  min_size         = 1
  max_size         = 4
  vpc_zone_identifier = module.vpc_app.private_subnets

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.app.arn]

  health_check_type = "EC2"
  health_check_grace_period = 300

  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }
}

# Auto Scaling Policy
resource "aws_autoscaling_policy" "cpu_based" {
  name                   = "cpu-scaling"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Application Load Balancer
resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc_app.public_subnets

  enable_deletion_protection = true

  tags = {
    Environment = "Production"
  }
}

resource "aws_lb_target_group" "app" {
  name     = "app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_app.vpc_id

  health_check {
    path                = "/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.app.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Security Groups
resource "aws_security_group" "alb" {
  name_prefix = "alb-"
  vpc_id      = module.vpc_app.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name_prefix = "app-"
  vpc_id      = module.vpc_app.vpc_id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ACM Certificate
resource "aws_acm_certificate" "app" {
  domain_name       = "${var.app_subdomain}.${var.domain_name}"
  validation_method = "DNS"

  tags = {
    Environment = "Production"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "app_validation" {
  for_each = {
    for dvo in aws_acm_certificate.app.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      value  = dvo.resource_record_value
    }
  }

  zone_id = data.aws_route53_zone.main.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.value]
}

resource "aws_acm_certificate_validation" "app" {
  certificate_arn         = aws_acm_certificate.app.arn
  validation_record_fqdns = [for record in aws_route53_record.app_validation : record.fqdn]
}

# Route 53
data "aws_route53_zone" "main" {
  name = var.domain_name
}

resource "aws_route53_record" "app" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${var.app_subdomain}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.app.dns_name
    zone_id                = aws_lb.app.zone_id
    evaluate_target_health = true
  }
}

# S3 Static Website
resource "aws_s3_bucket" "landing" {
  bucket = "${var.landing_subdomain}.${var.domain_name}"

  tags = {
    Environment = "Production"
  }
}

resource "aws_s3_bucket_website_configuration" "landing" {
  bucket = aws_s3_bucket.landing.bucket

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

resource "aws_s3_bucket_versioning" "landing" {
  bucket = aws_s3_bucket.landing.bucket
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "landing" {
  bucket = aws_s3_bucket.landing.bucket

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.ecommerce_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "landing" {
  bucket = aws_s3_bucket.landing.bucket

  rule {
    id     = "transition-and-expire"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "landing" {
  bucket = aws_s3_bucket.landing.bucket

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.landing.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = aws_cloudfront_distribution.landing.arn
          }
        }
      }
    ]
  })
}

# CloudFront for S3
resource "aws_cloudfront_distribution" "landing" {
  origin {
    domain_name = aws_s3_bucket.landing.bucket_regional_domain_name
    origin_id   = "S3-landing"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.landing.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-landing"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "https-only"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.landing.arn
    ssl_support_method  = "sni-only"
  }

  web_acl_id = aws_wafv2_web_acl.landing.arn

  tags = {
    Environment = "Production"
  }
}

resource "aws_cloudfront_origin_access_identity" "landing" {
  comment = "OAI for landing site"
}

resource "aws_acm_certificate" "landing" {
  domain_name       = "${var.landing_subdomain}.${var.domain_name}"
  validation_method = "DNS"

  tags = {
    Environment = "Production"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "landing_validation" {
  for_each = {
    for dvo in aws_acm_certificate.landing.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      value  = dvo.resource_record_value
    }
  }

  zone_id = data.aws_route53_zone.main.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.value]
}

resource "aws_acm_certificate_validation" "landing" {
  certificate_arn         = aws_acm_certificate.landing.arn
  validation_record_fqdns = [for record in aws_route53_record.landing_validation : record.fqdn]
}

resource "aws_route53_record" "landing" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${var.landing_subdomain}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.landing.domain_name
    zone_id                = aws_cloudfront_distribution.landing.hosted_zone_id
    evaluate_target_health = false
  }
}

# WAF for CloudFront
resource "aws_wafv2_web_acl" "landing" {
  name  = "landing-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "landingCommonRules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "landingWAF"
    sampled_requests_enabled   = true
  }
}

# IAM Policies
resource "aws_iam_policy" "ec2_read_only" {
  name        = "EC2ReadOnlyDev"
  description = "Read-only access to EC2 for Dev team"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "ec2:Describe*",
          "ec2:Get*",
          "ec2:List*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "s3_bucket_access" {
  name        = "S3BucketAccess"
  description = "Access to specific S3 bucket with encryption"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.landing.arn,
          "${aws_s3_bucket.landing.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "deny_cloudtrail_delete" {
  name        = "DenyCloudTrailDelete"
  description = "Deny deletion of CloudTrail logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = "cloudtrail:DeleteTrail"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "ec2_start_stop" {
  name        = "EC2StartStop"
  description = "Allow start/stop of EC2 instances"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "ec2:StartInstances",
          "ec2:StopInstances"
        ]
        Resource = "*"
      },
      {
        Effect   = "Deny"
        Action   = "ec2:TerminateInstances"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "kms_vpc_restrict" {
  name        = "KMSVPCRestrict"
  description = "Restrict KMS key usage to specific VPC"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.ecommerce_key.arn
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = module.vpc_app.vpc_id
          }
        }
      }
    ]
  })
}

# CloudTrail
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "ecommerce-cloudtrail-logs"

  tags = {
    Environment = "Production"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.bucket

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.ecommerce_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_cloudtrail" "ecommerce" {
  name                          = "ecommerce-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  kms_key_id = aws_kms_key.ecommerce_key.arn
}

# AWS Organizations and SCPs
resource "aws_organizations_organization" "ecommerce" {
  aws_service_access_principals = ["cloudtrail.amazonaws.com"]
  feature_set                   = "ALL"
}

resource "aws_organizations_organizational_unit" "prod" {
  name      = "OU-Prod"
  parent_id = aws_organizations_organization.ecommerce.roots[0].id
}

resource "aws_organizations_organizational_unit" "dev" {
  name      = "OU-Dev"
  parent_id = aws_organizations_organization.ecommerce.roots[0].id
}

resource "aws_organizations_policy" "restrict_region" {
  name = "RestrictRegion"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = var.region
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy" "restrict_dev_services" {
  name = "RestrictDevServices"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = "sagemaker:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy" "restrict_unencrypted_s3" {
  name = "RestrictUnencryptedS3"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "*"
        Condition = {
          "Null" = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "prod_restrict_region" {
  policy_id = aws_organizations_policy.restrict_region.id
  target_id = aws_organizations_organizational_unit.prod.id
}

resource "aws_organizations_policy_attachment" "dev_restrict_services" {
  policy_id = aws_organizations_policy.restrict_dev_services.id
  target_id = aws_organizations_organizational_unit.dev.id
}

resource "aws_organizations_policy_attachment" "restrict_s3" {
  policy_id = aws_organizations_policy.restrict_unencrypted_s3.id
  target_id = aws_organizations_organization.ecommerce.roots[0].id
}

# Data Sources
data "aws_caller_identity" "current" {}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}
