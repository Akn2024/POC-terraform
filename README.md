# POC-terraform

Approach
Modular Structure: Organize the Terraform code into modules for VPC, compute, S3/CloudFront, IAM, and SCPs.
Best Practices: Use variables for reusability, enable encryption, and follow AWS security recommendations.
Scope: Cover the key components specified (VPC, EC2, ALB, S3, CloudFront, IAM, SCPs, KMS).
Assumptions:
Deploying in us-east-1 for the OU-Prod restriction.
Using a pre-existing domain in Route 53 (yourdomain.com).
Simplifying some configurations (e.g., WAF rules, detailed SCPs) for brevity while ensuring functionality.
Excluding the admin portal and analytics tools deployment details, focusing on infrastructure.
Below is the Terraform template, wrapped in an <xaiArtifact> tag as requested, with a single main.tf file for simplicity. In a real-world scenario, you’d split this into multiple files/modules (e.g., vpc.tf, compute.tf, iam.tf), but I’ll combine them here for clarity and conciseness.

main.tf
x-terraform
Show inline
Explanation and Guidance
This Terraform template sets up the infrastructure as specified. Below is a breakdown of the components and how to use the template:

VPC Setup:
Two VPCs (app-vpc and data-vpc) are created using the terraform-aws-modules/vpc module for simplicity and best practices.
Each VPC has public and private subnets across two AZs (us-east-1a, us-east-1b).
NAT Gateways are deployed in public subnets for private subnet internet access (single NAT for cost optimization).
VPC peering is established with route table updates for secure communication between VPCs.
Compute and Load Balancing:
An Auto Scaling Group (ASG) deploys EC2 instances in private subnets using a launch template.
The launch template includes KMS-encrypted EBS volumes and a basic user data script (placeholder for your Node.js/Python app).
CPU-based scaling policy targets 70% utilization.
An ALB is placed in public subnets, listening on HTTPS (port 443) with an ACM certificate, forwarding traffic to the ASG.
S3 Static Site and CloudFront:
An S3 bucket hosts the static landing site (landing.yourdomain.com) with versioning and KMS encryption.
Lifecycle rules transition objects to Infrequent Access (30 days), Glacier (90 days), and expire after 365 days.
CloudFront serves the S3 content with HTTPS-only access and an ACM certificate.
A WAF with AWS Managed Rules protects against SQLi and XSS.
ACM and Route 53:
ACM certificates are created for app.yourdomain.com and landing.yourdomain.com.
Route 53 records include alias records for the ALB and CloudFront, plus DNS validation for ACM.
IAM Policies:
Five custom IAM policies are defined as specified:
EC2 read-only for the Dev team.
S3 access to the landing bucket with encryption enforcement.
Deny CloudTrail log deletion.
Allow EC2 start/stop but not terminate.
Restrict KMS key usage to app-vpc.
Policies are JSON-encoded and attached to resources as needed.
KMS Encryption:
A single KMS key is used for S3, EBS, RDS (not implemented here), and CloudTrail encryption.
The KMS policy restricts usage to app-vpc for specific actions.
AWS Organizations and SCPs:
An organization is created with two OUs: OU-Prod and OU-Dev.
SCPs enforce:
Region restriction to us-east-1 for OU-Prod.
Deny SageMaker access for OU-Dev.
Deny unencrypted S3 object uploads organization-wide.
CloudTrail:
A CloudTrail trail logs to an encrypted S3 bucket with KMS.
How to Use the Template
Prerequisites:
Install Terraform (>= 1.5.0).
Configure AWS CLI with credentials (aws configure).
Own a domain in Route 53 (yourdomain.com) or update the domain_name variable.
Directory Structure:
text

Copy
project/
└── main.tf
Save the provided main.tf in the project directory.
Initialize Terraform:
bash

Copy
cd project
terraform init
Customize Variables:
Update var.domain_name to your actual domain.
Modify var.region if needed (though SCP restricts to us-east-1 for prod).
Add your application deployment logic in the user_data script of the launch template.
Plan and Apply:
bash

Copy
terraform plan -out=tfplan
terraform apply tfplan
Outputs: Add outputs to retrieve key information, e.g.:
hcl

Copy
output "alb_dns_name" {
  value = aws_lb.app.dns_name
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.landing.domain_name
}
Next Steps:
Deploy your React SPA to the ALB target group (e.g., via CodeDeploy or CI/CD).
Upload static content to the S3 bucket for the landing site.
Configure RDS in the data-vpc private subnets (not included here for brevity).
Test WAF rules and scaling policies under load.
Notes
RDS and Analytics Tools: Omitted for brevity. You can add an RDS instance in data-vpc private subnets with KMS encryption and a read replica.
Cost Optimization: Uses single NAT Gateway, t3.micro instances, and lifecycle rules. Monitor usage with AWS Cost Explorer.
Security: Enforces HTTPS, KMS encryption, and WAF. Consider adding AWS Shield for DDoS protection.
Extensibility: Split into modules (e.g., modules/vpc, modules/compute) for larger projects.
This template provides a solid foundation for your e-commerce platform. Let me know if you need help with specific components, such as RDS setup, CI/CD integration, or additional SCPs!
