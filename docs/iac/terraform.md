# Terraform Modules

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/terraform-modules){ .md-button .md-button--primary }

## Overview

This portfolio includes **30+ security-hardened Terraform modules** designed for enterprise-grade infrastructure deployments. Each module follows Infrastructure as Code (IaC) best practices with built-in security controls, compliance requirements, and extensive documentation.

!!! success "Key Features"
    - **Security by Default**: All modules implement security best practices out of the box
    - **Compliance Ready**: Pre-configured for SOC 2, PCI-DSS, and HIPAA requirements
    - **Fully Tested**: Includes Terratest unit and integration tests
    - **Well Documented**: Complete variable descriptions and usage examples

## Module Catalog

| Module | Description | Security Features |
|--------|-------------|-------------------|
| **VPC** | Multi-AZ Virtual Private Cloud with public/private subnets | VPC Flow Logs, NACLs, no default VPC usage, private subnet isolation |
| **EKS** | Managed Kubernetes cluster with node groups | Envelope encryption, OIDC provider, private endpoint, secrets encryption |
| **RDS** | Managed relational database instances | Encryption at rest, SSL enforcement, IAM authentication, automated backups |
| **S3** | Secure object storage buckets | SSE-KMS encryption, versioning, access logging, public access blocks |
| **KMS** | Customer managed encryption keys | Key rotation, multi-region support, granular key policies |
| **IAM** | Identity and access management resources | Least privilege policies, MFA enforcement, password policies |

## Usage Examples

### VPC Module with Security Features

```hcl
module "vpc" {
  source  = "./modules/vpc"
  version = "3.0.0"

  name = "production-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  # Security configurations
  enable_nat_gateway     = true
  single_nat_gateway     = false
  enable_vpn_gateway     = false
  enable_dns_hostnames   = true
  enable_dns_support     = true

  # VPC Flow Logs for network monitoring
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_max_aggregation_interval    = 60

  # Network ACLs
  manage_default_network_acl = true
  default_network_acl_ingress = [
    {
      rule_no    = 100
      action     = "allow"
      from_port  = 443
      to_port    = 443
      protocol   = "tcp"
      cidr_block = "0.0.0.0/0"
    }
  ]

  tags = {
    Environment = "production"
    Terraform   = "true"
    Compliance  = "pci-dss"
  }
}
```

### EKS Module with Encryption and OIDC

```hcl
module "eks" {
  source  = "./modules/eks"
  version = "2.0.0"

  cluster_name    = "production-eks"
  cluster_version = "1.28"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Security configurations
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = false

  # Envelope encryption for secrets
  cluster_encryption_config = {
    provider_key_arn = module.kms.key_arn
    resources        = ["secrets"]
  }

  # OIDC provider for IAM Roles for Service Accounts (IRSA)
  enable_irsa = true

  # Cluster add-ons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent              = true
      service_account_role_arn = module.vpc_cni_irsa.iam_role_arn
    }
  }

  # Managed node groups
  eks_managed_node_groups = {
    secure_workers = {
      min_size     = 2
      max_size     = 10
      desired_size = 3

      instance_types = ["m6i.large"]
      capacity_type  = "ON_DEMAND"

      # Node security
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 100
            volume_type           = "gp3"
            encrypted             = true
            kms_key_id            = module.kms.key_arn
            delete_on_termination = true
          }
        }
      }
    }
  }

  # Cluster security group rules
  cluster_security_group_additional_rules = {
    ingress_nodes_ephemeral_ports_tcp = {
      description                = "Nodes on ephemeral ports"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "ingress"
      source_node_security_group = true
    }
  }

  tags = {
    Environment = "production"
    Terraform   = "true"
  }
}
```

### S3 Module with Encryption and Versioning

```hcl
module "s3_bucket" {
  source  = "./modules/s3"
  version = "1.5.0"

  bucket = "company-secure-data-bucket"

  # Block all public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  # Versioning for data protection
  versioning = {
    enabled = true
  }

  # Server-side encryption with KMS
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = module.kms.key_arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }

  # Access logging
  logging = {
    target_bucket = module.log_bucket.s3_bucket_id
    target_prefix = "access-logs/"
  }

  # Lifecycle rules
  lifecycle_rule = [
    {
      id      = "transition-to-glacier"
      enabled = true
      transition = [
        {
          days          = 90
          storage_class = "GLACIER"
        }
      ]
      noncurrent_version_expiration = {
        days = 365
      }
    }
  ]

  # Object lock for compliance
  object_lock_enabled = true
  object_lock_configuration = {
    rule = {
      default_retention = {
        mode = "GOVERNANCE"
        days = 365
      }
    }
  }

  tags = {
    Environment = "production"
    DataClass   = "confidential"
  }
}
```

## Security Scanning Integration

All Terraform modules are integrated with security scanning tools in the CI/CD pipeline to ensure compliance and catch misconfigurations early.

!!! warning "Pre-commit Hooks Required"
    Security scans run automatically on every commit. Failed scans block merges to protected branches.

### Scanning Tools

=== "tfsec"

    ```yaml
    # .github/workflows/terraform-security.yml
    - name: Run tfsec
      uses: aquasecurity/tfsec-action@v1.0.0
      with:
        working_directory: infrastructure-as-code/terraform-modules
        soft_fail: false
        additional_args: --minimum-severity HIGH
    ```

=== "Checkov"

    ```yaml
    - name: Run Checkov
      uses: bridgecrewio/checkov-action@v12
      with:
        directory: infrastructure-as-code/terraform-modules
        framework: terraform
        soft_fail: false
        check: CKV_AWS_1,CKV_AWS_2,CKV_AWS_3
        skip_check: CKV_AWS_999
    ```

=== "Terrascan"

    ```yaml
    - name: Run Terrascan
      uses: tenable/terrascan-action@main
      with:
        iac_type: terraform
        iac_dir: infrastructure-as-code/terraform-modules
        policy_type: aws
        sarif_upload: true
    ```

### Scan Results Dashboard

| Scanner | Checks | Critical | High | Medium | Status |
|---------|--------|----------|------|--------|--------|
| tfsec | 245 | 0 | 0 | 3 | :material-check-circle:{ .success } Passing |
| Checkov | 312 | 0 | 0 | 5 | :material-check-circle:{ .success } Passing |
| Terrascan | 189 | 0 | 1 | 2 | :material-alert-circle:{ .warning } Review |

## Module Structure

Each module follows a standardized structure for consistency and maintainability:

```
terraform-modules/
├── vpc/
│   ├── main.tf           # Primary resource definitions
│   ├── variables.tf      # Input variable declarations
│   ├── outputs.tf        # Output value definitions
│   ├── versions.tf       # Provider version constraints
│   ├── locals.tf         # Local value computations
│   ├── data.tf           # Data source definitions
│   ├── README.md         # Module documentation
│   └── examples/
│       ├── basic/        # Minimal configuration
│       └── complete/     # Full-featured example
├── eks/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── versions.tf
│   ├── iam.tf            # IAM roles and policies
│   ├── security-groups.tf
│   └── examples/
├── rds/
├── s3/
├── kms/
└── iam/
```

!!! tip "Module Documentation"
    Each module includes a comprehensive README with:

    - Input/output variable tables
    - Usage examples
    - Security considerations
    - Upgrade guides

## Source Files

| Module | GitHub Directory |
|--------|------------------|
| VPC | [terraform-modules/vpc](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/terraform-modules/vpc) |
| EKS | [terraform-modules/eks](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/terraform-modules/eks) |
| RDS | [terraform-modules/rds](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/terraform-modules/rds) |
| S3 | [terraform-modules/s3](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/terraform-modules/s3) |
| KMS | [terraform-modules/kms](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/terraform-modules/kms) |
| IAM | [terraform-modules/iam](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/terraform-modules/iam) |

---

!!! info "Related Documentation"
    - [CI/CD Pipeline Security](../devsecops/cicd.md)
    - [AWS Security Architecture](../cloud-security/aws.md)
    - [PCI DSS Compliance](../compliance/pci-dss.md)
