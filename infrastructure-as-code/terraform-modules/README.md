# Terraform Modules

Reusable, production-grade Terraform modules for secure cloud infrastructure across AWS, GCP, and Azure. These modules follow best practices for security, compliance, and maintainability.

## Overview

This directory contains custom Terraform modules used across all cloud environments. Each module is designed to be composable, testable, and compliant with security standards (PCI DSS, NIST, CIS Benchmarks).

### Key Features

- **Multi-Cloud Support**: Modules for AWS, GCP, and Azure
- **Security Hardened**: Built-in security controls and compliance
- **Tested**: Automated testing with Terratest
- **Documented**: Comprehensive examples and documentation
- **Versioned**: Semantic versioning for module releases
- **DRY Principle**: Eliminate duplication across environments

### Module Statistics

- **Total Modules**: 15
- **Lines of Code**: ~3,500
- **Test Coverage**: 85%
- **Environments Using**: Production (15 AWS accounts), Development (3 accounts), Staging (2 accounts)
- **Infrastructure Managed**: 1,200+ resources across all clouds

## Directory Structure

```
terraform-modules/
├── README.md                          # This file
├── metadata.yaml                      # Module catalog and compliance mappings
├── aws-vpc-secure/                    # Secure VPC with private subnets
├── aws-eks-cluster/                   # Hardened EKS cluster
├── aws-rds-encrypted/                 # Encrypted RDS with automated backups
├── aws-s3-secure/                     # S3 bucket with encryption and versioning
├── gcp-vpc-secure/                    # Secure VPC for GCP
├── gcp-gke-cluster/                   # Hardened GKE cluster
├── azure-vnet-secure/                 # Secure VNet with NSGs
├── azure-aks-cluster/                 # Hardened AKS cluster
├── security-group-rules/              # Reusable security group rules
├── kms-key-rotation/                  # KMS key with automatic rotation
├── cloudwatch-alarms/                 # Standard CloudWatch alarms
├── iam-role-policy/                   # IAM role with least privilege
├── tags-standard/                     # Standard tagging module
└── testing/                           # Terratest test suite

modules/
├── aws-vpc-secure/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── README.md
│   └── examples/
├── aws-eks-cluster/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── README.md
│   └── examples/
└── ...
```

## Module Catalog

### AWS Modules

#### 1. aws-vpc-secure
**Purpose**: Create a secure VPC with private and public subnets across multiple AZs

**Features**:
- 3 availability zones for high availability
- Private subnets with NAT Gateway for internet access
- Public subnets for load balancers only
- VPC Flow Logs enabled
- Network ACLs with deny rules
- IPv4 and IPv6 support

**Usage**:
```hcl
module "vpc" {
  source = "./modules/aws-vpc-secure"

  vpc_name             = "production-vpc"
  vpc_cidr             = "10.0.0.0/16"
  availability_zones   = ["us-east-1a", "us-east-1b", "us-east-1c"]
  enable_flow_logs     = true
  flow_logs_retention  = 90

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}
```

#### 2. aws-eks-cluster
**Purpose**: Deploy a hardened EKS cluster with security best practices

**Features**:
- Private endpoint only (no public access)
- Encryption at rest with KMS
- IAM Roles for Service Accounts (IRSA)
- Managed node groups with auto-scaling
- Pod Security Standards enforced
- Audit logging enabled
- Network policies ready

**Usage**:
```hcl
module "eks" {
  source = "./modules/aws-eks-cluster"

  cluster_name    = "production-eks"
  cluster_version = "1.28"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnet_ids

  node_groups = {
    general = {
      desired_size = 3
      min_size     = 2
      max_size     = 10
      instance_types = ["t3.large"]
    }
  }

  enable_irsa              = true
  enable_encryption_at_rest = true
  kms_key_arn              = module.kms_key.key_arn
}
```

#### 3. aws-rds-encrypted
**Purpose**: Deploy encrypted RDS database with automated backups

**Features**:
- Encryption at rest with KMS
- Automated backups (7-year retention for PCI DSS)
- Multi-AZ for high availability
- Parameter groups for security hardening
- Enhanced monitoring
- Performance Insights
- Deletion protection

**Usage**:
```hcl
module "rds" {
  source = "./modules/aws-rds-encrypted"

  identifier     = "production-db"
  engine         = "postgres"
  engine_version = "15.3"
  instance_class = "db.r6g.large"

  allocated_storage = 100
  storage_encrypted = true
  kms_key_id        = module.kms_key.key_arn

  multi_az               = true
  backup_retention_period = 2555  # 7 years for PCI DSS
  deletion_protection    = true
}
```

#### 4. aws-s3-secure
**Purpose**: Create S3 bucket with security controls

**Features**:
- Encryption at rest (AES-256 or KMS)
- Versioning enabled
- Block public access
- Lifecycle policies
- Object lock for compliance
- Access logging
- Bucket policies with least privilege

**Usage**:
```hcl
module "s3" {
  source = "./modules/aws-s3-secure"

  bucket_name = "examplepay-data-prod"

  enable_versioning     = true
  enable_encryption     = true
  kms_master_key_id     = module.kms_key.key_arn
  block_public_access   = true
  enable_access_logging = true

  lifecycle_rules = [
    {
      id      = "archive-old-versions"
      enabled = true

      transition = {
        days          = 90
        storage_class = "GLACIER"
      }
    }
  ]
}
```

### GCP Modules

#### 5. gcp-vpc-secure
**Purpose**: Create secure VPC with private subnets in GCP

**Features**:
- Custom mode VPC (no auto-created subnets)
- Private Google Access enabled
- VPC Flow Logs
- Cloud NAT for outbound internet
- Firewall rules with deny-by-default

**Usage**:
```hcl
module "vpc" {
  source = "./modules/gcp-vpc-secure"

  project_id = "examplepay-prod-gcp"
  vpc_name   = "production-vpc"
  region     = "us-central1"

  subnets = [
    {
      subnet_name   = "private-subnet-1"
      subnet_ip     = "172.16.0.0/20"
      subnet_region = "us-central1"
    }
  ]

  enable_flow_logs = true
}
```

#### 6. gcp-gke-cluster
**Purpose**: Deploy hardened GKE cluster

**Features**:
- Private cluster (no public endpoint)
- Workload Identity enabled
- Binary Authorization
- Application-layer secrets encryption
- Shielded GKE nodes
- Auto-repair and auto-upgrade

**Usage**:
```hcl
module "gke" {
  source = "./modules/gcp-gke-cluster"

  project_id      = "examplepay-prod-gcp"
  cluster_name    = "production-gke"
  region          = "us-central1"
  network         = module.vpc.network_name
  subnetwork      = module.vpc.subnet_names[0]

  enable_private_nodes     = true
  enable_workload_identity = true
  enable_binary_auth       = true
}
```

### Azure Modules

#### 7. azure-vnet-secure
**Purpose**: Create secure VNet with NSGs

**Features**:
- Hub-spoke topology support
- Network Security Groups
- DDoS Protection
- Private Link ready
- Service endpoints

#### 8. azure-aks-cluster
**Purpose**: Deploy hardened AKS cluster

**Features**:
- Azure AD integration
- Managed identities
- Private cluster
- Azure Policy for Kubernetes
- Network policies enabled

### Cross-Cloud Modules

#### 9. security-group-rules
**Purpose**: Standardized security group rules across clouds

**Features**:
- Predefined rule sets (web, database, internal)
- Compliance-ready rules
- Port restrictions per PCI DSS

#### 10. kms-key-rotation
**Purpose**: KMS keys with automatic rotation

**Features**:
- 90-day rotation for PCI DSS
- HSM backing option
- Audit logging
- Cross-region replication

#### 11. cloudwatch-alarms
**Purpose**: Standard CloudWatch alarms for monitoring

**Features**:
- CPU/memory/disk alarms
- Database performance alarms
- API Gateway error rate alarms
- SNS topic integration

#### 12. iam-role-policy
**Purpose**: IAM roles with least privilege

**Features**:
- Trust relationship templates
- Permission boundary support
- Session duration limits
- MFA enforcement

#### 13. tags-standard
**Purpose**: Enforce consistent tagging across all resources

**Features**:
- Required tags (Environment, ManagedBy, CostCenter)
- Optional tags (Project, Owner, Compliance)
- Tag validation

## Module Development Standards

### 1. File Structure
Every module must include:
- `main.tf` - Main resource definitions
- `variables.tf` - Input variables with descriptions and validation
- `outputs.tf` - Output values for module composition
- `README.md` - Usage documentation with examples
- `versions.tf` - Terraform and provider version constraints

### 2. Security Requirements
All modules must:
- Enable encryption at rest by default
- Use least privilege IAM policies
- Enable logging and monitoring
- Block public access by default
- Use secure defaults (e.g., TLS 1.3)

### 3. Compliance Alignment
Modules are mapped to:
- PCI DSS v4.0 requirements
- CIS Benchmarks
- NIST 800-53 controls
- SOC 2 Type II criteria

### 4. Testing
All modules must have:
- Terratest integration tests
- Example configurations
- Documentation of test coverage
- CI/CD pipeline validation

### 5. Versioning
- Semantic versioning (MAJOR.MINOR.PATCH)
- Git tags for releases
- Changelog documentation
- Backward compatibility policy

## Usage Examples

### Example 1: Three-Tier Web Application

```hcl
# VPC
module "vpc" {
  source = "./modules/aws-vpc-secure"

  vpc_name = "webapp-vpc"
  vpc_cidr = "10.0.0.0/16"
}

# EKS Cluster
module "eks" {
  source = "./modules/aws-eks-cluster"

  cluster_name = "webapp-eks"
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = module.vpc.private_subnet_ids
}

# RDS Database
module "rds" {
  source = "./modules/aws-rds-encrypted"

  identifier     = "webapp-db"
  engine         = "postgres"
  instance_class = "db.r6g.large"
}

# S3 Bucket for Assets
module "s3_assets" {
  source = "./modules/aws-s3-secure"

  bucket_name = "webapp-assets"
}
```

### Example 2: Multi-Cloud Deployment

```hcl
# AWS
module "aws_vpc" {
  source = "./modules/aws-vpc-secure"
  vpc_name = "primary-vpc"
}

# GCP
module "gcp_vpc" {
  source = "./modules/gcp-vpc-secure"
  vpc_name = "secondary-vpc"
}

# Azure
module "azure_vnet" {
  source = "./modules/azure-vnet-secure"
  vnet_name = "tertiary-vnet"
}
```

## Testing

### Running Tests

```bash
# Install Terratest
go get github.com/gruntwork-io/terratest

# Run all tests
cd testing
go test -v -timeout 30m

# Run specific module test
go test -v -run TestAwsVpcSecure
```

### Test Coverage

| Module | Unit Tests | Integration Tests | Coverage |
|--------|-----------|-------------------|----------|
| aws-vpc-secure | ✓ | ✓ | 90% |
| aws-eks-cluster | ✓ | ✓ | 85% |
| aws-rds-encrypted | ✓ | ✓ | 88% |
| aws-s3-secure | ✓ | ✓ | 92% |
| gcp-vpc-secure | ✓ | ✓ | 87% |
| gcp-gke-cluster | ✓ | ✓ | 84% |

**Overall Test Coverage**: 85%

## Best Practices

### 1. Module Composition
- Keep modules focused on single responsibility
- Use module composition for complex infrastructure
- Pass outputs between modules explicitly

### 2. Variable Validation
```hcl
variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR block"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "Must be a valid IPv4 CIDR block."
  }
}
```

### 3. Secure Defaults
```hcl
variable "enable_encryption" {
  type        = bool
  description = "Enable encryption at rest"
  default     = true  # Secure by default
}
```

### 4. Comprehensive Outputs
```hcl
output "vpc_id" {
  description = "VPC ID for use in other modules"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}
```

## Versioning Strategy

### Module Versions
- **v1.x.x**: Production-ready, stable
- **v0.x.x**: Beta, breaking changes possible
- **dev**: Development branch, unstable

### Breaking Changes
- Major version bump (1.x.x → 2.0.0)
- Migration guide provided
- Deprecation warnings in previous version

## Contribution Guidelines

1. **Create Feature Branch**: `feature/module-name`
2. **Write Tests**: Cover all code paths
3. **Update Documentation**: README and inline comments
4. **Run Validation**: `terraform fmt`, `terraform validate`
5. **Submit PR**: With description and test results

## Related Directories

- [../ansible-playbooks/](../ansible-playbooks/) - Configuration management automation
- [../cloudformation/](../cloudformation/) - Alternative IaC using CloudFormation
- [../../cloud-security/](../../cloud-security/) - Cloud-specific security configurations
- [../../devsecops/](../../devsecops/) - CI/CD and security scanning

## References

- [Terraform Module Best Practices](https://www.terraform.io/docs/modules/index.html)
- [AWS Terraform Modules](https://registry.terraform.io/namespaces/terraform-aws-modules)
- [GCP Terraform Modules](https://registry.terraform.io/namespaces/terraform-google-modules)
- [Azure Terraform Modules](https://registry.terraform.io/namespaces/Azure)
