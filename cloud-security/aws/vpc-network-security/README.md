# AWS VPC Network Security

| File | Purpose |
|------|---------|
| vpc-architecture.tf | Multi-tier VPC — public, private, isolated subnets |
| security-groups.tf | Least-privilege security group rules |
| network-acls.tf | Subnet-level NACLs |
| vpc-endpoints.tf | Private endpoints for AWS services |
| transit-gateway.tf | Transit Gateway for inter-VPC routing |
| vpc-flow-logs.tf | Flow logs to S3 + Athena |
| network-segmentation.yaml | Segmentation policy definitions |
| analyze-flow-logs.py | Flow log anomaly analysis |
| security-group-audit.py | SG rule compliance auditor |
| deploy-vpc.sh | Deployment script |
