#!/bin/bash
set -euo pipefail

# Deploy Hardened RDS Instance
# Author: Evgeniy Gantman

echo "[INFO] Deploying hardened RDS instance..."

# Initialize Terraform
terraform init

# Plan
terraform plan -out=tfplan

# Apply
terraform apply tfplan

echo "[INFO] RDS instance deployed successfully!"
echo "[INFO] Endpoint: $(terraform output -raw rds_endpoint)"
echo "[INFO] Connection requires SSL/TLS"
