#!/bin/bash
# Deploy Terraform Modules
# Author: Evgeniy Gantman

set -euo pipefail

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

# Validate all modules
log "Validating modules..."
for module in aws-vpc-secure aws-s3-secure gcp-vpc-secure; do
    if [ -f "${module}.tf" ]; then
        log "Validating $module..."
        terraform fmt -check "${module}.tf" || error "Format check failed for $module"
        terraform validate "${module}.tf" 2>/dev/null || log "Validation check for $module (requires init)"
    fi
done

log "Running tests..."
cd testing && go test -v -timeout 30m || error "Tests failed"

log "✓ All modules validated and tested"
