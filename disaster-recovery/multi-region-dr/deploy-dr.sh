#!/bin/bash
#
# Multi-Region Disaster Recovery Deployment Script
# Implements pilot-light DR strategy for payment processing platform
# Primary: eu-west-1 | Secondary: eu-west-2
#
# RTO Target: 4 hours
# RPO Target: 15 minutes
#
# Author: Evgeniy Gantman
# Version: 2.0
#

set -euo pipefail

# Configuration
PRIMARY_REGION="${PRIMARY_REGION:-eu-west-1}"
DR_REGION="${DR_REGION:-eu-west-2}"
ENVIRONMENT="${ENVIRONMENT:-production}"
DR_MODE="${1:-pilot-light}"  # pilot-light | warm-standby | hot-standby

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="/var/log/dr-deployment-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

log_info() { echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_section() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }

#######################################
# Pre-flight Checks
#######################################

preflight_checks() {
    log_section "Pre-flight Checks"

    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not installed"
        exit 1
    fi

    # Check credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured"
        exit 1
    fi

    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform not installed"
        exit 1
    fi

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not installed"
        exit 1
    fi

    # Verify primary region accessibility
    log_info "Checking primary region: $PRIMARY_REGION"
    if ! aws ec2 describe-regions --region-names $PRIMARY_REGION &> /dev/null; then
        log_error "Cannot access primary region: $PRIMARY_REGION"
        exit 1
    fi

    # Verify DR region accessibility
    log_info "Checking DR region: $DR_REGION"
    if ! aws ec2 describe-regions --region-names $DR_REGION &> /dev/null; then
        log_error "Cannot access DR region: $DR_REGION"
        exit 1
    fi

    log_info "Pre-flight checks passed"
}

#######################################
# Database Replication Setup
#######################################

setup_database_replication() {
    log_section "Setting Up Database Replication"

    # Get primary RDS instance
    PRIMARY_DB=$(aws rds describe-db-instances \
        --region $PRIMARY_REGION \
        --query "DBInstances[?DBInstanceIdentifier=='payment-db-prod'].DBInstanceIdentifier" \
        --output text)

    if [[ -z "$PRIMARY_DB" ]]; then
        log_error "Primary database not found in $PRIMARY_REGION"
        exit 1
    fi

    log_info "Found primary database: $PRIMARY_DB"

    # Check if read replica already exists in DR region
    DR_REPLICA=$(aws rds describe-db-instances \
        --region $DR_REGION \
        --query "DBInstances[?ReadReplicaSourceDBInstanceIdentifier=='arn:aws:rds:$PRIMARY_REGION:*:db:$PRIMARY_DB'].DBInstanceIdentifier" \
        --output text)

    if [[ -n "$DR_REPLICA" ]]; then
        log_info "DR read replica already exists: $DR_REPLICA"
    else
        log_info "Creating cross-region read replica in $DR_REGION"

        aws rds create-db-instance-read-replica \
            --db-instance-identifier "$PRIMARY_DB-dr-replica" \
            --source-db-instance-identifier "arn:aws:rds:$PRIMARY_REGION:$(aws sts get-caller-identity --query Account --output text):db:$PRIMARY_DB" \
            --db-instance-class db.r6g.xlarge \
            --publicly-accessible false \
            --auto-minor-version-upgrade true \
            --multi-az false \
            --storage-encrypted \
            --region $DR_REGION

        log_info "Waiting for read replica to become available (this may take 10-15 minutes)..."

        aws rds wait db-instance-available \
            --db-instance-identifier "$PRIMARY_DB-dr-replica" \
            --region $DR_REGION

        log_info "Read replica created successfully"
    fi

    # Enable automated backups on replica
    aws rds modify-db-instance \
        --db-instance-identifier "$PRIMARY_DB-dr-replica" \
        --backup-retention-period 7 \
        --preferred-backup-window "03:00-04:00" \
        --region $DR_REGION \
        --apply-immediately

    log_info "Database replication configured"
}

#######################################
# S3 Cross-Region Replication
#######################################

setup_s3_replication() {
    log_section "Setting Up S3 Cross-Region Replication"

    # Critical buckets to replicate
    BUCKETS=(
        "payment-data-prod"
        "cardholder-data-prod"
        "audit-logs-prod"
        "backup-prod"
    )

    for bucket in "${BUCKETS[@]}"; do
        log_info "Configuring replication for bucket: $bucket"

        # Create DR bucket if it doesn't exist
        DR_BUCKET="$bucket-dr"

        if ! aws s3api head-bucket --bucket $DR_BUCKET --region $DR_REGION 2>/dev/null; then
            log_info "Creating DR bucket: $DR_BUCKET"

            aws s3api create-bucket \
                --bucket $DR_BUCKET \
                --region $DR_REGION \
                --create-bucket-configuration LocationConstraint=$DR_REGION

            # Enable versioning (required for replication)
            aws s3api put-bucket-versioning \
                --bucket $DR_BUCKET \
                --region $DR_REGION \
                --versioning-configuration Status=Enabled

            # Enable encryption
            aws s3api put-bucket-encryption \
                --bucket $DR_BUCKET \
                --region $DR_REGION \
                --server-side-encryption-configuration '{
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        },
                        "BucketKeyEnabled": true
                    }]
                }'
        fi

        # Create replication role if not exists
        REPLICATION_ROLE="s3-replication-role"
        REPLICATION_ROLE_ARN="arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/$REPLICATION_ROLE"

        if ! aws iam get-role --role-name $REPLICATION_ROLE &>/dev/null; then
            log_info "Creating S3 replication IAM role"

            aws iam create-role \
                --role-name $REPLICATION_ROLE \
                --assume-role-policy-document '{
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "s3.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }]
                }'

            aws iam put-role-policy \
                --role-name $REPLICATION_ROLE \
                --policy-name S3ReplicationPolicy \
                --policy-document '{
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                            "Resource": "arn:aws:s3:::*"
                        },
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl"],
                            "Resource": "arn:aws:s3:::*/*"
                        },
                        {
                            "Effect": "Allow",
                            "Action": ["s3:ReplicateObject", "s3:ReplicateDelete"],
                            "Resource": "arn:aws:s3:::*/*"
                        }
                    ]
                }'

            sleep 10  # Allow role to propagate
        fi

        # Configure replication
        aws s3api put-bucket-replication \
            --bucket $bucket \
            --region $PRIMARY_REGION \
            --replication-configuration "{
                \"Role\": \"$REPLICATION_ROLE_ARN\",
                \"Rules\": [{
                    \"ID\": \"ReplicateAll\",
                    \"Priority\": 1,
                    \"Status\": \"Enabled\",
                    \"Filter\": {},
                    \"Destination\": {
                        \"Bucket\": \"arn:aws:s3:::$DR_BUCKET\",
                        \"ReplicationTime\": {
                            \"Status\": \"Enabled\",
                            \"Time\": {\"Minutes\": 15}
                        },
                        \"Metrics\": {
                            \"Status\": \"Enabled\",
                            \"EventThreshold\": {\"Minutes\": 15}
                        }
                    },
                    \"DeleteMarkerReplication\": {\"Status\": \"Enabled\"}
                }]
            }"

        log_info "Replication configured for $bucket → $DR_BUCKET (RPO: 15 minutes)"
    done

    log_info "S3 replication setup complete"
}

#######################################
# EKS Cluster DR Preparation
#######################################

prepare_eks_dr_cluster() {
    log_section "Preparing EKS Cluster in DR Region"

    case $DR_MODE in
        pilot-light)
            log_info "Pilot-light mode: Creating minimal EKS cluster"
            NODE_COUNT=0  # No nodes, cluster only
            ;;
        warm-standby)
            log_info "Warm-standby mode: Creating EKS cluster with minimal nodes"
            NODE_COUNT=2
            ;;
        hot-standby)
            log_info "Hot-standby mode: Creating full EKS cluster"
            NODE_COUNT=3
            ;;
    esac

    # Check if DR cluster exists
    if aws eks describe-cluster --name payment-eks-dr --region $DR_REGION &>/dev/null; then
        log_info "DR EKS cluster already exists"
    else
        log_info "Creating EKS cluster in DR region..."

        # Use eksctl for quick cluster creation
        eksctl create cluster \
            --name payment-eks-dr \
            --region $DR_REGION \
            --version 1.28 \
            --nodegroup-name dr-nodes \
            --node-type t3.medium \
            --nodes $NODE_COUNT \
            --nodes-min 0 \
            --nodes-max 10 \
            --managed \
            --zones "${DR_REGION}a,${DR_REGION}b,${DR_REGION}c"

        log_info "EKS cluster created"
    fi

    # Update kubeconfig
    aws eks update-kubeconfig \
        --name payment-eks-dr \
        --region $DR_REGION \
        --alias dr-cluster

    log_info "EKS DR cluster prepared"
}

#######################################
# Velero Backup Configuration
#######################################

setup_velero_backup() {
    log_section "Setting Up Velero for Kubernetes Backups"

    # Install Velero in primary cluster
    kubectl config use-context arn:aws:eks:$PRIMARY_REGION:$(aws sts get-caller-identity --query Account --output text):cluster/payment-eks-prod

    # Create S3 bucket for Velero backups
    VELERO_BUCKET="velero-backups-$(aws sts get-caller-identity --query Account --output text)"

    if ! aws s3api head-bucket --bucket $VELERO_BUCKET --region $PRIMARY_REGION 2>/dev/null; then
        aws s3api create-bucket \
            --bucket $VELERO_BUCKET \
            --region $PRIMARY_REGION

        aws s3api put-bucket-versioning \
            --bucket $VELERO_BUCKET \
            --versioning-configuration Status=Enabled
    fi

    # Install Velero
    if ! kubectl get namespace velero &>/dev/null; then
        log_info "Installing Velero..."

        velero install \
            --provider aws \
            --plugins velero/velero-plugin-for-aws:v1.8.0 \
            --bucket $VELERO_BUCKET \
            --backup-location-config region=$PRIMARY_REGION \
            --snapshot-location-config region=$PRIMARY_REGION \
            --use-volume-snapshots=true \
            --secret-file /dev/null \
            --use-node-agent

        sleep 30  # Wait for Velero to be ready
    fi

    # Create backup schedule (every 6 hours)
    velero schedule create payment-platform-backup \
        --schedule="0 */6 * * *" \
        --include-namespaces production,payment-services \
        --ttl 168h0m0s  # 7 days retention \
        --exclude-resources events,events.events.k8s.io \
        --snapshot-volumes

    log_info "Velero backup schedule created (every 6 hours, 7-day retention)"
}

#######################################
# Route 53 Health Checks and Failover
#######################################

setup_dns_failover() {
    log_section "Setting Up Route 53 Health Checks and Failover"

    # Get hosted zone ID
    HOSTED_ZONE_ID=$(aws route53 list-hosted-zones-by-name \
        --dns-name "payment-api.example.com" \
        --query "HostedZones[0].Id" \
        --output text | cut -d'/' -f3)

    if [[ -z "$HOSTED_ZONE_ID" ]]; then
        log_error "Hosted zone not found for payment-api.example.com"
        return 1
    fi

    # Primary endpoint health check
    PRIMARY_HEALTH_CHECK=$(aws route53 create-health-check \
        --caller-reference "primary-$(date +%s)" \
        --health-check-config "
            IPAddress=$(aws elbv2 describe-load-balancers \
                --region $PRIMARY_REGION \
                --names payment-alb-prod \
                --query 'LoadBalancers[0].DNSName' --output text | dig +short | head -1),
            Port=443,
            Type=HTTPS,
            ResourcePath=/health,
            RequestInterval=30,
            FailureThreshold=3
        " \
        --query 'HealthCheck.Id' \
        --output text)

    # DR endpoint health check
    DR_HEALTH_CHECK=$(aws route53 create-health-check \
        --caller-reference "dr-$(date +%s)" \
        --health-check-config "
            IPAddress=$(aws elbv2 describe-load-balancers \
                --region $DR_REGION \
                --names payment-alb-dr \
                --query 'LoadBalancers[0].DNSName' --output text | dig +short | head -1),
            Port=443,
            Type=HTTPS,
            ResourcePath=/health,
            RequestInterval=30,
            FailureThreshold=3
        " \
        --query 'HealthCheck.Id' \
        --output text)

    # Create failover records
    cat > /tmp/route53-changeset.json <<EOF
{
    "Changes": [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "payment-api.example.com",
                "Type": "A",
                "SetIdentifier": "Primary",
                "Failover": "PRIMARY",
                "AliasTarget": {
                    "HostedZoneId": "$(aws elbv2 describe-load-balancers --region $PRIMARY_REGION --names payment-alb-prod --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text)",
                    "DNSName": "$(aws elbv2 describe-load-balancers --region $PRIMARY_REGION --names payment-alb-prod --query 'LoadBalancers[0].DNSName' --output text)",
                    "EvaluateTargetHealth": true
                },
                "HealthCheckId": "$PRIMARY_HEALTH_CHECK"
            }
        },
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "payment-api.example.com",
                "Type": "A",
                "SetIdentifier": "Secondary",
                "Failover": "SECONDARY",
                "AliasTarget": {
                    "HostedZoneId": "$(aws elbv2 describe-load-balancers --region $DR_REGION --names payment-alb-dr --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text)",
                    "DNSName": "$(aws elbv2 describe-load-balancers --region $DR_REGION --names payment-alb-dr --query 'LoadBalancers[0].DNSName' --output text)",
                    "EvaluateTargetHealth": true
                },
                "HealthCheckId": "$DR_HEALTH_CHECK"
            }
        }
    ]
}
EOF

    aws route53 change-resource-record-sets \
        --hosted-zone-id $HOSTED_ZONE_ID \
        --change-batch file:///tmp/route53-changeset.json

    rm /tmp/route53-changeset.json

    log_info "Route 53 failover configured (Primary: $PRIMARY_REGION → DR: $DR_REGION)"
}

#######################################
# DR Runbook Generation
#######################################

generate_dr_runbook() {
    log_section "Generating DR Runbook"

    cat > /tmp/DR_RUNBOOK.md <<'EOF'
# Disaster Recovery Runbook

## Emergency Contacts
- **CISO**: [Name] - [Phone] - [Email]
- **Cloud Architect**: [Name] - [Phone] - [Email]
- **AWS TAM**: [Name] - [Phone]
- **On-Call Engineer**: PagerDuty escalation

## Failover Decision Criteria

Activate DR if ANY of the following occur:
- [ ] Primary region unavailable >30 minutes
- [ ] Database corruption in primary
- [ ] Ransomware affecting primary infrastructure
- [ ] Regulatory requirement (data residency)
- [ ] >99.95% SLA breach imminent

## Failover Procedure (RTO: 4 hours)

### Phase 1: Assessment (0-30 minutes)

**Step 1: Verify Primary Region Unavailability**
```bash
# Check AWS Service Health Dashboard
aws health describe-events --region eu-west-1

# Test primary database connectivity
psql -h payment-db-prod.XXXXX.eu-west-1.rds.amazonaws.com -U admin -d payment_db -c "SELECT 1;"

# Test primary API endpoint
curl -I https://payment-api.example.com/health
```

**Step 2: Escalate to Decision Makers**
- Notify CISO and Cloud Architect via PagerDuty P0
- Initiate war room (Slack: #dr-activation)
- Document incident start time

### Phase 2: Database Promotion (30-90 minutes)

**Step 3: Promote Read Replica to Standalone**
```bash
# CRITICAL: This is a one-way operation!
aws rds promote-read-replica \
  --db-instance-identifier payment-db-prod-dr-replica \
  --region eu-west-2

# Wait for promotion (typically 10-15 minutes)
aws rds wait db-instance-available \
  --db-instance-identifier payment-db-prod-dr-replica \
  --region eu-west-2

# Verify write capability
psql -h payment-db-prod-dr-replica.XXXXX.eu-west-2.rds.amazonaws.com -U admin -d payment_db -c "
  CREATE TABLE dr_test (id SERIAL, failover_time TIMESTAMP DEFAULT NOW());
  INSERT INTO dr_test DEFAULT VALUES;
  SELECT * FROM dr_test;
  DROP TABLE dr_test;
"
```

**Step 4: Update Application Database Endpoints**
```bash
# Update Kubernetes ConfigMaps
kubectl config use-context dr-cluster
kubectl patch configmap app-config -n production \
  -p '{"data":{"DB_HOST":"payment-db-prod-dr-replica.XXXXX.eu-west-2.rds.amazonaws.com"}}'

# Restart pods to pick up new config
kubectl rollout restart deployment/payment-api -n production
```

### Phase 3: Application Activation (90-180 minutes)

**Step 5: Scale EKS Node Group**
```bash
# Scale from 0 to production capacity
eksctl scale nodegroup \
  --cluster=payment-eks-dr \
  --region=eu-west-2 \
  --name=dr-nodes \
  --nodes=10 \
  --nodes-min=10 \
  --nodes-max=20

# Wait for nodes to be ready
kubectl wait --for=condition=Ready nodes --all --timeout=600s
```

**Step 6: Restore Kubernetes State from Velero**
```bash
# List available backups
velero backup get

# Restore latest backup
LATEST_BACKUP=$(velero backup get --output json | jq -r '.[0].metadata.name')
velero restore create dr-restore-$(date +%Y%m%d-%H%M%S) \
  --from-backup $LATEST_BACKUP \
  --wait

# Verify restoration
kubectl get pods -A
kubectl get svc -A
```

**Step 7: Restore S3 Data (if needed)**
```bash
# Sync from DR buckets to active buckets
aws s3 sync s3://payment-data-prod-dr s3://payment-data-prod --region eu-west-2
```

### Phase 4: DNS Failover (180-200 minutes)

**Step 8: Manually Trigger Route 53 Failover (if automatic failed)**
```bash
# Disable primary health check (forces failover)
aws route53 update-health-check \
  --health-check-id $PRIMARY_HEALTH_CHECK \
  --disabled

# Verify DNS propagation (may take 60-300 seconds)
dig payment-api.example.com +short
# Should return DR region load balancer IP
```

**Step 9: Verify Traffic Routing**
```bash
# Monitor DR region ALB metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApplicationELB \
  --metric-name RequestCount \
  --dimensions Name=LoadBalancer,Value=app/payment-alb-dr/XXXXX \
  --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum \
  --region eu-west-2
```

### Phase 5: Validation (200-240 minutes)

**Step 10: End-to-End Testing**
```bash
# Test payment flow
curl -X POST https://payment-api.example.com/api/v1/payments \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -d '{
    "amount": 1.00,
    "currency": "EUR",
    "card_token": "tok_test_xxxx"
  }'

# Check database for test transaction
psql -h $DR_DB_ENDPOINT -U admin -d payment_db -c "
  SELECT * FROM transactions ORDER BY created_at DESC LIMIT 5;
"
```

**Step 11: Monitor Error Rates**
```bash
# Check application logs
kubectl logs -f deployment/payment-api -n production | grep -i error

# Check error rate in Wazuh
# OpenSearch query: rule.level:>=10 AND timestamp:>now-1h
```

## Post-Failover Checklist

- [ ] All critical services operational in DR region
- [ ] Database writes successful
- [ ] Payment transactions processing
- [ ] Error rate <1%
- [ ] Monitoring and alerting operational
- [ ] Stakeholders notified (customers, partners, PCI QSA)
- [ ] Incident documentation updated

## Failback Procedure (when primary region restored)

### Prerequisites
- Primary region fully operational for >24 hours
- All tests passed in primary region
- Change window approved

### Steps
1. Set up reverse replication (DR → Primary)
2. Sync databases
3. Scale down DR cluster to warm-standby
4. Re-enable primary Route 53 health check
5. Monitor for 24 hours before full deactivation

## Testing Schedule

- **Quarterly**: Tabletop exercise (2 hours)
- **Bi-annual**: DR activation test (non-production)
- **Annual**: Full DR drill with downtime

## Metrics

- **RTO Target**: 4 hours
- **RPO Target**: 15 minutes (database replication + S3 replication)
- **Last Tested**: [Date]
- **Last Actual Failover**: [Date or "Never"]

---
**Document Version**: 2.0
**Last Updated**: December 2025
**Owner**: Cloud Architecture Team
EOF

    cp /tmp/DR_RUNBOOK.md /opt/dr-runbooks/
    log_info "DR Runbook generated: /opt/dr-runbooks/DR_RUNBOOK.md"
}

#######################################
# Main Execution
#######################################

main() {
    log_section "Multi-Region Disaster Recovery Deployment"
    log_info "DR Mode: $DR_MODE"
    log_info "Primary Region: $PRIMARY_REGION"
    log_info "DR Region: $DR_REGION"

    preflight_checks
    setup_database_replication
    setup_s3_replication
    prepare_eks_dr_cluster
    setup_velero_backup
    setup_dns_failover
    generate_dr_runbook

    log_section "Deployment Complete"
    log_info "DR infrastructure successfully deployed"
    log_info "RTO: 4 hours | RPO: 15 minutes"
    log_info "Runbook: /opt/dr-runbooks/DR_RUNBOOK.md"
    log_info "Log file: $LOG_FILE"
}

# Run main function
main "$@"
