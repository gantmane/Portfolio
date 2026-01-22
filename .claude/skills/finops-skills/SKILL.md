---
name: finops-skills
description: Cloud financial management expertise for cost optimization, reserved instances, spot instances, rightsizing, and FinOps practices. Use when analyzing cloud costs, implementing savings strategies, or optimizing infrastructure spending.
allowed-tools: Read, Grep, Glob, Bash(aws:*)
nist_csf_function: GOVERN
nist_csf_categories: [GV.RM-03, GV.OC-01, GV.OC-04, GV.OV-03, GV.SC-06]
mitre_attack_coverage: [T1496]
---

# FinOps Skills

> **NIST CSF 2.0 Alignment**: GOVERN Function - Risk Management & Organizational Context
> Supports cloud cost governance, resource optimization, and financial risk management

## FinOps Framework ⇒ GV.RM-03, GV.OV-03

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   INFORM    │───▶│  OPTIMIZE   │───▶│   OPERATE   │
│ Visibility  │    │ Rate/Usage  │    │ Governance  │
│ Allocation  │    │ Rightsizing │    │ Automation  │
│ Benchmarks  │    │ Architecture│    │ Continuous  │
└─────────────┘    └─────────────┘    └─────────────┘
    ⇒ GV.OC-01       ⇒ GV.RM-03        ⇒ GV.OV-03
```

## Cost Visibility ⇒ GV.OC-01, ID.AM-02

### Cost Allocation Tags ⇒ ID.AM-02
```yaml
# ⇒ ID.AM-02: Asset classification through tagging
required_tags:
  - key: Environment
    values: [production, staging, development]
  - key: Team
    values: [platform, backend, frontend, data]
  - key: Service
    values: [api, web, worker, database]
  - key: CostCenter
    format: "CC-[0-9]{4}"

enforcement:  # ⇒ GV.PO-01
  aws_config_rule: required-tags
  block_untagged: true
```

### AWS Cost Explorer Query ⇒ GV.OV-03
```bash
# Get cost by service ⇒ GV.OV-03 (Cost monitoring)
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE

# Get cost by tag ⇒ GV.OC-01 (Team allocation)
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity DAILY \
  --metrics UnblendedCost \
  --group-by Type=TAG,Key=Team
```

### Cost and Usage Report (Athena) ⇒ GV.OV-03
```sql
-- ⇒ GV.OV-03: Detailed cost analysis
SELECT
    line_item_usage_account_id AS account,
    resource_tags_user_team AS team,
    resource_tags_user_service AS service,
    product_product_name AS aws_service,
    SUM(line_item_unblended_cost) AS cost
FROM cost_and_usage_report
WHERE month = '2024-01'
GROUP BY 1, 2, 3, 4
ORDER BY cost DESC
LIMIT 50;
```

## Savings Plans & Reserved Instances ⇒ GV.RM-03

### Commitment Strategy ⇒ GV.RM-03 (Risk management)
```yaml
# ⇒ GV.RM-03: Balance between savings and flexibility
compute_savings_plans:
  coverage_target: 70%  # Steady-state compute
  term: 1_year
  payment: no_upfront

ec2_reserved_instances:
  coverage_target: 20%  # Specific workloads
  term: 1_year
  offering: standard

rds_reserved_instances:
  coverage_target: 80%
  term: 1_year

# Expected savings calculation:
# On-Demand baseline: $100,000/month
# Savings Plans (70% at 30% discount): -$21,000
# Reserved (20% at 40% discount): -$8,000
# Total monthly savings: ~$29,000 (29%)
```

### RI/SP Analysis ⇒ GV.RM-03
```bash
# Get RI recommendations ⇒ GV.RM-03
aws ce get-reservation-purchase-recommendation \
  --service "Amazon Elastic Compute Cloud - Compute" \
  --term-in-years ONE_YEAR \
  --payment-option NO_UPFRONT

# Get Savings Plans recommendations ⇒ GV.RM-03
aws ce get-savings-plans-purchase-recommendation \
  --savings-plans-type COMPUTE_SP \
  --term-in-years ONE_YEAR \
  --payment-option NO_UPFRONT \
  --lookback-period-in-days THIRTY_DAYS
```

## Spot Instances ⇒ GV.RM-03, PR.IR-04

### Spot Strategy ⇒ GV.RM-03
```yaml
# ⇒ GV.RM-03: Cost optimization with risk tolerance
spot_configuration:
  batch_processing:
    spot_percentage: 100%
    instance_diversification: 10+ types
    interruption_handling: checkpoint_restart  # ⇒ RC.RP-02

  kubernetes_workers:
    spot_percentage: 70%
    on_demand_base: 3 nodes  # ⇒ PR.IR-04 (Base capacity)
    allocation_strategy: capacity-optimized-prioritized

  dev_environments:
    spot_percentage: 100%
    hibernation: enabled
    auto_stop: "20:00"

instance_selection:
  strategy: diversified
  pools: 10+
  max_price: on_demand  # Never pay more than OD
```

### Spot Fleet Template ⇒ PR.IR-04
```json
{
  "SpotFleetRequestConfig": {
    "AllocationStrategy": "capacityOptimized",
    "TargetCapacity": 10,
    "IamFleetRole": "arn:aws:iam::ACCOUNT:role/spot-fleet-role",
    "LaunchTemplateConfigs": [
      {
        "LaunchTemplateSpecification": {
          "LaunchTemplateId": "lt-xxx"
        },
        "Overrides": [
          {"InstanceType": "m5.large"},
          {"InstanceType": "m5a.large"},
          {"InstanceType": "m5n.large"},
          {"InstanceType": "m6i.large"}
        ]
      }
    ]
  }
}
```

## Rightsizing ⇒ GV.RM-03

### Analysis Criteria ⇒ GV.OV-03
```python
# ⇒ GV.OV-03: Data-driven resource optimization
def analyze_rightsizing(instance_metrics):
    recommendations = []

    for instance in instances:
        cpu_p95 = get_percentile(instance, 'cpu', 95, days=14)
        memory_p95 = get_percentile(instance, 'memory', 95, days=14)

        if cpu_p95 < 20 and memory_p95 < 30:
            recommendation = 'downsize_two_sizes'
            confidence = 'high'
        elif cpu_p95 < 40 and memory_p95 < 50:
            recommendation = 'downsize_one_size'
            confidence = 'medium'
        else:
            recommendation = 'optimal'
            confidence = 'high'

        recommendations.append({
            'instance_id': instance.id,
            'current_type': instance.type,
            'recommendation': recommendation,
            'savings': calculate_savings(instance, recommendation)
        })

    return recommendations
```

### AWS Compute Optimizer ⇒ GV.OV-03
```bash
# Get EC2 recommendations ⇒ GV.OV-03
aws compute-optimizer get-ec2-instance-recommendations \
  --filters name=Finding,values=Overprovisioned

# Get EBS recommendations ⇒ GV.OV-03
aws compute-optimizer get-ebs-volume-recommendations \
  --filters name=Finding,values=Overprovisioned
```

## Waste Elimination ⇒ GV.OV-03

### Common Waste Categories
| Waste Type | Detection | Monthly Savings | NIST CSF |
|------------|-----------|-----------------|----------|
| Idle EC2 | CPU <5%, 14 days | $150-500/instance | GV.OV-03 |
| Unattached EBS | No attachment | $50-200/volume | GV.OV-03 |
| Old Snapshots | >90 days | $10-50/snapshot | GV.OV-03 |
| Unused Elastic IPs | Not attached | $3.60/IP | GV.OV-03 |
| Oversized RDS | CPU <20% | $200-1000/DB | GV.OV-03 |
| Dev 24/7 | Non-prod running | $500-2000/env | GV.OV-03 |

### Automated Cleanup ⇒ GV.OV-03
```python
import boto3
from datetime import datetime, timedelta

def cleanup_unused_ebs():
    """⇒ GV.OV-03: Automated waste elimination"""
    ec2 = boto3.client('ec2')

    # Find unattached volumes older than 30 days
    volumes = ec2.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )

    for volume in volumes['Volumes']:
        age = (datetime.now(volume['CreateTime'].tzinfo) -
               volume['CreateTime']).days

        if age > 30:
            # Snapshot before deletion ⇒ RC.RP-02
            ec2.create_snapshot(
                VolumeId=volume['VolumeId'],
                Description=f"Pre-cleanup backup"
            )
            # Tag for review
            ec2.create_tags(
                Resources=[volume['VolumeId']],
                Tags=[{'Key': 'ToDelete', 'Value': 'true'}]
            )

def stop_dev_environments():
    """⇒ GV.OV-03: Non-production scheduling"""
    ec2 = boto3.client('ec2')

    instances = ec2.describe_instances(
        Filters=[
            {'Name': 'tag:Environment', 'Values': ['development']},
            {'Name': 'tag:AutoStop', 'Values': ['true']},
            {'Name': 'instance-state-name', 'Values': ['running']}
        ]
    )

    instance_ids = [i['InstanceId']
                    for r in instances['Reservations']
                    for i in r['Instances']]

    if instance_ids:
        ec2.stop_instances(InstanceIds=instance_ids)
```

## Budget Management ⇒ GV.RM-03, GV.SC-06

### AWS Budgets ⇒ GV.RM-03
```yaml
# ⇒ GV.RM-03: Financial risk controls
budgets:
  - name: "Monthly Infrastructure"
    type: COST
    amount: 150000
    time_unit: MONTHLY
    alerts:
      - threshold: 80
        notification: [email]
      - threshold: 100
        notification: [email, sns]
      - threshold: 110
        action: stop_non_essential  # ⇒ Automatic response

  - name: "Team Platform"
    type: COST
    amount: 50000
    filter:
      tags:
        Team: platform
```

### Budget Alerts ⇒ GV.RM-03
```bash
# Create budget with alert ⇒ GV.RM-03
aws budgets create-budget \
  --account-id $ACCOUNT_ID \
  --budget file://budget.json \
  --notifications-with-subscribers file://notifications.json
```

## Unit Economics ⇒ GV.OC-04

### Cost Per Transaction ⇒ GV.OC-04
```yaml
# ⇒ GV.OC-04: Business-aligned cost metrics
unit_economics:
  cost_per_request:
    formula: "total_infra_cost / total_requests"
    current: $0.00012
    target: $0.00010

  cost_per_user:
    formula: "total_cost / monthly_active_users"
    current: $2.50
    target: $2.00

  infrastructure_ratio:
    formula: "infra_cost / revenue"
    current: 8%
    target: 6%
```

## FinOps Report Template ⇒ GV.OC-04

```markdown
## Monthly FinOps Report - January 2024

### Executive Summary ⇒ GV.OC-04
| Metric | Value | vs Last Month | vs Budget |
|--------|-------|---------------|-----------|
| Total Spend | $142,500 | -5% | -5% |
| Savings Plan Coverage | 72% | +2% | On target |
| Waste Identified | $8,200 | - | - |

### Cost by Team ⇒ GV.OC-01
| Team | Spend | % of Total | Trend |
|------|-------|------------|-------|
| Platform | $52,000 | 36% | ↓ |
| Backend | $38,000 | 27% | → |
| Data | $32,000 | 22% | ↑ |

### Top Optimization Opportunities ⇒ GV.RM-03
1. Rightsizing RDS - $4,200/month savings
2. Spot for EKS - $3,800/month savings
3. Dev scheduling - $2,400/month savings

### Action Items ⇒ ID.RA-06
| Priority | Action | Owner | Savings |
|----------|--------|-------|---------|
| High | RDS rightsizing | DBA | $4,200 |
| High | EKS spot | Platform | $3,800 |
| Medium | Dev scheduling | DevOps | $2,400 |
```

## Security Consideration ⇒ T1496 defense

### Cryptomining Detection ⇒ DE.CM-01, T1496
- Unusual EC2 instance launches
- High CPU utilization on unexpected instances
- Unauthorized AMI usage
- Budget alerts for compute spikes

## MITRE ATT&CK Coverage

This skill addresses defense against:
- **T1496**: Resource Hijacking (cryptomining detection through cost anomalies)
