#!/usr/bin/env python3
"""
AWS Cost Optimization Analyzer
Author: Evgeniy Gantman
Purpose: Identify cost savings opportunities across AWS infrastructure
"""

import boto3
from datetime import datetime, timedelta
from typing import Dict, List
import json

ec2 = boto3.client('ec2')
ce = boto3.client('ce')
cloudwatch = boto3.client('cloudwatch')
compute_optimizer = boto3.client('compute-optimizer')

def analyze_ec2_right_sizing() -> List[Dict]:
    """Analyze EC2 instances for right-sizing opportunities"""
    print("[INFO] Analyzing EC2 instances for right-sizing...")

    recommendations = []
    instances = ec2.describe_instances(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
    )

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_type = instance['InstanceType']

            # Get CPU utilization (14-day average)
            cpu_stats = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=datetime.utcnow() - timedelta(days=14),
                EndTime=datetime.utcnow(),
                Period=86400,
                Statistics=['Average']
            )

            if cpu_stats['Datapoints']:
                avg_cpu = sum(d['Average'] for d in cpu_stats['Datapoints']) / len(cpu_stats['Datapoints'])

                # Right-sizing opportunity if CPU <30%
                if avg_cpu < 30:
                    # Get Compute Optimizer recommendation
                    try:
                        optimizer_rec = compute_optimizer.get_ec2_instance_recommendations(
                            instanceArns=[f"arn:aws:ec2:us-east-1::instance/{instance_id}"]
                        )

                        if optimizer_rec['instanceRecommendations']:
                            rec = optimizer_rec['instanceRecommendations'][0]
                            recommended_type = rec['recommendationOptions'][0]['instanceType']
                            estimated_savings = rec['recommendationOptions'][0]['estimatedMonthlySavings']['value']

                            recommendations.append({
                                'instance_id': instance_id,
                                'current_type': instance_type,
                                'recommended_type': recommended_type,
                                'avg_cpu': round(avg_cpu, 2),
                                'monthly_savings': estimated_savings
                            })
                    except Exception as e:
                        print(f"[WARN] Could not get optimizer rec for {instance_id}: {e}")

    print(f"[INFO] Found {len(recommendations)} right-sizing opportunities")
    return recommendations

def analyze_idle_resources() -> Dict:
    """Identify idle and wasted resources"""
    print("[INFO] Analyzing idle resources...")

    idle_resources = {
        'unattached_ebs': [],
        'old_snapshots': [],
        'unused_eips': [],
        'stopped_instances': []
    }

    # Unattached EBS volumes
    volumes = ec2.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )
    for vol in volumes['Volumes']:
        age_days = (datetime.now(vol['CreateTime'].tzinfo) - vol['CreateTime']).days
        if age_days > 30:
            idle_resources['unattached_ebs'].append({
                'volume_id': vol['VolumeId'],
                'size_gb': vol['Size'],
                'age_days': age_days,
                'monthly_cost': vol['Size'] * 0.10  # $0.10/GB-month for gp3
            })

    # Old snapshots (>90 days, not part of backup policy)
    snapshots = ec2.describe_snapshots(OwnerIds=['self'])
    for snap in snapshots['Snapshots']:
        age_days = (datetime.now(snap['StartTime'].tzinfo) - snap['StartTime']).days
        if age_days > 90:
            # Check if it has 'backup' or 'ami' tag (keep these)
            tags = {t['Key']: t['Value'] for t in snap.get('Tags', [])}
            if 'backup' not in tags and 'ami' not in tags.get('Name', '').lower():
                idle_resources['old_snapshots'].append({
                    'snapshot_id': snap['SnapshotId'],
                    'age_days': age_days,
                    'size_gb': snap['VolumeSize']
                })

    # Unused Elastic IPs
    eips = ec2.describe_addresses()
    for eip in eips['Addresses']:
        if 'InstanceId' not in eip:  # Not associated
            idle_resources['unused_eips'].append({
                'allocation_id': eip['AllocationId'],
                'public_ip': eip['PublicIp'],
                'monthly_cost': 3.60  # $0.005/hour
            })

    # Stopped instances (>7 days)
    stopped = ec2.describe_instances(
        Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
    )
    for reservation in stopped['Reservations']:
        for instance in reservation['Instances']:
            # EBS costs still apply
            ebs_cost = sum(
                bdm['Ebs']['VolumeSize'] * 0.10
                for bdm in instance.get('BlockDeviceMappings', [])
                if 'Ebs' in bdm
            )
            idle_resources['stopped_instances'].append({
                'instance_id': instance['InstanceId'],
                'instance_type': instance['InstanceType'],
                'monthly_ebs_cost': ebs_cost
            })

    return idle_resources

def analyze_s3_optimization() -> List[Dict]:
    """Analyze S3 buckets for storage class optimization"""
    print("[INFO] Analyzing S3 storage optimization...")

    s3 = boto3.client('s3')
    recommendations = []

    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets[:10]:  # Sample first 10 buckets
        bucket_name = bucket['Name']

        try:
            # Check if Intelligent-Tiering or lifecycle policies exist
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                has_lifecycle = True
            except:
                has_lifecycle = False

            # Get storage metrics
            cloudwatch_s3 = boto3.client('cloudwatch')
            storage_bytes = cloudwatch_s3.get_metric_statistics(
                Namespace='AWS/S3',
                MetricName='BucketSizeBytes',
                Dimensions=[
                    {'Name': 'BucketName', 'Value': bucket_name},
                    {'Name': 'StorageType', 'Value': 'StandardStorage'}
                ],
                StartTime=datetime.utcnow() - timedelta(days=1),
                EndTime=datetime.utcnow(),
                Period=86400,
                Statistics=['Average']
            )

            if storage_bytes['Datapoints'] and not has_lifecycle:
                size_gb = storage_bytes['Datapoints'][0]['Average'] / (1024**3)
                # Potential 45% savings with lifecycle policies
                recommendations.append({
                    'bucket': bucket_name,
                    'size_gb': round(size_gb, 2),
                    'has_lifecycle': has_lifecycle,
                    'estimated_savings': round(size_gb * 0.023 * 0.45, 2)  # 45% of $0.023/GB
                })
        except Exception as e:
            print(f"[WARN] Error analyzing bucket {bucket_name}: {e}")

    return recommendations

def calculate_total_savings(recommendations: Dict) -> Dict:
    """Calculate total potential savings"""
    total_monthly = 0

    # EC2 right-sizing
    if 'ec2_rightsizing' in recommendations:
        total_monthly += sum(r['monthly_savings'] for r in recommendations['ec2_rightsizing'])

    # Idle resources
    if 'idle_resources' in recommendations:
        idle = recommendations['idle_resources']
        total_monthly += sum(r['monthly_cost'] for r in idle['unattached_ebs'])
        total_monthly += sum(r['monthly_cost'] for r in idle['unused_eips'])

    # S3 optimization
    if 's3_optimization' in recommendations:
        total_monthly += sum(r['estimated_savings'] for r in recommendations['s3_optimization'])

    return {
        'monthly_savings': round(total_monthly, 2),
        'annual_savings': round(total_monthly * 12, 2)
    }

def main():
    """Run complete cost optimization analysis"""
    print("="*70)
    print("AWS Cost Optimization Analysis")
    print("="*70)

    recommendations = {}

    # EC2 Right-sizing
    recommendations['ec2_rightsizing'] = analyze_ec2_right_sizing()

    # Idle Resources
    recommendations['idle_resources'] = analyze_idle_resources()

    # S3 Optimization
    recommendations['s3_optimization'] = analyze_s3_optimization()

    # Calculate savings
    savings = calculate_total_savings(recommendations)

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"EC2 Right-sizing Opportunities: {len(recommendations['ec2_rightsizing'])}")
    print(f"Unattached EBS Volumes: {len(recommendations['idle_resources']['unattached_ebs'])}")
    print(f"Old Snapshots: {len(recommendations['idle_resources']['old_snapshots'])}")
    print(f"Unused Elastic IPs: {len(recommendations['idle_resources']['unused_eips'])}")
    print(f"S3 Optimization Opportunities: {len(recommendations['s3_optimization'])}")
    print("\n" + "-"*70)
    print(f"Estimated Monthly Savings: ${savings['monthly_savings']:,.2f}")
    print(f"Estimated Annual Savings: ${savings['annual_savings']:,.2f}")
    print("="*70)

    # Save to file
    with open('cost-optimization-report.json', 'w') as f:
        json.dump({
            'timestamp': datetime.utcnow().isoformat(),
            'recommendations': recommendations,
            'savings': savings
        }, f, indent=2, default=str)

    print("\n[INFO] Full report saved to: cost-optimization-report.json")

if __name__ == '__main__':
    main()
