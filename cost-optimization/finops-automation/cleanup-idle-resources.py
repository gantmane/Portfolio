#!/usr/bin/env python3
"""
Automated Idle Resource Cleanup
Author: Evgeniy Gantman
Purpose: Automatically clean up idle AWS resources to reduce costs
"""

import boto3
from datetime import datetime, timedelta

ec2 = boto3.client('ec2')
sns = boto3.client('sns')
SNS_TOPIC = 'arn:aws:sns:us-east-1:123456789012:cost-optimization-alerts'

def cleanup_unattached_ebs():
    """Delete unattached EBS volumes older than 30 days"""
    print("[INFO] Cleaning up unattached EBS volumes...")

    volumes = ec2.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )

    deleted_count = 0
    savings = 0

    for vol in volumes['Volumes']:
        age_days = (datetime.now(vol['CreateTime'].tzinfo) - vol['CreateTime']).days

        if age_days > 30:
            volume_id = vol['VolumeId']
            size_gb = vol['Size']
            monthly_cost = size_gb * 0.10

            try:
                ec2.delete_volume(VolumeId=volume_id)
                print(f"[DELETED] {volume_id} ({size_gb}GB, ${monthly_cost:.2f}/mo)")
                deleted_count += 1
                savings += monthly_cost
            except Exception as e:
                print(f"[ERROR] Failed to delete {volume_id}: {e}")

    print(f"[INFO] Deleted {deleted_count} volumes, saving ${savings:.2f}/month")
    return deleted_count, savings

if __name__ == '__main__':
    deleted, savings = cleanup_unattached_ebs()
    print(f"Total savings: ${savings * 12:.2f}/year")
