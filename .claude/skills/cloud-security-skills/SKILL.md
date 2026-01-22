---
name: cloud-security-skills
description: Cloud security architecture for AWS, GCP, Azure. Use when designing cloud security, reviewing cloud configurations, implementing CSPM/CWPP, or analyzing cloud attack paths.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.PS-01, PR.DS-01, PR.AA-05, PR.IR-01, ID.AM-02]
mitre_attack_coverage: [T1190, T1078, T1552, T1530, T1619]
---

# Cloud Security Architecture

> **NIST CSF 2.0 Alignment**: PROTECT Function - Platform Security & Data Protection
> Supports cloud infrastructure protection, access control, data encryption, and threat detection

## Quick Reference
**Index:** "AWS IAM least privilege", "Network segmentation", "Cloud data encryption", "CSPM/CWPP" | **Docs:** Cloud Security baselines, Terraform IaC scanning, AWS/GCP/Azure CLI

## Core Capabilities ⇒ NIST CSF Categories

### Identity & Access Management ⇒ PR.AA-05
IAM policy design, least privilege enforcement, SCPs, workload identity, conditional access, and attribute-based controls.
```bash
aws iam get-user-policy --user-name USER --policy-name POLICY
gcloud iam service-accounts get-iam-policy SA-EMAIL
az role assignment list --subscription SUB-ID
```
**Reference:** AWS Organizations, GCP Cloud IAM, Azure Entra ID

### Network Security ⇒ PR.IR-01
VPC architecture, security groups, firewall rules, WAF/DDoS mitigation, network isolation, and zero trust segmentation.
```bash
aws ec2 describe-security-groups --filters Name=group-id,Values=sg-*
gcloud compute firewall-rules list --format=json
az network nsg rule list --resource-group RG --nsg-name NSG
```
**Reference:** AWS VPC, GCP VPC, Azure Virtual Networks

### Data Protection & Encryption ⇒ PR.DS-01
KMS/key vault architecture, key rotation, bucket policies, object ACLs, and database encryption strategies.
```bash
aws kms list-keys && aws kms get-key-rotation-status --key-id KEY-ID
gsutil encryption set gs://BUCKET
az keyvault secret list --vault-name VAULT
```
**Reference:** AWS KMS/Secrets Manager, GCP Cloud KMS, Azure Key Vault

### Cloud Threat Detection ⇒ ID.RA-01
GuardDuty/Security Hub, CloudTrail logging, CSPM/CWPP platforms for anomaly detection, compliance scanning, and workload protection.
```bash
aws cloudtrail start-logging --name TRAIL
aws guardduty list-findings --detector-id DETECTOR-ID
aws securityhub get-compliance-summary
```
**Reference:** AWS GuardDuty/Security Hub, GCP Security Command Center, Azure Defender

### Infrastructure as Code Security ⇒ PR.PS-01
IaC scanning (tfsec, Checkov, Trivy), policy enforcement (OPA, Sentinel), pre-deployment checks, and drift detection.
```bash
tfsec . && checkov -d . --framework terraform && trivy config .
az blueprint published artifact list --blueprint-name BP
```
**Reference:** Terraform/CloudFormation, OPA, AWS Config

## MITRE ATT&CK Coverage
T1190 (WAF/DDoS), T1078 (IAM least privilege), T1552 (Secrets+encryption), T1530 (Bucket policies), T1619 (CSPM controls)

## References
AWS: https://docs.aws.amazon.com/security/ | GCP: https://cloud.google.com/security/best-practices | Azure: https://docs.microsoft.com/azure/security/
