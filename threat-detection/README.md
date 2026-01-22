# Threat Detection

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: Proactive threat detection, hunting, and MITRE ATT&CK coverage

## Overview

This directory contains threat detection capabilities, hunting queries, and purple team exercises for proactive security operations.

## Contents

### [MITRE ATT&CK Mapping](mitre-attack-mapping/)
Quantified threat detection coverage against MITRE ATT&CK framework.
- 85%+ technique coverage across 14 tactics
- Gap analysis with remediation recommendations
- Purple Team validation results

### [Threat Hunting](threat-hunting/)
Production hunting scenarios for proactive threat detection.
- 11 hunting queries (AWS CloudTrail, Kubernetes, Payment Fraud)
- Athena queries for AWS compromise indicators
- Pod escape and privilege escalation detection

### [Purple Team](purple-team/)
Adversary simulation and detection validation.
- Exercise scenarios and procedures
- Detection validation testing
- Red/Blue team coordination

### [Detection Rules](detection-rules/)
Custom detection rule development and lifecycle.

## Key Metrics

| Metric | Value |
|--------|-------|
| MITRE Technique Coverage | 85%+ |
| MITRE Tactic Coverage | 100% (14/14) |
| Hunting Scenarios | 11 production queries |
| Detection Validation | Purple Team tested |

## Related Sections

- [SIEM & SOC](../siem-soc/) - Detection rule deployment
- [Cloud Security](../cloud-security/) - AWS threat detection
- [Kubernetes Security](../kubernetes-security/) - Container threat detection
