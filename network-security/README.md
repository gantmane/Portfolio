# Network Security

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: Network security controls, IDS/IPS, and micro-segmentation

## Overview

This directory contains network security implementations including firewall configurations, IDS/IPS deployment, micro-segmentation strategies, and zero trust network access.

## Contents

### [Traffic Analysis](traffic-analysis/)
Network traffic analysis and monitoring.
- Flow log analysis
- Anomaly detection
- Bandwidth monitoring

### [Traffic Monitoring](traffic-monitoring/)
Real-time network monitoring configurations.

### [Firewall Configs](firewall-configs/)
AWS Network Firewall and security group management.
- Stateful inspection rules
- Domain filtering
- Protocol enforcement

### [IDS/IPS](ids-ips/)
Intrusion Detection and Prevention Systems.
- Suricata rule configurations
- Alert management
- Threat response automation

### [Micro-segmentation](micro-segmentation/)
Network segmentation strategies.
- VPC design patterns
- Security group policies
- Network ACLs

### [VPN/ZTA](vpn-zta/)
Secure remote access and zero trust architecture.
- VPN configurations
- Zero trust network access
- Identity-based access

## Key Controls

| Control | Implementation |
|---------|----------------|
| **Perimeter Security** | AWS Network Firewall, WAF |
| **East-West Traffic** | Security Groups, Network Policies |
| **IDS/IPS** | Suricata with custom rules |
| **Segmentation** | VPC isolation, micro-segmentation |
| **Remote Access** | VPN with MFA, Zero Trust |

## Network Architecture

- **Hub-and-Spoke** - Centralized egress and inspection
- **Transit Gateway** - Inter-VPC connectivity
- **PrivateLink** - Secure AWS service access
- **VPC Endpoints** - Private API access

## Related Sections

- [Cloud Security](../cloud-security/) - AWS VPC security
- [Kubernetes Security](../kubernetes-security/) - Network policies
- [SIEM & SOC](../siem-soc/) - Network detection (Security Onion)
