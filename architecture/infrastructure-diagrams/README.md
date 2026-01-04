# Infrastructure Architecture & Diagrams

**Author**: Evgeniy Gantman
**Architectures Documented**: 25+
**Security Zones**: 6 (DMZ, App, DB, etc.)
**Compliance**: PCI DSS network segmentation

## Overview
Comprehensive infrastructure architecture documentation including network diagrams, security zones, data flows, and threat models for 25+ critical systems.

## Key Diagrams
1. **High-Level Architecture**: Multi-region AWS infrastructure
2. **Network Diagram**: VPCs, subnets, security groups
3. **Security Zones**: DMZ, application, database, management
4. **Data Flow Diagrams**: PII/PHI data paths (PCI DSS)
5. **Threat Model**: STRIDE analysis
6. **Zero Trust Architecture**: Identity, device, network layers

## Security Zones
- **DMZ**: Public-facing (ALB, CloudFront)
- **Application Tier**: Private subnets (EKS, ECS)
- **Database Tier**: Isolated subnets (RDS, Aurora)
- **Management**: Bastion hosts, VPN
- **Security**: SIEM, scanners, monitoring
- **Backup**: Isolated backup infrastructure

## Technology Stack
- Lucidchart (diagramming)
- draw.io (open source)
- Visio (enterprise)
- Terraform (IaC documentation)

## Resume Achievements
- **"25+ architectures documented"**: Comprehensive documentation
- **"6 security zones"**: Defense in depth
- **"PCI DSS network segmentation"**: Compliance-driven design
- **"Multi-region architecture"**: High availability design
