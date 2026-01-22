# API Security

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: API protection framework with WAF, rate limiting, and authentication

## Overview

This directory contains API security implementations including AWS WAF configurations, rate limiting strategies, and authentication mechanisms for protecting 120+ production endpoints.

## Contents

### [Gateway Protection](gateway-protection/)
AWS WAF and API Gateway security configurations.
- 12 WAF rule groups
- SQL injection and XSS protection
- Card testing attack prevention
- Bot management

### [Rate Limiting](rate-limiting/)
Tiered rate limiting implementation.
- Free/Standard/Premium tier limits
- Per-endpoint throttling
- Burst handling

## Key Metrics

| Metric | Value |
|--------|-------|
| Endpoints Protected | 120+ |
| Attacks Blocked | 50,000+/month |
| WAF Rule Groups | 12 |
| API Availability | 99.98% |
| Daily Requests | 2.5M |
| Security Cost | $520/month |

## Protection Layers

1. **CloudFront** - DDoS protection, edge caching
2. **AWS WAF** - Application layer filtering
3. **API Gateway** - Request validation, throttling
4. **Lambda Authorizers** - JWT validation
5. **mTLS** - Service-to-service authentication

## WAF Rule Groups

| Rule Group | Purpose |
|------------|---------|
| SQL Injection | Block SQLi attempts |
| XSS Protection | Prevent cross-site scripting |
| Card Testing | Detect bulk card validation |
| Rate Limiting | Request throttling |
| Geo Blocking | Regional restrictions |
| Bot Control | Automated traffic management |

## Related Sections

- [Cloud Security](../cloud-security/) - AWS WAF/Shield configurations
- [Network Security](../network-security/) - Network layer protection
- [Compliance](../compliance/) - PCI DSS API requirements
