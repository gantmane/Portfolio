# API Security Framework

AWS WAF + API Gateway protecting 120+ endpoints with 99.98% availability.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/api-security/gateway-protection){ .md-button .md-button--primary }

---

## Overview

Enterprise API security framework protecting payment processing APIs, blocking 50,000+ attacks monthly while maintaining high availability.

## Key Metrics

| Metric | Value |
|--------|-------|
| Endpoints Protected | 120+ |
| Attacks Blocked | 50,000+/month |
| Availability | 99.98% |
| Daily Requests | 2.5M |
| Monthly Cost | $520 |

---

## Protection Layers

### Layer 1: AWS WAF

12 rule groups protecting against:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Card Testing Patterns
- Bot Detection

### Layer 2: API Gateway

- Request validation
- Schema enforcement
- Throttling
- Usage plans

### Layer 3: Application

- JWT validation
- API key verification
- mTLS for service-to-service

---

## Rate Limiting

### Tiered Approach

| Tier | Requests/sec | Burst | Use Case |
|------|-------------|-------|----------|
| Free | 10 | 50 | Trial users |
| Standard | 100 | 500 | Regular merchants |
| Premium | 1000 | 5000 | High-volume partners |

### Implementation

```yaml
# API Gateway Usage Plan
UsagePlan:
  Throttle:
    RateLimit: 100
    BurstLimit: 500
  Quota:
    Limit: 10000
    Period: DAY
```

---

## Authentication

### JWT Validation

```yaml
# JWT Authorizer
Authorizer:
  Type: JWT
  Issuer: https://auth.example.com
  Audience: api.example.com
  Claims:
    - scope
    - client_id
    - merchant_id
```

### API Keys

- Generated per merchant
- Rotated every 90 days
- Scoped to specific endpoints

### mTLS

- Service-to-service authentication
- Certificate-based identity
- Mutual verification

---

## WAF Rules

### SQL Injection Protection

```json
{
  "Name": "SQLInjectionRule",
  "Priority": 1,
  "Statement": {
    "SqliMatchStatement": {
      "FieldToMatch": {
        "Body": {}
      },
      "TextTransformations": [
        {"Priority": 0, "Type": "URL_DECODE"},
        {"Priority": 1, "Type": "HTML_ENTITY_DECODE"}
      ]
    }
  },
  "Action": {"Block": {}}
}
```

### Card Testing Detection

```json
{
  "Name": "CardTestingRule",
  "Priority": 5,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 100,
      "AggregateKeyType": "IP"
    }
  },
  "Action": {"Block": {}}
}
```

---

## Monitoring

### CloudWatch Metrics

- Blocked requests by rule
- Request latency (p50, p95, p99)
- 4xx/5xx error rates
- Throttled requests

### Alerting

- Attack spike detection
- Availability degradation
- Unusual traffic patterns

---

## Source Files

| File | Description |
|------|-------------|
| [gateway-protection/](https://github.com/gantmane/Portfolio/tree/main/api-security/gateway-protection) | WAF + API Gateway configs |
| [authentication/](https://github.com/gantmane/Portfolio/tree/main/api-security) | Auth implementations |
| [rate-limiting/](https://github.com/gantmane/Portfolio/tree/main/api-security/rate-limiting) | Rate limiting configs |

---

## Related Projects

- [Cloud Security](../cloud-security/index.md) - AWS security controls
- [Network Security](../cloud-security/index.md) - Network protection
