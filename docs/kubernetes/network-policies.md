# Network Policies

Kubernetes network segmentation with Cilium and Calico.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/network-policies){ .md-button .md-button--primary }

---

## Overview

Micro-segmentation implementation using Kubernetes Network Policies for PCI DSS compliant workload isolation.

## Default Deny Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

---

## Namespace Isolation

### PCI DSS Cardholder Data Environment

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cde-isolation
  namespace: cardholder-data
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              pci-zone: cde
        - namespaceSelector:
            matchLabels:
              pci-zone: dmz
          podSelector:
            matchLabels:
              role: api-gateway
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              pci-zone: cde
```

---

## Service-to-Service Policies

### Payment Service

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-service
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

---

## Egress Filtering

### Allow Only Required External

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: external-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      external-access: "true"
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8  # Internal only
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443  # HTTPS only
```

---

## Cilium Enhanced Policies

### L7 HTTP Filtering

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-l7-policy
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: frontend
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "/api/v1/.*"
              - method: "POST"
                path: "/api/v1/payments"
```

---

## Source Files

| File | Description |
|------|-------------|
| [network-policies/](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/network-policies) | Policy definitions |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/kubernetes-security/network-policies/README.md) | Implementation guide |
