# Calico / Kubernetes Network Policies

Production deployment: 3 clusters, 47 NetworkPolicy objects, 100% namespace coverage

Stack: Calico 3.27, Kubernetes 1.29, EKS, Cilium (secondary cluster), eBPF

## Files

| File | Purpose |
|------|---------|
| policies/default-deny.yaml | Zero-trust baseline — deny all ingress/egress across production/payment namespaces |
| policies/allow-dns.yaml | CoreDNS egress allowance — required after default-deny for service discovery |
| policies/namespace-isolation.yaml | Explicit service-to-service allow rules — gateway→api→database flow |
