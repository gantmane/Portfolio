# Falco

Production deployment: 6-node EKS cluster, 340+ custom rules, real-time Slack + PagerDuty alerting

Stack: Falco 0.37, Falcosidekick, Kubernetes 1.29, eBPF driver, AWS CloudWatch

## Files

| File | Purpose |
|------|---------|
| rules/payment-rules.yaml | PAN read detection, card data file access, payment process anomalies |
| rules/container-escape.yaml | Privileged spawn, mount namespace manipulation, nsenter detection |
| rules/network-anomaly.yaml | Unexpected outbound, reverse shells, ICMP tunneling detection |
