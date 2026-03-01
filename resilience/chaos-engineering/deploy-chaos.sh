#!/bin/bash
set -euo pipefail

# Deploy Litmus Chaos Engineering
# Author: Evgeniy Gantman

NAMESPACE="litmus"
LITMUS_VERSION="3.5.0"

echo "[INFO] Installing Litmus Chaos..."

# Create namespace
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Install Litmus via Helm
helm repo add litmuschaos https://litmuschaos.github.io/litmus-helm/
helm repo update

helm install chaos litmuschaos/litmus \
  --namespace "${NAMESPACE}" \
  --version "${LITMUS_VERSION}" \
  --set portal.frontend.service.type=LoadBalancer

# Wait for pods
kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=chaos -n "${NAMESPACE}" --timeout=300s

# Install chaos experiments
kubectl apply -f https://hub.litmuschaos.io/api/chaos/master?file=charts/generic/experiments.yaml -n "${NAMESPACE}"

# Apply custom experiments
kubectl apply -f chaos-experiments.yaml

echo "[INFO] Litmus Chaos deployed!"
echo "[INFO] Access portal: kubectl port-forward -n ${NAMESPACE} svc/chaos-litmus-frontend-service 9091:9091"
