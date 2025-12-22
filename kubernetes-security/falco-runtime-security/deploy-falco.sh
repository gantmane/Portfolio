#!/bin/bash
set -euo pipefail

# Falco Runtime Security Deployment Script
# Author: Evgeniy Gantman
# Purpose: Deploy Falco runtime threat detection to Kubernetes cluster

# Configuration
FALCO_VERSION="3.8.4"  # Helm chart version
NAMESPACE="falco"
HELM_RELEASE="falco"
DRIVER_TYPE="${DRIVER_TYPE:-modern_bpf}"  # Options: modern_bpf, ebpf, module

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Please install kubectl."
        exit 1
    fi

    # Check helm
    if ! command -v helm &> /dev/null; then
        log_error "Helm not found. Please install Helm 3.x."
        exit 1
    fi

    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster."
        exit 1
    fi

    # Check kernel version
    local kernel_version
    kernel_version=$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.kernelVersion}')
    log_info "Cluster kernel version: ${kernel_version}"

    log_info "Prerequisites check passed."
}

# Detect best driver type
detect_driver() {
    log_info "Detecting optimal Falco driver..."

    local kernel_version
    kernel_version=$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.kernelVersion}' | cut -d. -f1,2)

    if [[ $(echo "${kernel_version} >= 5.8" | bc -l) -eq 1 ]]; then
        log_info "Kernel ${kernel_version} supports modern BPF. Using modern_bpf driver."
        DRIVER_TYPE="modern_bpf"
    elif [[ $(echo "${kernel_version} >= 4.14" | bc -l) -eq 1 ]]; then
        log_info "Kernel ${kernel_version} supports eBPF. Using ebpf driver."
        DRIVER_TYPE="ebpf"
    else
        log_warn "Old kernel ${kernel_version}. Using kernel module."
        DRIVER_TYPE="module"
    fi
}

# Create namespace
create_namespace() {
    log_info "Creating namespace ${NAMESPACE}..."

    kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

    # Label namespace
    kubectl label namespace "${NAMESPACE}" \
        name=falco \
        security-monitoring=enabled \
        --overwrite

    log_info "Namespace ${NAMESPACE} ready."
}

# Add Falco Helm repository
add_helm_repo() {
    log_info "Adding Falco Helm repository..."

    helm repo add falcosecurity https://falcosecurity.github.io/charts
    helm repo update

    log_info "Helm repository added."
}

# Deploy Falcosidekick (alert router)
deploy_falcosidekick() {
    log_info "Deploying Falcosidekick..."

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: falcosidekick-config
  namespace: ${NAMESPACE}
data:
  config.yaml: |
    slack:
      webhookurl: "${SLACK_WEBHOOK_URL:-}"
      channel: "#security-alerts"
      minimumpriority: "warning"

    pagerduty:
      routingkey: "${PAGERDUTY_ROUTING_KEY:-}"
      minimumpriority: "critical"

    elasticsearch:
      hostport: "elasticsearch.monitoring:9200"
      index: "falco"
      minimumpriority: "debug"

    prometheus:
      extralabels: "cluster:production"

    webhook:
      address: "http://wazuh-manager:55000/security-events"
      minimumpriority: "warning"
EOF

    helm upgrade --install falcosidekick falcosecurity/falcosidekick \
        --namespace "${NAMESPACE}" \
        --version 0.7.9 \
        --set webui.enabled=true \
        --set webui.replicaCount=2 \
        --set config.existingConfigMap=falcosidekick-config

    log_info "Falcosidekick deployed."
}

# Deploy Falco
deploy_falco() {
    log_info "Deploying Falco with ${DRIVER_TYPE} driver..."

    # Create values file
    cat > /tmp/falco-values.yaml <<EOF
driver:
  kind: ${DRIVER_TYPE}
  modernBpf:
    leastPrivileged: true

tty: true

falco:
  grpc:
    enabled: true
    bind_address: "0.0.0.0:5060"

  grpc_output:
    enabled: true

  json_output: true
  json_include_output_property: true
  json_include_tags_property: true

  log_level: info
  log_stderr: true
  log_syslog: true

  priority: debug

  buffered_outputs: true

  syscall_event_drops:
    actions:
      - log
      - alert
    rate: 0.03333
    max_burst: 1000

  webserver:
    enabled: true
    listen_port: 8765
    k8s_healthz_endpoint: /healthz

  metrics:
    enabled: true
    interval: 1h
    output_rule: true
    resource_utilization_enabled: true

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 200m
    memory: 256Mi

tolerations:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
  - effect: NoSchedule
    key: node-role.kubernetes.io/control-plane

podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8765"
  prometheus.io/path: "/metrics"

serviceMonitor:
  enabled: true
  interval: 30s

falcosidekick:
  enabled: true
  fullfqdn: true

customRules:
  pci-dss-rules.yaml: |-
$(cat falco-rules.yaml | sed 's/^/    /')

EOF

    # Deploy Falco
    helm upgrade --install "${HELM_RELEASE}" falcosecurity/falco \
        --namespace "${NAMESPACE}" \
        --version "${FALCO_VERSION}" \
        --values /tmp/falco-values.yaml \
        --wait \
        --timeout 10m

    log_info "Falco deployed successfully."

    # Cleanup
    rm /tmp/falco-values.yaml
}

# Verify deployment
verify_deployment() {
    log_info "Verifying Falco deployment..."

    # Wait for pods to be ready
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/name=falco \
        -n "${NAMESPACE}" \
        --timeout=300s

    # Check DaemonSet status
    local desired_pods
    local ready_pods

    desired_pods=$(kubectl get daemonset "${HELM_RELEASE}" \
        -n "${NAMESPACE}" \
        -o jsonpath='{.status.desiredNumberScheduled}')

    ready_pods=$(kubectl get daemonset "${HELM_RELEASE}" \
        -n "${NAMESPACE}" \
        -o jsonpath='{.status.numberReady}')

    if [[ "${desired_pods}" -eq "${ready_pods}" ]]; then
        log_info "✓ All ${ready_pods} Falco pods are ready"
    else
        log_error "Only ${ready_pods}/${desired_pods} Falco pods are ready"
        return 1
    fi

    # Check driver loaded
    log_info "Checking Falco driver..."
    kubectl logs -n "${NAMESPACE}" -l app.kubernetes.io/name=falco --tail=20 | grep -i "driver loaded" && \
        log_info "✓ Falco driver loaded successfully" || \
        log_warn "Could not verify driver status"

    # List pods
    log_info "Falco pods:"
    kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=falco
}

# Test Falco detection
test_detection() {
    log_info "Testing Falco detection capabilities..."

    log_info "Test 1: Creating a shell in a container (should trigger alert)..."

    # Create test pod
    kubectl run falco-test-shell \
        --image=alpine \
        --restart=Never \
        --rm -i --tty \
        -- sh -c "echo 'Testing Falco shell detection'; sleep 5" &

    sleep 10

    log_info "Test 2: Reading sensitive file (should trigger alert)..."

    kubectl run falco-test-sensitive \
        --image=alpine \
        --restart=Never \
        --rm -i --tty \
        -- sh -c "cat /etc/shadow 2>/dev/null || true; sleep 5" &

    sleep 10

    log_info "Checking Falco alerts..."
    kubectl logs -n "${NAMESPACE}" -l app.kubernetes.io/name=falco --tail=50 | \
        grep -E "Shell spawned|Sensitive file" || \
        log_warn "No alerts found in logs"

    # Cleanup
    kubectl delete pod falco-test-shell falco-test-sensitive --ignore-not-found

    log_info "Detection tests completed."
}

# Display metrics endpoint
show_metrics() {
    log_info "Setting up Prometheus metrics access..."

    cat <<EOF

Falco Prometheus Metrics:
  Port-forward: kubectl port-forward -n ${NAMESPACE} daemonset/${HELM_RELEASE} 8765:8765
  Metrics URL: http://localhost:8765/metrics

Falcosidekick UI:
  Port-forward: kubectl port-forward -n ${NAMESPACE} svc/falcosidekick-ui 2802:2802
  UI URL: http://localhost:2802

EOF
}

# Show recent alerts
show_alerts() {
    log_info "Recent Falco alerts (last 50):"
    kubectl logs -n "${NAMESPACE}" -l app.kubernetes.io/name=falco --tail=50 | \
        jq -r 'select(.priority != null) | "\(.time) [\(.priority)] \(.rule): \(.output)"' 2>/dev/null || \
        kubectl logs -n "${NAMESPACE}" -l app.kubernetes.io/name=falco --tail=50
}

# Configure PagerDuty integration
configure_pagerduty() {
    local routing_key="$1"

    log_info "Configuring PagerDuty integration..."

    kubectl create secret generic falcosidekick-pagerduty \
        -n "${NAMESPACE}" \
        --from-literal=routing-key="${routing_key}" \
        --dry-run=client -o yaml | kubectl apply -f -

    log_info "PagerDuty configured."
}

# Main deployment flow
main() {
    log_info "Starting Falco runtime security deployment..."
    log_info "Target cluster: $(kubectl config current-context)"
    log_info "Driver type: ${DRIVER_TYPE}"

    read -p "Continue with deployment? (yes/no): " confirm
    if [[ "${confirm}" != "yes" ]]; then
        log_warn "Deployment cancelled."
        exit 0
    fi

    check_prerequisites
    detect_driver
    create_namespace
    add_helm_repo
    deploy_falcosidekick
    deploy_falco
    verify_deployment
    test_detection
    show_metrics
    show_alerts

    log_info ""
    log_info "==================================================================="
    log_info "Falco runtime security deployed successfully!"
    log_info "==================================================================="
    log_info ""
    log_info "Next steps:"
    log_info "  1. View alerts: kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=falco -f"
    log_info "  2. Access metrics: kubectl port-forward -n ${NAMESPACE} daemonset/falco 8765:8765"
    log_info "  3. Falcosidekick UI: kubectl port-forward -n ${NAMESPACE} svc/falcosidekick-ui 2802:2802"
    log_info "  4. Configure PagerDuty: ./deploy-falco.sh setup-pagerduty <routing-key>"
    log_info ""
}

# Uninstall
uninstall() {
    log_warn "Uninstalling Falco..."

    read -p "This will remove all Falco components. Continue? (yes/no): " confirm
    if [[ "${confirm}" != "yes" ]]; then
        log_warn "Uninstall cancelled."
        exit 0
    fi

    helm uninstall "${HELM_RELEASE}" -n "${NAMESPACE}" || true
    helm uninstall falcosidekick -n "${NAMESPACE}" || true
    kubectl delete namespace "${NAMESPACE}"

    log_info "Falco uninstalled."
}

# Parse arguments
case "${1:-deploy}" in
    deploy)
        main
        ;;
    uninstall)
        uninstall
        ;;
    test)
        test_detection
        ;;
    alerts)
        show_alerts
        ;;
    setup-pagerduty)
        if [[ -z "${2:-}" ]]; then
            log_error "Usage: $0 setup-pagerduty <routing-key>"
            exit 1
        fi
        configure_pagerduty "$2"
        ;;
    *)
        cat <<EOF
Usage: $0 {deploy|uninstall|test|alerts|setup-pagerduty}
  deploy             - Install Falco runtime security
  uninstall          - Remove Falco
  test               - Test detection capabilities
  alerts             - Show recent alerts
  setup-pagerduty    - Configure PagerDuty integration

Environment Variables:
  DRIVER_TYPE        - Driver type: modern_bpf (default), ebpf, module
  SLACK_WEBHOOK_URL  - Slack webhook for alerts
  PAGERDUTY_ROUTING_KEY - PagerDuty routing key
EOF
        exit 1
        ;;
esac
