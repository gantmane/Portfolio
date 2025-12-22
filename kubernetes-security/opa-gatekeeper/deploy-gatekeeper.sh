#!/bin/bash
set -euo pipefail

# OPA Gatekeeper Deployment Script
# Author: Evgeniy Gantman
# Purpose: Deploy OPA Gatekeeper with security policies to Kubernetes cluster

# Configuration
GATEKEEPER_VERSION="v3.14.0"
NAMESPACE="gatekeeper-system"
AUDIT_MODE="${AUDIT_MODE:-false}"  # Set to 'true' for initial deployment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Please install kubectl."
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster."
        exit 1
    fi

    log_info "Prerequisites check passed."
}

# Install Gatekeeper
install_gatekeeper() {
    log_info "Installing OPA Gatekeeper ${GATEKEEPER_VERSION}..."

    kubectl apply -f "https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml"

    log_info "Waiting for Gatekeeper deployment..."
    kubectl wait --for=condition=ready pod \
        -l control-plane=controller-manager \
        -n "${NAMESPACE}" \
        --timeout=300s

    kubectl wait --for=condition=ready pod \
        -l control-plane=audit-controller \
        -n "${NAMESPACE}" \
        --timeout=300s

    log_info "Gatekeeper installed successfully."
}

# Deploy Constraint Templates
deploy_constraint_templates() {
    log_info "Deploying Constraint Templates..."

    if [[ -f "constraint-templates.yaml" ]]; then
        kubectl apply -f constraint-templates.yaml
        log_info "Constraint templates deployed."
    else
        log_warn "constraint-templates.yaml not found. Skipping."
    fi

    # Wait for CRDs to be established
    log_info "Waiting for CRDs to be ready..."
    sleep 10
}

# Deploy Constraints
deploy_constraints() {
    log_info "Deploying Constraints..."

    if [[ -f "constraints.yaml" ]]; then
        if [[ "${AUDIT_MODE}" == "true" ]]; then
            log_warn "AUDIT MODE: Setting all constraints to 'dryrun' enforcement"

            # Create temporary file with dryrun enforcement
            sed 's/enforcementAction: deny/enforcementAction: dryrun/g' constraints.yaml > constraints-audit.yaml
            kubectl apply -f constraints-audit.yaml
            rm constraints-audit.yaml
        else
            kubectl apply -f constraints.yaml
        fi

        log_info "Constraints deployed."
    else
        log_warn "constraints.yaml not found. Skipping."
    fi
}

# Verify Deployment
verify_deployment() {
    log_info "Verifying Gatekeeper deployment..."

    # Check controller status
    local controller_ready
    controller_ready=$(kubectl get deployment gatekeeper-controller-manager \
        -n "${NAMESPACE}" \
        -o jsonpath='{.status.readyReplicas}')

    if [[ "${controller_ready}" -ge 1 ]]; then
        log_info "Controller is ready (${controller_ready} replicas)"
    else
        log_error "Controller is not ready"
        return 1
    fi

    # Check audit controller
    local audit_ready
    audit_ready=$(kubectl get deployment gatekeeper-audit \
        -n "${NAMESPACE}" \
        -o jsonpath='{.status.readyReplicas}')

    if [[ "${audit_ready}" -ge 1 ]]; then
        log_info "Audit controller is ready (${audit_ready} replicas)"
    else
        log_error "Audit controller is not ready"
        return 1
    fi

    # List constraint templates
    log_info "Installed Constraint Templates:"
    kubectl get constrainttemplates

    # List constraints
    log_info "Active Constraints:"
    kubectl get constraints --all-namespaces
}

# Test Policies
test_policies() {
    log_info "Testing policy enforcement..."

    # Test 1: Try to create privileged pod (should fail)
    log_info "Test 1: Attempting to create privileged pod (should be denied)..."

    cat <<EOF | kubectl apply -f - 2>&1 | grep -q "denied" && log_info "✓ Privileged pod correctly denied" || log_warn "✗ Test failed"
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: default
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      privileged: true
EOF

    # Clean up test pod if it was created
    kubectl delete pod test-privileged -n default --ignore-not-found

    # Test 2: Create compliant pod (should succeed)
    log_info "Test 2: Creating compliant pod (should succeed)..."

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-compliant
  namespace: default
  labels:
    owner: "devops"
    environment: "test"
    cost-center: "engineering"
spec:
  containers:
  - name: nginx
    image: registry.example.com/nginx:1.21
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
      limits:
        cpu: "200m"
        memory: "256Mi"
    securityContext:
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
EOF

    if [[ $? -eq 0 ]]; then
        log_info "✓ Compliant pod created successfully"
        kubectl delete pod test-compliant -n default
    else
        log_warn "✗ Compliant pod creation failed"
    fi
}

# Display Audit Results
show_audit_results() {
    log_info "Displaying audit results (violations)..."

    echo ""
    echo "=== Constraint Violations (Last Hour) ==="

    for constraint in $(kubectl get constraints -A -o name); do
        violations=$(kubectl get "${constraint}" -o jsonpath='{.status.totalViolations}' 2>/dev/null || echo "0")

        if [[ "${violations}" -gt 0 ]]; then
            constraint_name=$(echo "${constraint}" | cut -d'/' -f2)
            echo -e "${YELLOW}${constraint_name}${NC}: ${violations} violations"
        fi
    done

    echo ""
    log_info "For detailed violations, check the Gatekeeper audit logs:"
    echo "kubectl logs -n ${NAMESPACE} -l control-plane=audit-controller --tail=100"
}

# Enable Metrics
enable_metrics() {
    log_info "Enabling Prometheus metrics..."

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: gatekeeper-controller-metrics
  namespace: ${NAMESPACE}
  labels:
    app: gatekeeper
spec:
  ports:
  - name: metrics
    port: 8888
    protocol: TCP
    targetPort: 8888
  selector:
    control-plane: controller-manager
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: gatekeeper-controller
  namespace: ${NAMESPACE}
spec:
  endpoints:
  - port: metrics
    interval: 30s
  selector:
    matchLabels:
      app: gatekeeper
EOF

    log_info "Metrics endpoint configured."
}

# Main deployment flow
main() {
    log_info "Starting OPA Gatekeeper deployment..."
    log_info "Target cluster: $(kubectl config current-context)"
    log_info "Audit mode: ${AUDIT_MODE}"

    read -p "Continue with deployment? (yes/no): " confirm
    if [[ "${confirm}" != "yes" ]]; then
        log_warn "Deployment cancelled."
        exit 0
    fi

    check_prerequisites
    install_gatekeeper
    deploy_constraint_templates
    deploy_constraints
    verify_deployment
    enable_metrics

    if [[ "${AUDIT_MODE}" == "true" ]]; then
        log_warn "Deployed in AUDIT MODE. Review violations before enforcing."
        show_audit_results
    else
        test_policies
    fi

    log_info "Gatekeeper deployment completed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "  1. Monitor audit logs: kubectl logs -n ${NAMESPACE} -l control-plane=audit-controller"
    log_info "  2. View violations: kubectl get constraints -A"
    log_info "  3. Check metrics: kubectl port-forward -n ${NAMESPACE} svc/gatekeeper-controller-metrics 8888:8888"

    if [[ "${AUDIT_MODE}" == "true" ]]; then
        log_info "  4. After 7 days, switch to enforcement: AUDIT_MODE=false ./deploy-gatekeeper.sh"
    fi
}

# Uninstall function
uninstall() {
    log_warn "Uninstalling OPA Gatekeeper..."

    read -p "This will remove all policies. Continue? (yes/no): " confirm
    if [[ "${confirm}" != "yes" ]]; then
        log_warn "Uninstall cancelled."
        exit 0
    fi

    kubectl delete -f constraints.yaml --ignore-not-found
    kubectl delete -f constraint-templates.yaml --ignore-not-found
    kubectl delete -f "https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml" --ignore-not-found

    log_info "Gatekeeper uninstalled."
}

# Parse arguments
case "${1:-deploy}" in
    deploy)
        main
        ;;
    uninstall)
        uninstall
        ;;
    audit)
        show_audit_results
        ;;
    test)
        test_policies
        ;;
    *)
        echo "Usage: $0 {deploy|uninstall|audit|test}"
        echo "  deploy     - Install Gatekeeper and policies"
        echo "  uninstall  - Remove Gatekeeper"
        echo "  audit      - Show violation summary"
        echo "  test       - Test policy enforcement"
        exit 1
        ;;
esac
