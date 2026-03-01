#!/bin/bash
################################################################################
# KUBERNETES SECURITY THREAT HUNTING
################################################################################
# Author: Evgeniy Gantman
# Purpose: Hunt for security violations and suspicious activity in Kubernetes
# MITRE ATT&CK: T1611 (Container Escape), T1552 (Credential Access)
# Prerequisites: kubectl access to cluster, jq installed
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_DIR="./k8s_hunt_results_$(date +%Y%m%d_%H%M%S)"
CRITICAL_NAMESPACES="kube-system kube-public kube-node-lease"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${BLUE}=============================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=============================================================================${NC}"
}

print_alert() {
    echo -e "${RED}[!] ALERT: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] WARNING: $1${NC}"
}

print_info() {
    echo -e "${GREEN}[+] $1${NC}"
}

################################################################################
# HUNT 1: Container Escape Attempts
################################################################################

hunt_container_escape() {
    print_header "HUNT: Container Escape Attempts (T1611)"

    local findings=0
    local output_file="$OUTPUT_DIR/container_escape.txt"

    echo "Hunting for privileged containers and dangerous configurations..." > "$output_file"
    echo "" >> "$output_file"

    # Check for privileged containers
    print_info "Checking for privileged containers..."
    privileged_pods=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        select(.spec.containers[]?.securityContext?.privileged == true) |
        "\(.metadata.namespace)/\(.metadata.name) | Privileged: true"')

    if [ -n "$privileged_pods" ]; then
        echo "PRIVILEGED CONTAINERS DETECTED:" >> "$output_file"
        echo "$privileged_pods" >> "$output_file"
        echo "" >> "$output_file"
        findings=$((findings + $(echo "$privileged_pods" | wc -l)))
        print_alert "Found $(echo "$privileged_pods" | wc -l) privileged containers"
    fi

    # Check for hostNetwork usage
    print_info "Checking for hostNetwork usage..."
    hostnetwork_pods=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        select(.spec.hostNetwork == true) |
        "\(.metadata.namespace)/\(.metadata.name) | hostNetwork: true"')

    if [ -n "$hostnetwork_pods" ]; then
        echo "HOST NETWORK ACCESS:" >> "$output_file"
        echo "$hostnetwork_pods" >> "$output_file"
        echo "" >> "$output_file"
        findings=$((findings + $(echo "$hostnetwork_pods" | wc -l)))
        print_alert "Found $(echo "$hostnetwork_pods" | wc -l) pods with hostNetwork"
    fi

    # Check for hostPID usage
    print_info "Checking for hostPID usage..."
    hostpid_pods=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        select(.spec.hostPID == true) |
        "\(.metadata.namespace)/\(.metadata.name) | hostPID: true"')

    if [ -n "$hostpid_pods" ]; then
        echo "HOST PID ACCESS:" >> "$output_file"
        echo "$hostpid_pods" >> "$output_file"
        echo "" >> "$output_file"
        findings=$((findings + $(echo "$hostpid_pods" | wc -l)))
        print_alert "Found $(echo "$hostpid_pods" | wc -l) pods with hostPID"
    fi

    # Check for sensitive host path mounts
    print_info "Checking for sensitive host path mounts..."
    dangerous_mounts=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        select(.spec.volumes[]?.hostPath.path != null) |
        select(
            .spec.volumes[].hostPath.path == "/" or
            .spec.volumes[].hostPath.path == "/proc" or
            .spec.volumes[].hostPath.path == "/sys" or
            .spec.volumes[].hostPath.path == "/var/run/docker.sock" or
            .spec.volumes[].hostPath.path == "/etc"
        ) |
        "\(.metadata.namespace)/\(.metadata.name) | Mounted: \(.spec.volumes[].hostPath.path)"')

    if [ -n "$dangerous_mounts" ]; then
        echo "DANGEROUS HOST PATH MOUNTS:" >> "$output_file"
        echo "$dangerous_mounts" >> "$output_file"
        echo "" >> "$output_file"
        findings=$((findings + $(echo "$dangerous_mounts" | wc -l)))
        print_alert "Found $(echo "$dangerous_mounts" | wc -l) pods with dangerous mounts"
    fi

    # Check for containers running as root
    print_info "Checking for containers running as root..."
    root_containers=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        select(.spec.containers[]?.securityContext?.runAsUser == 0 or
               .spec.securityContext?.runAsUser == 0 or
               (.spec.containers[]?.securityContext?.runAsUser == null and
                .spec.securityContext?.runAsUser == null)) |
        "\(.metadata.namespace)/\(.metadata.name) | Running as: root (UID 0)"')

    if [ -n "$root_containers" ]; then
        echo "CONTAINERS RUNNING AS ROOT:" >> "$output_file"
        echo "$root_containers" >> "$output_file"
        echo "" >> "$output_file"
        print_warning "Found $(echo "$root_containers" | wc -l) containers potentially running as root"
    fi

    echo "Total findings: $findings" >> "$output_file"
    print_info "Container escape hunt complete. Findings: $findings"
    echo ""
}

################################################################################
# HUNT 2: Service Account Token Theft
################################################################################

hunt_service_account_abuse() {
    print_header "HUNT: Service Account Token Abuse (T1528)"

    local findings=0
    local output_file="$OUTPUT_DIR/service_account_abuse.txt"

    echo "Hunting for service account security issues..." > "$output_file"
    echo "" >> "$output_file"

    # Find pods with automountServiceAccountToken enabled
    print_info "Checking for automounted service account tokens..."
    auto_mount_pods=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        select(.spec.automountServiceAccountToken != false) |
        "\(.metadata.namespace)/\(.metadata.name) | SA: \(.spec.serviceAccountName // "default") | automount: enabled"')

    if [ -n "$auto_mount_pods" ]; then
        echo "PODS WITH AUTOMOUNTED SERVICE ACCOUNT TOKENS:" >> "$output_file"
        echo "$auto_mount_pods" >> "$output_file"
        echo "" >> "$output_file"
        print_warning "Found $(echo "$auto_mount_pods" | wc -l) pods with automounted tokens"
    fi

    # Find service accounts with cluster-admin role
    print_info "Checking for service accounts with cluster-admin..."
    cluster_admin_sa=$(kubectl get clusterrolebindings -o json | \
        jq -r '.items[] |
        select(.roleRef.name == "cluster-admin") |
        select(.subjects[]?.kind == "ServiceAccount") |
        "\(.metadata.name) | SA: \(.subjects[].namespace // "N/A")/\(.subjects[].name)"')

    if [ -n "$cluster_admin_sa" ]; then
        echo "SERVICE ACCOUNTS WITH CLUSTER-ADMIN:" >> "$output_file"
        echo "$cluster_admin_sa" >> "$output_file"
        echo "" >> "$output_file"
        findings=$((findings + $(echo "$cluster_admin_sa" | wc -l)))
        print_alert "Found $(echo "$cluster_admin_sa" | wc -l) service accounts with cluster-admin"
    fi

    # Find overly permissive RBAC roles
    print_info "Checking for overly permissive roles..."
    permissive_roles=$(kubectl get clusterroles -o json | \
        jq -r '.items[] |
        select(.rules[]?.verbs[]? == "*" and .rules[]?.resources[]? == "*") |
        "\(.metadata.name) | Wildcard permissions (*, *)"')

    if [ -n "$permissive_roles" ]; then
        echo "OVERLY PERMISSIVE CLUSTER ROLES:" >> "$output_file"
        echo "$permissive_roles" >> "$output_file"
        echo "" >> "$output_file"
        findings=$((findings + $(echo "$permissive_roles" | wc -l)))
        print_alert "Found $(echo "$permissive_roles" | wc -l) roles with wildcard permissions"
    fi

    echo "Total findings: $findings" >> "$output_file"
    print_info "Service account abuse hunt complete. Findings: $findings"
    echo ""
}

################################################################################
# HUNT 3: Suspicious Container Images
################################################################################

hunt_suspicious_images() {
    print_header "HUNT: Suspicious Container Images"

    local findings=0
    local output_file="$OUTPUT_DIR/suspicious_images.txt"

    echo "Hunting for suspicious container images..." > "$output_file"
    echo "" >> "$output_file"

    # Check for images without tags or using 'latest'
    print_info "Checking for untagged or 'latest' images..."
    latest_images=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        .spec.containers[] |
        select(.image | endswith(":latest") or (contains(":") | not)) |
        "\(.image)"' | sort -u)

    if [ -n "$latest_images" ]; then
        echo "IMAGES USING 'latest' TAG OR NO TAG:" >> "$output_file"
        echo "$latest_images" >> "$output_file"
        echo "" >> "$output_file"
        print_warning "Found $(echo "$latest_images" | wc -l) images using latest/no tag"
    fi

    # Check for images NOT from approved registries
    print_info "Checking for images from unapproved registries..."
    approved_registries="gcr.io registry.company.com ecr.amazonaws.com"
    unapproved_images=$(kubectl get pods --all-namespaces -o json | \
        jq -r --arg approved "$approved_registries" '
        .items[] |
        .spec.containers[] |
        select(.image | test($approved) | not) |
        "\(.image)"' | sort -u)

    if [ -n "$unapproved_images" ]; then
        echo "IMAGES FROM UNAPPROVED REGISTRIES:" >> "$output_file"
        echo "$unapproved_images" >> "$output_file"
        echo "" >> "$output_file"
        findings=$((findings + $(echo "$unapproved_images" | wc -l)))
        print_alert "Found $(echo "$unapproved_images" | wc -l) images from unapproved registries"
    fi

    # Check for images with known risky base images
    print_info "Checking for risky base images..."
    risky_images=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        .spec.containers[] |
        select(.image | test("alpine:3.[0-5]|ubuntu:14|centos:6|debian:7")) |
        "\(.image)"' | sort -u)

    if [ -n "$risky_images" ]; then
        echo "OUTDATED/RISKY BASE IMAGES:" >> "$output_file"
        echo "$risky_images" >> "$output_file"
        echo "" >> "$output_file"
        print_warning "Found $(echo "$risky_images" | wc -l) outdated base images"
    fi

    echo "Total findings: $findings" >> "$output_file"
    print_info "Suspicious images hunt complete. Findings: $findings"
    echo ""
}

################################################################################
# HUNT 4: Network Policy Violations
################################################################################

hunt_network_violations() {
    print_header "HUNT: Network Policy Violations"

    local findings=0
    local output_file="$OUTPUT_DIR/network_violations.txt"

    echo "Hunting for network policy violations..." > "$output_file"
    echo "" >> "$output_file"

    # Check for namespaces without network policies
    print_info "Checking for namespaces without network policies..."
    all_namespaces=$(kubectl get namespaces -o json | jq -r '.items[].metadata.name')

    for ns in $all_namespaces; do
        if [[ ! "$CRITICAL_NAMESPACES" =~ $ns ]]; then
            policy_count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
            if [ "$policy_count" -eq 0 ]; then
                echo "Namespace '$ns' has NO network policies" >> "$output_file"
                findings=$((findings + 1))
            fi
        fi
    done

    if [ $findings -gt 0 ]; then
        print_alert "Found $findings namespaces without network policies"
    fi

    # Check for default-allow policies
    print_info "Checking for overly permissive network policies..."
    permissive_policies=$(kubectl get networkpolicies --all-namespaces -o json | \
        jq -r '.items[] |
        select(.spec.ingress == [] or .spec.egress == []) |
        "\(.metadata.namespace)/\(.metadata.name) | Type: Allow-all"')

    if [ -n "$permissive_policies" ]; then
        echo "" >> "$output_file"
        echo "OVERLY PERMISSIVE NETWORK POLICIES:" >> "$output_file"
        echo "$permissive_policies" >> "$output_file"
        print_warning "Found permissive network policies"
    fi

    echo "" >> "$output_file"
    echo "Total findings: $findings" >> "$output_file"
    print_info "Network policy hunt complete. Findings: $findings"
    echo ""
}

################################################################################
# HUNT 5: Secrets Exposure
################################################################################

hunt_secrets_exposure() {
    print_header "HUNT: Secrets Exposure (T1552)"

    local findings=0
    local output_file="$OUTPUT_DIR/secrets_exposure.txt"

    echo "Hunting for exposed secrets..." > "$output_file"
    echo "" >> "$output_file"

    # Check for secrets in environment variables
    print_info "Checking for secrets in environment variables..."
    env_secrets=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] |
        .spec.containers[] |
        select(.env != null) |
        .env[] |
        select(.name | test("PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE"; "i")) |
        select(.value != null) |
        "\(.name): \(.value)"' | head -20)

    if [ -n "$env_secrets" ]; then
        echo "POTENTIAL SECRETS IN ENVIRONMENT VARIABLES (first 20):" >> "$output_file"
        echo "$env_secrets" >> "$output_file"
        echo "" >> "$output_file"
        findings=$((findings + $(echo "$env_secrets" | wc -l)))
        print_alert "Found potential secrets in environment variables"
    fi

    # Check for ConfigMaps with sensitive data
    print_info "Checking ConfigMaps for sensitive data..."
    sensitive_configmaps=$(kubectl get configmaps --all-namespaces -o json | \
        jq -r '.items[] |
        select(.data != null) |
        select(.data | to_entries[] | .value | test("password|secret|api[_-]?key|token"; "i")) |
        "\(.metadata.namespace)/\(.metadata.name)"' | head -20)

    if [ -n "$sensitive_configmaps" ]; then
        echo "CONFIGMAPS WITH POTENTIAL SECRETS (first 20):" >> "$output_file"
        echo "$sensitive_configmaps" >> "$output_file"
        echo "" >> "$output_file"
        print_warning "Found ConfigMaps with potential secrets"
    fi

    echo "Total findings: $findings" >> "$output_file"
    print_info "Secrets exposure hunt complete. Findings: $findings"
    echo ""
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    echo -e "${BLUE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════╗
║     KUBERNETES SECURITY THREAT HUNTING                               ║
║     Author: Evgeniy Gantman                                          ║
║     MITRE ATT&CK: T1611, T1552, T1528                                ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    # Check prerequisites
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}Error: kubectl not found${NC}"
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        echo -e "${RED}Error: jq not found${NC}"
        exit 1
    fi

    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    print_info "Hunt results will be saved to: $OUTPUT_DIR"
    echo ""

    # Verify cluster access
    print_info "Verifying cluster access..."
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}Error: Cannot connect to Kubernetes cluster${NC}"
        exit 1
    fi

    cluster_name=$(kubectl config current-context)
    print_info "Hunting in cluster: $cluster_name"
    echo ""

    # Execute hunts
    hunt_container_escape
    hunt_service_account_abuse
    hunt_suspicious_images
    hunt_network_violations
    hunt_secrets_exposure

    # Summary
    print_header "HUNT SUMMARY"
    echo ""
    echo "Results saved in: $OUTPUT_DIR"
    echo ""
    echo "Files created:"
    ls -lh "$OUTPUT_DIR"
    echo ""

    total_findings=0
    for file in "$OUTPUT_DIR"/*.txt; do
        file_findings=$(grep -c "Total findings:" "$file" 2>/dev/null || echo "0")
        if [ "$file_findings" -gt 0 ]; then
            findings_count=$(grep "Total findings:" "$file" | awk '{print $NF}')
            total_findings=$((total_findings + findings_count))
        fi
    done

    echo "Total security findings across all hunts: $total_findings"
    echo ""

    if [ $total_findings -gt 0 ]; then
        print_alert "SECURITY ISSUES DETECTED - Review hunt results immediately"
        exit 1
    else
        print_info "No critical security issues detected"
        exit 0
    fi
}

# Execute main
main "$@"
