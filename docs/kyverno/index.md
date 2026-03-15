# Kyverno

![Kyverno](https://img.shields.io/badge/Kyverno-1.11-326CE5?logo=kubernetes&logoColor=white)
![Cosign](https://img.shields.io/badge/Cosign-Sigstore-4285F4?logo=google&logoColor=white)
![EKS](https://img.shields.io/badge/EKS-1.29-FF9900?logo=amazonaws&logoColor=white)
![CIS](https://img.shields.io/badge/CIS%20K8s-5.2.x-orange)
![Policies](https://img.shields.io/badge/ClusterPolicies-14%20enforced-brightgreen)

Production deployment: 14 ClusterPolicies enforced across 3 EKS clusters, 0 policy exceptions

Stack: Kyverno 1.11, Cosign, EKS 1.29, Sigstore, GitOps via ArgoCD

!!! tip "Production Posture"
    All 14 policies run in `Enforce` (blocking) mode — not `Audit`. Zero policy exceptions granted since deployment. Supply chain integrity enforced via Cosign keyless signatures on every pod admission.

## Files

| File | Purpose |
|------|---------|
| policies/require-image-signature.yaml | Cosign signature verification at admission — supply chain integrity |
| policies/require-run-as-nonroot.yaml | Reject pods running as UID 0 — CIS K8s 5.2.6 |
| policies/restrict-host-path.yaml | Block hostPath volume mounts — container escape prevention |
| policies/restrict-capabilities.yaml | Drop ALL capabilities, allowlist only needed — CIS K8s 5.2.8 |
| policies/block-privileged.yaml | Deny privileged containers and hostPID/hostNetwork |

---

## View Code

=== "Image Signature (Supply Chain)"

    !!! danger "Security Control — Admission Blocking"
        `validationFailureAction: Enforce` blocks unsigned images at the Kubernetes API server before the pod is ever scheduled. No exceptions — a missing Cosign signature is an immediate admission rejection.

    !!! info "MITRE ATT&CK — T1195.002 Compromise Software Supply Chain"
        Keyless Sigstore verification ties every image to a specific CI/CD workflow run via OIDC. An attacker cannot forge a signature without compromising the GitHub Actions OIDC token for that exact workflow.

    !!! warning "PCI DSS 6.3.2 / NIST SP 800-190"
        PCI DSS 6.3.2 requires that all system components are protected from known vulnerabilities. This policy also blocks images with unfixed critical CVEs via vulnerability scan attestation — zero CRITICAL CVEs is enforced at admission.

    Cosign keyless verification via Sigstore transparency log. Blocks unsigned images at admission.
    Requires vulnerability scan attestation with zero critical CVEs. PCI DSS 6.3.2, NIST SP 800-190.

    ??? example "Full Policy — policies/require-image-signature.yaml"
        ```yaml title="policies/require-image-signature.yaml"
        apiVersion: kyverno.io/v1
        kind: ClusterPolicy
        metadata:
          name: require-image-signature
          annotations:
            policies.kyverno.io/title: Require Image Signature
            policies.kyverno.io/category: Supply Chain Security
            policies.kyverno.io/severity: critical
            policies.kyverno.io/description: >-
              All container images must be signed with Cosign using the organization's
              signing key. Images without a valid cryptographic signature are rejected
              at admission time. Enforces supply chain integrity per PCI DSS 6.3.2.
        spec:
          validationFailureAction: Enforce
          background: false

          rules:
            # Verify Sigstore keyless signatures — production and PCI namespaces
            - name: verify-image-signature
              match:
                any:
                  - resources:
                      kinds: [Pod]
                      namespaces: [production, pci-scope, payment]
              exclude:
                any:
                  - resources:
                      namespaces: [kube-system, kyverno, cert-manager]
              verifyImages:
                - imageReferences: ["*"]
                  attestors:
                    - count: 1
                      entries:
                        - keyless:
                            rekor:
                              url: https://rekor.sigstore.dev
                            # OIDC issuer must match the CI/CD provider that signed the image
                            issuer: "https://token.actions.githubusercontent.com"
                            subject: "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main"
                            ctlog:
                              url: https://ctfe.sigstore.dev/test
                  # Block images with unfixed critical CVEs (from vulnerability scan attestation)
                  attestations:
                    - predicateType: https://cosign.sigstore.dev/attestation/vuln/v1
                      conditions:
                        - all:
                            - key: "{{ scanner.result.summary.CRITICAL }}"
                              operator: Equals
                              value: "0"

            # Key-based verification for internal/ECR registry images
            - name: verify-internal-image-signature
              match:
                any:
                  - resources:
                      kinds: [Pod]
                      namespaces: [production, pci-scope, payment]
              verifyImages:
                - imageReferences:
                    - "registry.internal.example.com/*"
                    - "*.dkr.ecr.*.amazonaws.com/*"
                  attestors:
                    - count: 1
                      entries:
                        - keys:
                            publicKeys: |-
                              -----BEGIN PUBLIC KEY-----
                              # Replace with actual Cosign public key
                              -----END PUBLIC KEY-----
                            signatureAlgorithm: sha256

            # Block images from untrusted registries entirely
            - name: block-untrusted-registry
              match:
                any:
                  - resources:
                      kinds: [Pod]
                      namespaces: [production, pci-scope]
              validate:
                message: >-
                  Images must come from approved registries. Image {{ element.image }} is not allowed.
                foreach:
                  - list: "request.object.spec.containers"
                    deny:
                      conditions:
                        all:
                          - key: "{{ element.image }}"
                            operator: AnyNotIn
                            value:
                              - "registry.internal.example.com/*"
                              - "*.dkr.ecr.*.amazonaws.com/*"
                              - "gcr.io/google-containers/*"
                              - "registry.k8s.io/*"
        ```

=== "Block Privileged Containers"

    !!! danger "Security Control — Container Escape Prevention"
        Privileged containers have near-full host root access. This policy blocks all 6 host-isolation vectors: `privileged`, `hostNetwork`, `hostPID`, `hostIPC`, `hostPort`, and `allowPrivilegeEscalation`. Container escape attacks typically require at least one of these vectors.

    !!! info "MITRE ATT&CK — T1611 Escape to Host"
        `privileged: true` is the most direct path to host compromise from a container. `hostPID` allows signaling host processes. `hostNetwork` enables sniffing all cluster traffic. All blocked at admission.

    !!! warning "CIS Kubernetes Benchmark 5.2.1–5.2.9"
        This single policy satisfies CIS K8s controls 5.2.1 (privileged), 5.2.2 (hostPID), 5.2.3 (hostIPC), and 5.2.5 (hostNetwork). Verified compliant across all 3 EKS clusters via Kyverno policy reports.

    Blocks `privileged: true`, `hostNetwork`, `hostPID`, `hostIPC`, and `hostPort` usage.
    Covers all 6 host-isolation vectors. CIS Kubernetes 5.2.1–5.2.9, PCI DSS 6.2.4.

    ??? example "Full Policy — policies/block-privileged.yaml"
        ```yaml title="policies/block-privileged.yaml"
        apiVersion: kyverno.io/v1
        kind: ClusterPolicy
        metadata:
          name: block-privileged
          annotations:
            policies.kyverno.io/title: Block Privileged Containers and Host Namespace Sharing
            policies.kyverno.io/category: Pod Security Standards / Baseline
            policies.kyverno.io/severity: critical
            policies.kyverno.io/description: >-
              Blocks privileged containers and host namespace sharing (hostNetwork,
              hostPID, hostIPC). These settings break container isolation and are the
              most common vectors for container escape attacks.
        spec:
          validationFailureAction: Enforce
          background: true

          rules:
            # Rule 1: Block privileged: true — grants near-full host root access
            - name: block-privileged-containers
              match:
                any:
                  - resources:
                      kinds: [Pod]
              exclude:
                any:
                  - resources:
                      namespaces: [kube-system, kyverno]
              validate:
                message: >-
                  Privileged containers are not allowed. Container {{ element.name }}
                  has securityContext.privileged: true. Reference: CIS Kubernetes 5.2.1.
                foreach:
                  - list: "request.object.spec.containers[]"
                    deny:
                      conditions:
                        any:
                          - key: "{{ element.securityContext.privileged || false }}"
                            operator: Equals
                            value: true

            # Rule 3: Block hostNetwork — allows sniffing all cluster traffic
            - name: block-host-network
              match:
                any:
                  - resources:
                      kinds: [Pod]
              exclude:
                any:
                  - resources:
                      namespaces: [kube-system, kyverno]
              validate:
                message: >-
                  hostNetwork: true is not permitted. Shares the host network namespace.
                  Reference: CIS Kubernetes 5.2.5.
                pattern:
                  spec:
                    =(hostNetwork): false

            # Rule 4: Block hostPID — allows seeing/signaling all host processes
            - name: block-host-pid
              match:
                any:
                  - resources:
                      kinds: [Pod]
              validate:
                message: "hostPID: true is not permitted. Reference: CIS Kubernetes 5.2.2."
                pattern:
                  spec:
                    =(hostPID): false

            # Rule 5: Block hostIPC — allows shared memory attacks across processes
            - name: block-host-ipc
              match:
                any:
                  - resources:
                      kinds: [Pod]
              validate:
                message: "hostIPC: true is not permitted. Reference: CIS Kubernetes 5.2.3."
                pattern:
                  spec:
                    =(hostIPC): false
        ```

=== "Restrict Capabilities"

    !!! danger "Security Control — Linux Capability Hardening"
        `drop: [ALL]` removes every Linux capability from containers, then the allowlist explicitly grants only what is needed. Blocking `SYS_ADMIN` alone eliminates the majority of kernel-level privilege escalation paths. Production namespaces are held to a stricter allowlist than non-production.

    !!! info "MITRE ATT&CK — T1068 Exploitation for Privilege Escalation"
        `SYS_PTRACE` enables reading other processes' memory (debugger-style attacks). `NET_RAW` enables MITM via raw sockets. `SYS_MODULE` allows loading kernel modules — full host compromise. All 13 are blocked even after `drop: ALL` to prevent accidental re-add.

    !!! tip "Best Practice — seccompProfile"
        Capabilities are coarse controls. The `require-seccomp-profile` rule adds a second layer: `RuntimeDefault` seccomp filters ~300 allowed syscalls, blocking the ~200 dangerous ones not addressable by capabilities alone. Defense in depth at the syscall level.

    Enforces `drop: [ALL]` on every container. Blocks 13 dangerous capabilities (SYS_ADMIN, NET_RAW, etc.).
    Production namespaces: only NET_BIND_SERVICE may be re-added. Requires seccompProfile. CIS K8s 5.2.8.

    ??? example "Full Policy — policies/restrict-capabilities.yaml"
        ```yaml title="policies/restrict-capabilities.yaml"
        apiVersion: kyverno.io/v1
        kind: ClusterPolicy
        metadata:
          name: restrict-capabilities
          annotations:
            policies.kyverno.io/title: Restrict Linux Capabilities
            policies.kyverno.io/category: Pod Security Standards / Baseline
            policies.kyverno.io/severity: high
            policies.kyverno.io/description: >-
              All containers must drop ALL Linux capabilities. Only NET_BIND_SERVICE
              may be re-added in production namespaces. Prevents privilege escalation
              through capability abuse.
        spec:
          validationFailureAction: Enforce
          background: true

          rules:
            # Rule 1: Require capabilities.drop: ["ALL"]
            - name: require-drop-all
              match:
                any:
                  - resources:
                      kinds: [Pod]
              exclude:
                any:
                  - resources:
                      namespaces: [kube-system, kyverno]
              validate:
                message: >-
                  Container {{ element.name }} must set capabilities.drop: ["ALL"].
                  Reference: CIS Benchmark 5.2.8.
                foreach:
                  - list: "request.object.spec.containers[]"
                    deny:
                      conditions:
                        all:
                          - key: ALL
                            operator: AnyNotIn
                            value: "{{ element.securityContext.capabilities.drop[] }}"

            # Rule 2: Block 13 dangerous capabilities — never allow even after drop ALL
            - name: block-dangerous-capabilities
              match:
                any:
                  - resources:
                      kinds: [Pod]
              validate:
                message: >-
                  Container {{ element.name }} adds a prohibited capability.
                  Reference: PCI DSS 2.2.1, CIS 5.2.8.
                foreach:
                  - list: "request.object.spec.containers[]"
                    deny:
                      conditions:
                        any:
                          - key: "{{ element.securityContext.capabilities.add[] }}"
                            operator: AnyIn
                            value:
                              - SYS_ADMIN     # kernel-level access — full host compromise
                              - SYS_MODULE    # load kernel modules
                              - SYS_RAWIO
                              - SYS_PTRACE    # debug/read other process memory
                              - SYS_BOOT
                              - NET_ADMIN     # modify network interfaces
                              - NET_RAW       # raw socket — MITM attacks
                              - DAC_READ_SEARCH
                              - SETFCAP
                              - KILL
                              - SYS_NICE
                              - MKNOD
                              - AUDIT_WRITE
                              - AUDIT_CONTROL

            # Rule 3: Production allowlist — only NET_BIND_SERVICE permitted
            - name: enforce-capability-allowlist
              match:
                any:
                  - resources:
                      kinds: [Pod]
                      namespaces: [production, pci-scope, payment]
              validate:
                message: >-
                  Only NET_BIND_SERVICE is permitted in production namespaces.
                  Submit a policy exception for other capabilities.
                foreach:
                  - list: "request.object.spec.containers[]"
                    deny:
                      conditions:
                        any:
                          - key: "{{ element.securityContext.capabilities.add[] }}"
                            operator: AnyNotIn
                            value: [NET_BIND_SERVICE]

            # Rule 5: Require seccompProfile (defense in depth — filters syscalls)
            - name: require-seccomp-profile
              match:
                any:
                  - resources:
                      kinds: [Pod]
                      namespaces: [production, pci-scope, payment]
              validate:
                message: >-
                  Pod must define a seccompProfile. Use RuntimeDefault to block ~40
                  dangerous syscalls. Reference: CIS Kubernetes Benchmark 5.7.2.
                pattern:
                  spec:
                    securityContext:
                      seccompProfile:
                        type: "RuntimeDefault | Localhost"
        ```
