# ArgoCD GitOps

![ArgoCD](https://img.shields.io/badge/ArgoCD-2.10-EF7B4D?logo=argo&logoColor=white)
![Keycloak](https://img.shields.io/badge/Keycloak-OIDC-4D4D4D?logo=keycloak&logoColor=white)
![Kubernetes](https://img.shields.io/badge/EKS-3%20clusters-326CE5?logo=kubernetes&logoColor=white)
![Redis HA](https://img.shields.io/badge/Redis-HA%20%2B%20HAProxy-DC382D?logo=redis&logoColor=white)
![GitOps](https://img.shields.io/badge/GitOps-drift%20detection-brightgreen)

Production deployment: GitOps for 3 EKS clusters, Keycloak OIDC, Prometheus metrics, sync windows for security tools

Stack: ArgoCD 2.10, Helm, Keycloak OIDC, Redis HA, kube-prometheus-stack

!!! tip "Production GitOps Posture"
    All clusters run with `selfHeal: true` and `prune: true` — any manual change to cluster state is automatically reverted within 3 minutes. Security tooling (Kyverno, Falco, Wazuh) has dedicated sync windows to prevent accidental policy disruption during business hours.

## Files

| Path | Description |
|------|-------------|
| `install/values.yaml` | Helm values — HA (3 replicas), Keycloak OIDC, Prometheus metrics |
| `projects/infrastructure.yaml` | AppProject — cluster-wide resources (Vault, cert-manager, ingress) |
| `projects/security.yaml` | AppProject — security tooling (Kyverno, Falco, Wazuh, OPA) |
| `projects/applications.yaml` | AppProject — business workloads (production, staging, development) |
| `applications/vault.yaml` | Application — HashiCorp Vault HA (Raft, 3 nodes) |
| `applications/external-secrets.yaml` | Application — External Secrets Operator |
| `applications/kyverno.yaml` | Application — Kyverno policy engine HA |
| `applications/monitoring.yaml` | Application — kube-prometheus-stack (Prometheus + Grafana) |
| `rbac/admin-policy.csv` | RBAC — full access (platform-team, security-team, argocd-admins) |
| `rbac/readonly-policy.csv` | RBAC — view only (dev-team, auditors, default fallback) |

---

## View Code

=== "Helm Values (HA + OIDC)"

    !!! danger "Security Control — Default Deny RBAC"
        `policy.default: role:readonly` means every user who authenticates gets read-only access by default. Elevated access requires explicit group membership in Keycloak, mapped to ArgoCD roles via the `groups` OIDC claim. No one gets admin by accident.

    !!! info "Keycloak OIDC Integration"
        The `groups` claim is marked `essential: true` — authentication fails if Keycloak does not return group membership. This prevents users from logging in with an empty group set and silently inheriting only the readonly fallback. Groups drive all RBAC decisions.

    !!! tip "Best Practice — Redis HA with HAProxy"
        ArgoCD uses Redis as its in-memory state cache. Single-node Redis is a single point of failure for the entire control plane. Redis HA with HAProxy provides active/passive failover — if the Redis primary fails, HAProxy reroutes to a replica within seconds without ArgoCD restart.

    3-replica server, 2-replica repo-server, Redis HA with HAProxy. Keycloak OIDC via groups claim.
    Default policy: `role:readonly` — all access must be explicitly granted. ServiceMonitors for Prometheus.

    ??? example "Full Helm Values — install/values.yaml"
        ```yaml title="install/values.yaml"
        global:
          image:
            tag: v2.10.0

        ## ── Controller ──────────────────────────────────────────────────────────────
        controller:
          replicas: 1
          resources:
            requests: { cpu: 250m, memory: 256Mi }
            limits:   { cpu: 1000m, memory: 1Gi }
          metrics:
            enabled: true
            serviceMonitor:
              enabled: true
              namespace: monitoring

        ## ── Server — 3 replicas for HA ──────────────────────────────────────────────
        server:
          replicas: 3
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits:   { cpu: 500m, memory: 512Mi }
          metrics:
            enabled: true
            serviceMonitor:
              enabled: true
              namespace: monitoring
          config:
            ## OIDC via Keycloak — groups claim drives RBAC
            oidc.config: |
              name: Keycloak
              issuer: https://keycloak.gantmanbiz.com/realms/homelab
              clientID: argocd
              clientSecret: $oidc.keycloak.clientSecret
              requestedScopes: [openid, profile, email, groups]
              requestedIDTokenClaims:
                groups:
                  essential: true
            url: https://argocd.gantmanbiz.com
            application.instanceLabelKey: argocd.argoproj.io/app-name
            ## Custom health check for cert-manager Certificate resources
            resource.customizations.health.cert-manager.io_Certificate: |
              hs = {}
              if obj.status ~= nil then
                if obj.status.conditions ~= nil then
                  for i, condition in ipairs(obj.status.conditions) do
                    if condition.type == "Ready" and condition.status == "False" then
                      hs.status = "Degraded"
                      hs.message = condition.message
                      return hs
                    end
                    if condition.type == "Ready" and condition.status == "True" then
                      hs.status = "Healthy"
                      return hs
                    end
                  end
                end
              end
              hs.status = "Progressing"
              hs.message = "Waiting for certificate"
              return hs

        ## ── Repo Server — 2 replicas ────────────────────────────────────────────────
        repoServer:
          replicas: 2
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits:   { cpu: 500m, memory: 512Mi }

        ## ── ApplicationSet Controller — 2 replicas ──────────────────────────────────
        applicationSet:
          replicas: 2

        ## ── Redis HA with HAProxy ────────────────────────────────────────────────────
        redis-ha:
          enabled: true
          haproxy:
            enabled: true
            resources:
              requests: { cpu: 50m,  memory: 64Mi }
              limits:   { cpu: 200m, memory: 128Mi }

        ## ── RBAC — default deny; groups mapped from Keycloak ────────────────────────
        configs:
          rbac:
            policy.default: role:readonly   # Least privilege default
            policy.csv: |
              p, role:admin, applications, *, */*, allow
              p, role:admin, clusters,     *, *, allow
              p, role:admin, repositories, *, *, allow
              p, role:admin, projects,     *, *, allow
              g, argocd-admins,   role:admin
              g, argocd-readonly, role:readonly
            scopes: "[groups]"
        ```

=== "Vault Application"

    !!! tip "Best Practice — ignoreDifferences for Webhooks"
        `MutatingWebhookConfiguration.caBundle` is injected at runtime by cert-manager — it changes on every cert rotation. Without `ignoreDifferences`, ArgoCD would detect this as drift and trigger a sync, which would overwrite the live caBundle with the empty Git value, breaking admission webhooks. This is a common production pitfall.

    !!! info "Semver Image Update Strategy"
        `argocd-image-updater` watches for new Vault Helm chart versions matching `0.28.*`. When a patch is released, it opens a PR updating the `targetRevision`. Patch versions go through the normal review pipeline — no manual version bumps.

    !!! danger "Security Control — selfHeal + prune"
        `selfHeal: true` reverts any manual `kubectl` change to Vault within the ArgoCD sync interval (default 3 minutes). `prune: true` removes any resource not present in Git. `allowEmpty: false` prevents accidentally syncing to an empty state, which would delete all Vault pods.

    ArgoCD Application for Vault HA. Automated prune + self-heal. Semver image update strategy.
    ignoreDifferences for MutatingWebhookConfiguration caBundle — prevents reconciliation thrash.

    ??? example "Full Application — applications/vault.yaml"
        ```yaml title="applications/vault.yaml"
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata:
          name: vault
          namespace: argocd
          labels:
            app.kubernetes.io/component: secrets-management
            app.kubernetes.io/part-of: infrastructure
          annotations:
            argocd-image-updater.argoproj.io/image-list: vault=hashicorp/vault
            argocd-image-updater.argoproj.io/vault.update-strategy: semver
          finalizers:
            - resources-finalizer.argocd.argoproj.io
        spec:
          project: infrastructure

          source:
            repoURL: https://helm.releases.hashicorp.com
            chart: vault
            targetRevision: "0.28.*"
            helm:
              releaseName: vault
              values: |
                global:
                  enabled: true
                  tlsDisable: false

                server:
                  ha:
                    enabled: true
                    replicas: 3
                    raft:
                      enabled: true
                      setNodeId: true
                      config: |
                        ui = true
                        listener "tcp" {
                          tls_disable = 0
                          address = "[::]:8200"
                          cluster_address = "[::]:8201"
                          tls_cert_file = "/vault/userconfig/vault-ha-tls/vault.crt"
                          tls_key_file  = "/vault/userconfig/vault-ha-tls/vault.key"
                          tls_client_ca_file = "/vault/userconfig/vault-ha-tls/vault.ca"
                        }
                        storage "raft" { path = "/vault/data" }
                        service_registration "kubernetes" {}

                  resources:
                    requests: { memory: 256Mi, cpu: 250m }
                    limits:   { memory: 512Mi, cpu: 500m }

                  readinessProbe:
                    enabled: true
                    path: /v1/sys/health?standbyok=true

                injector:
                  enabled: true
                  replicas: 2

          destination:
            server: https://kubernetes.default.svc
            namespace: vault

          syncPolicy:
            automated:
              prune:     true    # Remove resources not in Git
              selfHeal:  true    # Revert manual cluster changes
              allowEmpty: false  # Never sync to an empty state
            syncOptions:
              - CreateNamespace=true
              - PrunePropagationPolicy=foreground
              - PruneLast=true
              - RespectIgnoreDifferences=true
            retry:
              limit: 5
              backoff:
                duration:    5s
                factor:      2
                maxDuration: 3m

          # Webhook caBundle is injected at runtime — ignore to prevent reconciliation loop
          ignoreDifferences:
            - group: admissionregistration.k8s.io
              kind: MutatingWebhookConfiguration
              jsonPointers:
                - /webhooks/0/clientConfig/caBundle
        ```

=== "Security AppProject"

    !!! danger "Security Control — Source Repository Allowlist"
        AppProjects enforce which Git/Helm repositories can be used as sources. Workloads in the `security` project can only pull from approved repositories — a compromised CI pipeline cannot deploy a malicious Kyverno policy from an untrusted registry or repository.

    !!! warning "Sync Windows — Policy Change Control"
        Kyverno and OPA Gatekeeper policy changes are restricted to a 1-hour window at 01:00 UTC daily. This prevents admission webhook changes from occurring during business hours when engineer response capacity is lower. Detection tools (Falco, Trivy) update every 15 minutes — fast feedback for signature/rule updates.

    !!! info "Orphaned Resource Monitoring"
        `orphanedResources.warn: true` surfaces any resource in these namespaces that is not tracked by an ArgoCD Application. Security tooling must be intentional — an untracked resource in the `kyverno` namespace is a potential supply chain or insider threat indicator.

    !!! tip "Best Practice — clusterResourceWhitelist Scoping"
        Only explicitly listed cluster-scoped resource types can be managed by this project. The security project can manage `ClusterPolicy`, `ClusterRole`, `ClusterRoleBinding`, and admission webhooks — but cannot touch `Namespace`, `PersistentVolume`, or `StorageClass`. Blast radius is contained.

    AppProject scoping Kyverno, Falco, Wazuh, OPA Gatekeeper. Cluster-scoped resource whitelist
    for ClusterPolicy, CRDs, ValidatingWebhooks. Sync windows: policy changes off-hours (01:00 UTC),
    detection tools every 15 min.

    ??? example "Full AppProject — projects/security.yaml"
        ```yaml title="projects/security.yaml"
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata:
          name: security
          namespace: argocd
          finalizers:
            - resources-finalizer.argocd.argoproj.io
        spec:
          description: "Security platform — policy enforcement, runtime threat detection, compliance"

          ## Approved source repositories — only these Git/Helm repos may be used
          sourceRepos:
            - https://github.com/gantmane/Portfolio.git
            - https://kyverno.github.io/kyverno
            - https://falcosecurity.github.io/charts
            - https://open-policy-agent.github.io/gatekeeper/charts
            - https://wazuh.github.io/wazuh-kubernetes
            - https://aquasecurity.github.io/helm-charts

          ## Allowed destinations — security tools span multiple namespaces
          destinations:
            - { server: https://kubernetes.default.svc, namespace: kyverno }
            - { server: https://kubernetes.default.svc, namespace: falco }
            - { server: https://kubernetes.default.svc, namespace: wazuh }
            - { server: https://kubernetes.default.svc, namespace: opa-gatekeeper }
            - { server: https://kubernetes.default.svc, namespace: trivy-system }

          ## Cluster-scoped resources required by admission webhook tools
          clusterResourceWhitelist:
            - { group: kyverno.io,                    kind: ClusterPolicy }
            - { group: kyverno.io,                    kind: ClusterPolicyReport }
            - { group: constraints.gatekeeper.sh,     kind: "*" }
            - { group: templates.gatekeeper.sh,       kind: ConstraintTemplate }
            - { group: rbac.authorization.k8s.io,     kind: ClusterRole }
            - { group: rbac.authorization.k8s.io,     kind: ClusterRoleBinding }
            - { group: apiextensions.k8s.io,          kind: CustomResourceDefinition }
            - { group: admissionregistration.k8s.io,  kind: ValidatingAdmissionWebhook }
            - { group: admissionregistration.k8s.io,  kind: MutatingAdmissionWebhook }
            - { group: networking.k8s.io,             kind: NetworkPolicy }

          ## Orphaned resource monitoring — security tools must be intentional
          orphanedResources:
            warn: true
            ignore:
              - { group: kyverno.io, kind: PolicyReport }

          ## Sync windows — policy changes require off-hours window to avoid disruption
          syncWindows:
            - kind: allow
              schedule: "0 1 * * *"    # Daily 01:00 UTC — policy engine changes
              duration: 1h
              applications: [kyverno, opa-gatekeeper]
            - kind: allow
              schedule: "*/15 * * * *" # Every 15 min — detection rule updates
              duration: 5m
              applications: [falco, trivy]

          ## Project-level RBAC
          roles:
            - name: security-admin
              description: Full access to security project (security team)
              policies:
                - p, proj:security:security-admin, applications, *, security/*, allow
                - p, proj:security:security-admin, repositories, *, *, allow
              groups: [argocd-admins, security-team]
            - name: security-readonly
              description: View security policies and reports
              policies:
                - p, proj:security:security-readonly, applications, get, security/*, allow
              groups: [argocd-readonly, dev-team]
        ```
