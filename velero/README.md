# Velero — Kubernetes Backup & DR

| File | Purpose |
|------|---------|
| `install/values.yaml` | Helm values — AWS plugin, CSI, metrics, resource limits |
| `schedules/daily-cluster-backup.yaml` | Full cluster backup, 02:00 UTC, 30-day retention |
| `schedules/hourly-pvc-backup.yaml` | PVC-only backup, every hour, 7-day retention |
| `schedules/pre-upgrade-backup.yaml` | Manual pre-upgrade snapshot template, 90-day retention |
| `backup-locations/aws-s3.yaml` | AWS S3 primary storage location |
| `backup-locations/minio.yaml` | MinIO self-hosted secondary/DR storage location |
| `restore/restore-template.yaml` | Restore template with namespace mapping for DR |
