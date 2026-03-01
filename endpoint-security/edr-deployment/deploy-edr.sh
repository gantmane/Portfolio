#!/bin/bash
set -euo pipefail

# CrowdStrike Falcon EDR Deployment
# Author: Evgeniy Gantman

FALCON_CID="${FALCON_CID:-YOUR_CID_HERE}"
SENSOR_VERSION="7.10"

echo "[INFO] Deploying CrowdStrike Falcon EDR..."

# Deploy Falcon Sensor via DaemonSet (Kubernetes nodes)
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falcon-sensor
  namespace: falcon-system
spec:
  selector:
    matchLabels:
      app: falcon-sensor
  template:
    metadata:
      labels:
        app: falcon-sensor
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: falcon-sensor
        image: crowdstrike/falcon-sensor:${SENSOR_VERSION}
        env:
        - name: FALCONCTL_OPT_CID
          value: "${FALCON_CID}"
        - name: FALCONCTL_OPT_TRACE
          value: "none"
        volumeMounts:
        - name: host-filesystem
          mountPath: /host
      volumes:
      - name: host-filesystem
        hostPath:
          path: /
EOF

echo "[INFO] CrowdStrike Falcon EDR deployed to Kubernetes nodes"
echo "[INFO] For workstations, deploy via your endpoint management solution"
