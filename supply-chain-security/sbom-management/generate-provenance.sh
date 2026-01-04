#!/bin/bash
################################################################################
# SLSA PROVENANCE GENERATION SCRIPT
################################################################################
# Author: Evgeniy Gantman
# Purpose: Generate SLSA v1.0 provenance for container images
# Usage: ./generate-provenance.sh <image-name>
# Requirements: docker, cosign, syft, jq
################################################################################

set -euo pipefail

# Configuration
KMS_KEY_ARN="${KMS_KEY_ARN:-arn:aws:kms:us-east-1:123456789012:key/abc-123}"
BUILDER_ID="https://gitlab.company.com/gitlab-runner/${CI_RUNNER_VERSION:-v15.11.0}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

################################################################################
# Validate inputs
################################################################################

if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <image-name>${NC}"
    echo "Example: $0 registry.company.com/payment-api:v1.2.3"
    exit 1
fi

IMAGE_NAME="$1"
PROVENANCE_FILE="provenance-$(echo "$IMAGE_NAME" | tr '/:' '_').json"
SBOM_FILE="sbom-$(echo "$IMAGE_NAME" | tr '/:' '_').json"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         SLSA PROVENANCE GENERATION                            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

################################################################################
# Check prerequisites
################################################################################

echo -e "${BLUE}[1/6] Checking prerequisites...${NC}"

for cmd in docker cosign syft jq git; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED}Error: $cmd not found${NC}"
        exit 1
    fi
done

echo -e "${GREEN}[✓] All prerequisites met${NC}"
echo ""

################################################################################
# Extract image metadata
################################################################################

echo -e "${BLUE}[2/6] Extracting image metadata...${NC}"

# Pull image if not present
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "Pulling image: $IMAGE_NAME"
    docker pull "$IMAGE_NAME"
fi

# Get image digest
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_NAME" | cut -d'@' -f2)

if [ -z "$IMAGE_DIGEST" ]; then
    echo -e "${RED}Error: Could not extract image digest${NC}"
    exit 1
fi

echo "Image: $IMAGE_NAME"
echo "Digest: $IMAGE_DIGEST"

# Extract build metadata from environment or Git
GIT_COMMIT_SHA="${CI_COMMIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}"
GIT_REPO_URL="${CI_PROJECT_URL:-$(git config --get remote.origin.url 2>/dev/null || echo 'unknown')}"
GIT_REF="${CI_COMMIT_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')}"
PIPELINE_URL="${CI_PIPELINE_URL:-unknown}"
RUNNER_ID="${CI_RUNNER_ID:-unknown}"

BUILD_STARTED_AT="${CI_JOB_STARTED_AT:-$(date -Iseconds)}"
BUILD_FINISHED_AT="$(date -Iseconds)"

echo -e "${GREEN}[✓] Metadata extracted${NC}"
echo ""

################################################################################
# Generate SBOM (Software Bill of Materials)
################################################################################

echo -e "${BLUE}[3/6] Generating SBOM with Syft...${NC}"

syft "$IMAGE_NAME" -o spdx-json > "$SBOM_FILE"

PACKAGE_COUNT=$(jq '.packages | length' "$SBOM_FILE")
echo "Packages detected: $PACKAGE_COUNT"

echo -e "${GREEN}[✓] SBOM generated: $SBOM_FILE${NC}"
echo ""

################################################################################
# Create provenance attestation
################################################################################

echo -e "${BLUE}[4/6] Creating SLSA provenance attestation...${NC}"

# Extract materials (dependencies) from SBOM
MATERIALS=$(jq '[.packages[] | {
  uri: ("pkg:" + (.SPDXID | split("#")[1] | split("/")[0] | ascii_downcase) + "/" + .name + "@" + .versionInfo),
  digest: {
    sha256: (.checksums[]? | select(.algorithm == "SHA256") | .checksumValue)
  }
}] | map(select(.digest.sha256 != null))' "$SBOM_FILE")

# Create in-toto provenance statement
cat > "$PROVENANCE_FILE" <<EOF
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v1.0",
  "subject": [
    {
      "name": "$IMAGE_NAME",
      "digest": {
        "$(echo "$IMAGE_DIGEST" | cut -d':' -f1)": "$(echo "$IMAGE_DIGEST" | cut -d':' -f2)"
      }
    }
  ],
  "predicate": {
    "buildDefinition": {
      "buildType": "https://gitlab.com/gitlab-org/gitlab-runner@v1",
      "externalParameters": {
        "repository": "$GIT_REPO_URL",
        "ref": "$GIT_REF",
        "commit": "$GIT_COMMIT_SHA"
      },
      "internalParameters": {
        "runner_id": "$RUNNER_ID",
        "pipeline_url": "$PIPELINE_URL"
      },
      "resolvedDependencies": $MATERIALS
    },
    "runDetails": {
      "builder": {
        "id": "$BUILDER_ID",
        "version": {}
      },
      "metadata": {
        "invocationId": "$PIPELINE_URL",
        "startedOn": "$BUILD_STARTED_AT",
        "finishedOn": "$BUILD_FINISHED_AT"
      },
      "byproducts": [
        {
          "name": "SBOM",
          "uri": "$SBOM_FILE",
          "digest": {
            "sha256": "$(sha256sum "$SBOM_FILE" | awk '{print $1}')"
          }
        }
      ]
    }
  }
}
EOF

# Validate JSON
if ! jq empty "$PROVENANCE_FILE" 2>/dev/null; then
    echo -e "${RED}Error: Invalid JSON in provenance file${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Provenance created: $PROVENANCE_FILE${NC}"
echo ""

################################################################################
# Sign provenance with Cosign
################################################################################

echo -e "${BLUE}[5/6] Signing provenance with Cosign (AWS KMS)...${NC}"

cosign sign-blob "$PROVENANCE_FILE" \
  --output-signature "${PROVENANCE_FILE}.sig" \
  --output-certificate "${PROVENANCE_FILE}.cert" \
  --key "awskms:///${KMS_KEY_ARN}" \
  --yes

echo -e "${GREEN}[✓] Provenance signed${NC}"
echo "  Signature: ${PROVENANCE_FILE}.sig"
echo "  Certificate: ${PROVENANCE_FILE}.cert"
echo ""

################################################################################
# Attach provenance to image
################################################################################

echo -e "${BLUE}[6/6] Attaching provenance to container image...${NC}"

cosign attach attestation "$IMAGE_NAME" \
  --attestation "$PROVENANCE_FILE" \
  --type slsaprovenance

# Also attach SBOM
cosign attach sbom --sbom "$SBOM_FILE" "$IMAGE_NAME"

echo -e "${GREEN}[✓] Provenance and SBOM attached to image${NC}"
echo ""

################################################################################
# Verification
################################################################################

echo -e "${BLUE}Verifying provenance signature...${NC}"

if cosign verify-attestation "$IMAGE_NAME" \
    --type slsaprovenance \
    --key "awskms:///${KMS_KEY_ARN}" > /dev/null 2>&1; then
    echo -e "${GREEN}[✓] Provenance verification PASSED${NC}"
else
    echo -e "${RED}[!] Provenance verification FAILED${NC}"
    exit 1
fi

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              SLSA PROVENANCE GENERATION COMPLETE              ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Image: $IMAGE_NAME"
echo "Digest: $IMAGE_DIGEST"
echo "Provenance: $PROVENANCE_FILE"
echo "SBOM: $SBOM_FILE"
echo ""
echo "Artifacts created:"
echo "  - $PROVENANCE_FILE (provenance attestation)"
echo "  - ${PROVENANCE_FILE}.sig (signature)"
echo "  - ${PROVENANCE_FILE}.cert (certificate)"
echo "  - $SBOM_FILE (SBOM)"
echo ""
echo "Verification command:"
echo "  cosign verify-attestation $IMAGE_NAME \\"
echo "    --type slsaprovenance \\"
echo "    --key awskms:///$KMS_KEY_ARN"
echo ""
