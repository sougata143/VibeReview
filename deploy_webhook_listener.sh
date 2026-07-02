#!/bin/bash
# deploy_webhook_listener.sh
# Deploys VibeReview as a Tier 3 custom code review runtime with webhook support and durable sessions.

set -e

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"vibe-review-project"}
REGION=${GOOGLE_CLOUD_LOCATION:-"us-central1"}
SERVICE_NAME="vibe-review-webhook-listener"

echo "=== Step 1: Building and Packaging VibeReview ==="
mkdir -p dist/
rm -f dist/vibe-review-webhook.zip
zip -q -r dist/vibe-review-webhook.zip app/ .agent/ pyproject.toml README.md -x "*.pyc" "*__pycache__*"
echo "Package built at: dist/vibe-review-webhook.zip"

echo "=== Step 2: Deploying to Google Cloud Agent Runtime ==="
if [ "${OFFLINE_DRY_RUN}" = "true" ]; then
  echo "[Dry Run] Would execute:"
  echo "agents-cli deploy \\"
  echo "  --project-id ${PROJECT_ID} \\"
  echo "  --location ${REGION} \\"
  echo "  --service-name ${SERVICE_NAME} \\"
  echo "  --package-path dist/vibe-review-webhook.zip \\"
  echo "  --update-env-vars SESSION_SERVICE=vertex_ai,ENABLE_MEMORY=true,ENABLE_SKILLS=true"
else
  agents-cli deploy \
    --project-id "${PROJECT_ID}" \
    --location "${REGION}" \
    --service-name "${SERVICE_NAME}" \
    --package-path dist/vibe-review-webhook.zip \
    --update-env-vars SESSION_SERVICE=vertex_ai,ENABLE_MEMORY=true,ENABLE_SKILLS=true
fi

echo "=== Step 3: Webhook Registration Info ==="
echo "Configure your GitHub repository webhook with the following details:"
echo "1. Payload URL: https://${SERVICE_NAME}-${PROJECT_ID}.run.app/receive_webhook"
echo "2. Content type: application/json"
echo "3. Event triggers: Let me select individual events -> Pull requests"
echo "4. SSL verification: Enabled"
echo "========================================================="
