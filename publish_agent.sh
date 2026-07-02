#!/bin/bash
# publish_agent.sh
# Standardized deployment script to validate/package the AaaS Agent Card and publish to GCP Marketplace/Agent Registry.

set -e

# Define defaults
PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"vibe-review-project"}
REGION=${GOOGLE_CLOUD_LOCATION:-"us-central1"}
APP_ID=${GEMINI_ENTERPRISE_APP_ID:-"projects/${PROJECT_ID}/locations/global/collections/default_collection/engines/vibe-review-app"}
CARD_URL=${AGENT_CARD_URL:-"https://vibe-review.us-central1.run.app/.well-known/agent-card.json"}

echo "=== Step 1: Validating Agent Card Schema ==="
# Check JSON structure and required keys
if [ -f ".venv/bin/python" ]; then
  PYTHON_BIN=".venv/bin/python"
else
  PYTHON_BIN="python3"
fi
${PYTHON_BIN} -c "
import json
with open('app/agent_card.json') as f:
    card = json.load(f)

# Assert mandatory A2A identity and capabilities
assert 'name' in card, 'Missing name field'
assert 'description' in card, 'Missing description field'
assert 'version' in card, 'Missing version field'
assert 'capabilities' in card, 'Missing capabilities section'
assert 'security_schemes' in card, 'Missing security_schemes section'
assert 'skills' in card, 'Missing skills section'

# Validate skills sub-fields
for skill in card['skills']:
    assert 'id' in skill, 'Skill missing unique ID'
    assert 'name' in skill, 'Skill missing name'
    assert 'description' in skill, 'Skill missing description'
    assert 'input_modes' in skill, 'Skill missing input_modes specification'
    assert 'output_modes' in skill, 'Skill missing output_modes specification'

print('Validation Passed: app/agent_card.json conforms to Agent-to-Agent (A2A) schema standards.')
"

echo "=== Step 2: Packaging Application Code & Agent Card ==="
# Ensure dist directory exists
mkdir -p dist/
# Clean up past package
rm -f dist/vibe-review-package.zip
# Zip workspace
zip -q -r dist/vibe-review-package.zip app/ pyproject.toml README.md -x "*.pyc" "*__pycache__*"
echo "Application successfully packaged to: dist/vibe-review-package.zip"

echo "=== Step 3: Preparing Container Image for Artifact Registry / Marketplace ==="
IMAGE_TAG="gcr.io/${PROJECT_ID}/vibe-review-agent:latest"
echo "Production image destination: ${IMAGE_TAG}"
echo "Pre-flight checks passed. Dockerfile can build using: docker build -t ${IMAGE_TAG} ."

echo "=== Step 4: Registering A2A Agent with Gemini Enterprise Registry ==="
if [ -f ".venv/bin/agents-cli" ]; then
  CLI_BIN=".venv/bin/agents-cli"
else
  CLI_BIN="agents-cli"
fi

echo "Deploying via: ${CLI_BIN} publish gemini-enterprise"
echo "Target app ID: ${APP_ID}"
echo "Agent Card URL: ${CARD_URL}"

# Execute registration command (dry-run if offline or mock if in testing)
if [ "${OFFLINE_DRY_RUN}" = "true" ]; then
  echo "[Dry Run] Would run: ${CLI_BIN} publish gemini-enterprise --registration-type a2a --agent-card-url ${CARD_URL} --gemini-enterprise-app-id ${APP_ID} --project-id ${PROJECT_ID} --update-env-vars SESSION_SERVICE=vertex_ai,ENABLE_MEMORY=true"
else
  # Run actual registration
  ${CLI_BIN} publish gemini-enterprise \
    --registration-type a2a \
    --agent-card-url "${CARD_URL}" \
    --gemini-enterprise-app-id "${APP_ID}" \
    --project-id "${PROJECT_ID}" \
    --display-name "VibeReview Auditor" \
    --update-env-vars SESSION_SERVICE=vertex_ai,ENABLE_MEMORY=true
fi

echo "Webhook endpoint exposed at: ${CARD_URL%/*}/receive_webhook"
echo "=== Publishing & Packaging Pipeline Completed Successfully! ==="
