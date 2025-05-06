#!/bin/bash

echo "Starting Apigee GitOps script for resource type: $RESOURCE_TYPE"
JOB_STATUS="SUCCESS"

KEY_FILE_PATH="/tmp/sa-key.json"
echo "$GCP_SA_KEY_JSON" > "$KEY_FILE_PATH"
chmod 400 "$KEY_FILE_PATH"
gcloud auth activate-service-account --key-file="$KEY_FILE_PATH" --project="$GCP_PROJECT_ID_FOR_LOGGING"
gcloud config set project "$APIGEE_ORGANIZATION"
SCRIPT_ARGS="--org \"$APIGEE_ORGANIZATION\" --path \"apigee-gitops-repo/$CONFIG_PATH_IN_REPO\" --keyfile \"$KEY_FILE_PATH\" -t \"$RESOURCE_TYPE\" -v"
if [ -n "$APIGEE_ENVIRONMENT" ]; then
    SCRIPT_ARGS="$SCRIPT_ARGS --env \"$APIGEE_ENVIRONMENT\""
fi
if [ "$APPLY_CHANGES" = "true" ]; then
    SCRIPT_ARGS="$SCRIPT_ARGS --ensure-git-state"
    echo "WARNING: --ensure-git-state IS ENABLED. CHANGES WILL BE APPLIED."
else
    echo "INFO: Running in dry-run mode (--ensure-git-state is OFF)."
fi

echo "Executing: python3 /app/apigee_gitops_tool.py $SCRIPT_ARGS"
# Capture exit code of the python script
set +e # Disable exit on error temporarily
python3 /app/apigee_gitops_tool.py "$SCRIPT_ARGS"
SCRIPT_EXIT_CODE=$?
set -e # Re-enable exit on error

if [ $SCRIPT_EXIT_CODE -ne 0 ]; then
    echo "Python script failed with exit code $SCRIPT_EXIT_CODE"
    JOB_STATUS="FAILURE"
else
    echo "Python script completed successfully."
fi

# --- Notification Stage (Log to Google Cloud Logging) ---
LOG_NAME="concourse-apigee-gitops-jobs" # Common log name for all jobs
CONCOURSE_URL="${ATC_EXTERNAL_URL:-unknown-concourse-url}" # Get Concourse URL if available
BUILD_LINK="$CONCOURSE_URL/teams/$CONCOURSE_TEAM_NAME/pipelines/$CONCOURSE_PIPELINE_NAME/jobs/$CONCOURSE_JOB_NAME/builds/$CONCOURSE_BUILD_NAME"

# Prepare JSON payload for structured logging
JSON_PAYLOAD=$(cat <<EOF
{
    "message": "Concourse job '$CONCOURSE_JOB_NAME' for Apigee resource '$RESOURCE_TYPE' finished with status: $JOB_STATUS.",
    "concourse": {
    "team": "$CONCOURSE_TEAM_NAME",
    "pipeline": "$CONCOURSE_PIPELINE_NAME",
    "job": "$CONCOURSE_JOB_NAME",
    "build_id": "$CONCOURSE_BUILD_ID",
    "build_name": "$CONCOURSE_BUILD_NAME",
    "build_link": "$BUILD_LINK"
    },
    "apigee_org": "$APIGEE_ORGANIZATION",
    "apigee_env": "${APIGEE_ENVIRONMENT:-N/A}",
    "resource_type_processed": "$RESOURCE_TYPE",
    "apply_changes_enabled": "$APPLY_CHANGES",
    "script_exit_code": "$SCRIPT_EXIT_CODE"
}
EOF
)

echo "Attempting to write log to Google Cloud Logging..."
gcloud logging write "$LOG_NAME" "$JSON_PAYLOAD" --payload-type=json --project="$GCP_PROJECT_ID_FOR_LOGGING" \
    --severity=$(if [ "$JOB_STATUS" = "SUCCESS" ]; then echo "INFO"; else echo "ERROR"; fi)

# Clean up
rm -f "$KEY_FILE_PATH"
gcloud auth revoke --all 2>/dev/null || true # Revoke SA creds used by gcloud

echo "Apigee GitOps script and logging finished for resource type: $RESOURCE_TYPE"

# Write status to an output file for Concourse (optional, but good for chaining)
echo "$JOB_STATUS" > task-status/status.txt

# Ensure the task exits with the script's exit code if it failed,
# or if logging fails and we want to mark the task as failed.
if [ "$JOB_STATUS" = "FAILURE" ]; then
    exit $SCRIPT_EXIT_CODE # Or exit 1 if you want a generic failure code
fi