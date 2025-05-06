# Use the official Python 3 Alpine image as a base
FROM python:3.11-alpine

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
# - build-base: For compiling some Python packages if they have C extensions (e.g., cryptography, though not directly used by current script)
# - libffi-dev: Dependency for some Python packages
# - openssl-dev: For SSL capabilities
# We try to keep this minimal. If 'pip install' fails for a specific package,
# you might need to add more Alpine packages here (e.g., specific -dev libraries).
RUN apk add --no-cache build-base libffi-dev openssl-dev curl

# Optional: Install gcloud CLI if you want to use ADC via `gcloud auth application-default login`
# This adds significant size to the image. Only include if necessary.
# RUN apk add --no-cache google-cloud-sdk \
#     && gcloud config set core/disable_usage_reporting true \
#     && gcloud config set component_manager/disable_update_check true

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the main script into the image
# Alternatively, you can mount this at runtime
COPY apigee_gitops_tool.py .

# Make the script executable (optional, but good practice)
RUN chmod +x apigee_gitops_tool.py

# Set the entrypoint to your script
# This allows you to run 'docker run <image_name> --org ...'
ENTRYPOINT ["python3", "/app/apigee_gitops_tool.py"]

# Default command (can be overridden)
# CMD ["--help"]