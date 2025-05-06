# Use the official Google Cloud SDK slim image as a base
# This image includes gcloud, gsutil, bq, and Python.
FROM google/cloud-sdk:slim

# Set the working directory in the container
WORKDIR /app

# Alpine's package manager is apk. Slim image is Debian-based, uses apt-get.
# The slim image should have Python 3 and pip. If not, or for specific versions:
# RUN apt-get update && apt-get install -y python3 python3-pip
#
# Install any additional system dependencies needed by your Python packages' C extensions.
# build-essential is equivalent to build-base on Alpine.
# libffi-dev and libssl-dev (Debian names for openssl-dev) are common.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    curl \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Ensure gcloud components are up-to-date if needed, though slim should be recent.
# RUN gcloud components update --quiet

# Configure gcloud for non-interactive use (already done in base image, but good to be aware)
# RUN gcloud config set core/disable_prompts true
# RUN gcloud config set core/disable_usage_reporting true
# RUN gcloud config set component_manager/disable_update_check true


# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies using pip3
# Using python3 -m pip to ensure we use the pip associated with the Python3 in the image
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Copy the main script into the image
COPY apigee_gitops_tool.py .

# Make the script executable
RUN chmod +x apigee_gitops_tool.py

# Set the entrypoint to your script
ENTRYPOINT ["python3", "/app/apigee_gitops_tool.py"]

# Default command (can be overridden, e.g., for debugging)
# CMD ["--help"]