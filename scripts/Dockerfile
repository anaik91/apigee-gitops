# Use the official Google Cloud SDK slim image as a base
FROM google/cloud-sdk:slim

WORKDIR /app

# Install system dependencies and ensure venv support
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    curl \
    python3-pip \
    python3-venv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment
RUN python3 -m venv /opt/venv

# Activate the virtual environment and install dependencies
# Note: Activating venv in one RUN doesn't persist to next.
# So, we combine venv activation and pip install in one RUN or use full path to pip.
COPY requirements.txt .
RUN . /opt/venv/bin/activate && \
    pip install --no-cache-dir -r requirements.txt

# Copy the main script into the image
COPY apigee_gitops_tool.py .
RUN chmod +x apigee_gitops_tool.py

# Set the entrypoint to use the Python from the virtual environment
ENTRYPOINT ["/opt/venv/bin/python3", "/app/apigee_gitops_tool.py"]

# CMD ["--help"]