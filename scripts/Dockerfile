# Use the official Google Cloud SDK slim image as a base
FROM google/cloud-sdk:slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    curl \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Add --break-system-packages flag
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY apigee_gitops_tool.py .
RUN chmod +x apigee_gitops_tool.py

ENTRYPOINT ["python3", "/app/apigee_gitops_tool.py"]
# CMD ["--help"]