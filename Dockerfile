FROM python:3.12.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source code
COPY src/ src/
COPY check_ip/ check_ip/
COPY check_ip_batch/ check_ip_batch/

# Set PYTHONPATH for absolute imports
ENV PYTHONPATH=/app/src

# Default entrypoint
ENTRYPOINT ["python3"]
