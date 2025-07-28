FROM python:3.11-slim

# Install system dependencies including build tools for C extensions
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    make \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 enclave && chown -R enclave:enclave /app
USER enclave

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

EXPOSE 8001

CMD ["python", "server.py"]