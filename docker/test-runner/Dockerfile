FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libsecp256k1-dev \
    pkg-config \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements files
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

# Install additional test dependencies
RUN pip install --no-cache-dir \
    pytest-html \
    pytest-json-report \
    pytest-benchmark \
    pytest-xdist

# Create directories for test reports
RUN mkdir -p /app/test-reports /app/htmlcov

# Create non-root user
RUN useradd -m -u 1000 tester && chown -R tester:tester /app
USER tester

# Set Python path
ENV PYTHONPATH=/app

# Default command runs all tests
CMD ["python", "-m", "pytest", "--tb=short", "--cov=nitro_wallet", "--cov=application", "--cov-report=html:/app/htmlcov", "--cov-report=xml:/app/test-reports/coverage.xml", "--junitxml=/app/test-reports/junit.xml"]