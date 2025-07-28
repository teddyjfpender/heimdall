FROM python:3.11-slim

# Install system dependencies and development tools
RUN apt-get update && apt-get install -y \
    build-essential \
    libsecp256k1-dev \
    pkg-config \
    curl \
    git \
    vim \
    nano \
    htop \
    jq \
    awscli \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for CDK
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs

# Install AWS CDK
RUN npm install -g aws-cdk@2.98.0

WORKDIR /workspace

# Install Python development tools
RUN pip install --no-cache-dir \
    black \
    isort \
    flake8 \
    mypy \
    bandit \
    pre-commit \
    ipython \
    jupyter \
    pytest \
    pytest-cov \
    boto3

# Create non-root user
RUN useradd -m -u 1000 developer && \
    usermod -aG docker developer && \
    chown -R developer:developer /workspace

USER developer

# Configure git (will be overridden by user)
RUN git config --global user.name "Developer" && \
    git config --global user.email "dev@example.com"

# Set up shell
RUN echo 'alias ll="ls -la"' >> ~/.bashrc && \
    echo 'alias la="ls -A"' >> ~/.bashrc && \
    echo 'alias l="ls -CF"' >> ~/.bashrc

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python --version && aws --version && node --version || exit 1

CMD ["bash"]