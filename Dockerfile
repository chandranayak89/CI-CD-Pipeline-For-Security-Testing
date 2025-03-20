FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on

# Create a non-root user
RUN groupadd -r securityapp && useradd -r -g securityapp securityapp

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories for the web dashboard
RUN mkdir -p src/static src/templates src/logs && \
    chown -R securityapp:securityapp /app

# Switch to non-root user
USER securityapp

# Expose port for web dashboard
EXPOSE 8080

# Command to run the application
CMD ["python", "-m", "src.main", "--dashboard"] 