FROM python:3.11-slim

# Install ipmitool, openssh-client, and sshpass (for detailed OS inventory via SSH)
RUN apt-get update && apt-get install -y \
    ipmitool \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 5000

# Run with gunicorn
# Use 1 worker to prevent duplicate background collectors
# (each worker spawns its own background_collector thread)
# 8 threads handles concurrent requests adequately for dashboard use
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8", "app:app"]

