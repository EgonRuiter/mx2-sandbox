# Build stage: Use official slim Python runtime
FROM python:3.11-slim

# Set system environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Expose the daemon REST API port
EXPOSE 8000

# Copy codebase into the container
COPY . /app

# Ensure logs and storage directories exist
RUN mkdir -p /app/logs /app/storage

# Run the REST daemon web server
CMD ["python", "src/web_server.py"]
