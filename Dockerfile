# Start with Python base image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy necessary files
COPY . /app

# Install dependencies
RUN pip install wallycore

# Generate a self-signed certificate; `server.pem` will be copied to the host on first run by `docker-entrypoint.sh`
RUN openssl req -new -x509 -keyout server.pem -out server.pem -days 3650 -nodes -subj "/CN=localhost"

# Copy the entrypoint script into the container
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# Make the script executable
RUN chmod +x /app/docker-entrypoint.sh

# Expose the required port
EXPOSE 4443

# Set the entrypoint to the main command, so additional args can be passed in docker-compose.yml
ENTRYPOINT ["/app/docker-entrypoint.sh", "python3", "/app/SimpleJadePinServer.py"]