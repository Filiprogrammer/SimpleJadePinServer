# Start with Python base image
FROM python:3.12-alpine

# Set the working directory
WORKDIR /app

# Copy necessary files
COPY SimpleJadePinServer.py index.html oracle_qr.html qrcode.js /app/

# Install dependencies
RUN pip install --no-cache-dir wallycore

# Expose the required port
EXPOSE 4443

# Set the entrypoint to the main command, so additional args can be passed in docker-compose.yml
ENTRYPOINT ["python3", "/app/SimpleJadePinServer.py"]
