# Start with Python base image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy necessary files
COPY . /app

# Install dependencies
RUN pip install wallycore

# Generate a self-signed certificate (optional)
RUN openssl req -new -x509 -keyout server.pem -out server.pem -days 3650 -nodes -subj "/CN=localhost"

# Expose the required port
EXPOSE 4443

# Start the server
CMD ["python3", "SimpleJadePinServer.py"]
