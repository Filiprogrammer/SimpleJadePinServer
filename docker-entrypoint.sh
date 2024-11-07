#!/bin/bash

# Path to the mounted volume location
KEY_DIR="/app/key_data"

# Check if the server.pem exists in the volume
if [ ! -f "$KEY_DIR/server.pem" ]; then
    echo "server.pem not found, copying from container to host volume"
    # Copy server.pem from the container to the volume
    cp /app/server.pem $KEY_DIR/
else
    echo "server.pem already exists in the volume"
fi

# Now execute the main application
exec "$@"