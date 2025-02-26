#!/bin/bash

# Check if .PID file exists
if [ ! -f .PID ]; then
  echo "PID file not found. Is the server running?"
  exit 1
fi

# Kill the process using the PID
PID=$(cat .PID)
echo "Stopping server with PID $PID..."
kill $PID

# Cleanup .PID file
rm -f .PID
echo "Server stopped."
