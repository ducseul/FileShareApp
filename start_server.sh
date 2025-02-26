#!/bin/bash

# Start Gunicorn
echo Enable environment
source env/bin/activate
echo "Starting Gunicorn server..."
#gunicorn -w 1 -b 0.0.0.0:80 main:app > output.log 2>&1 &
gunicorn -w 1 -k eventlet -b 0.0.0.0:80 --timeout 300 --access-logfile - --error-logfile - --log-level debug  main:app > output.log 2>&1 &

# Save PID to .PID file
echo $! > .PID
echo "Server started with PID $(cat .PID). Logs are being written to output.log."
