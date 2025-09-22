#!/bin/bash

# Development script to run all services concurrently
# This script starts API, Admin, and both mobile apps in development mode

echo "Starting Tollab development environment..."

# Check if required tools are installed
command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required but not installed. Install it with: npm install -g pnpm" >&2; exit 1; }
command -v expo >/dev/null 2>&1 || { echo "Expo CLI is required but not installed. Install it with: npm install -g @expo/cli" >&2; exit 1; }

# Function to handle cleanup on exit
cleanup() {
    echo "Stopping all development servers..."
    kill $(jobs -p) 2>/dev/null
    exit
}

# Set trap to cleanup on script exit
trap cleanup SIGINT SIGTERM

# Start API server
echo "Starting API server..."
cd apps/api && pnpm dev &
API_PID=$!

# Start Admin app
echo "Starting Admin app..."
cd ../admin && pnpm dev &
ADMIN_PID=$!

# Start Student mobile app
echo "Starting Student mobile app..."
cd ../student && npx expo start --dev-client --port 8081 &
STUDENT_PID=$!

# Start Merchant mobile app
echo "Starting Merchant mobile app..."
cd ../merchant && npx expo start --dev-client --port 8082 &
MERCHANT_PID=$!

# Return to root directory
cd ../..

echo "All services started!"
echo "API: http://localhost:3000"
echo "Admin: http://localhost:5173"
echo "Student app: http://localhost:8081"
echo "Merchant app: http://localhost:8082"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for all background processes
wait