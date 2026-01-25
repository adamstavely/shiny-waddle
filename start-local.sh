#!/bin/bash

# Heimdall Local Development Startup Script
# This script starts both the API and Frontend services

set -e

echo "🚀 Starting Heimdall Dashboard..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if dependencies are installed
if [ ! -d "dashboard-api/node_modules" ] || [ ! -d "dashboard-frontend/node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm run dashboard:install
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    kill $API_PID $FRONTEND_PID 2>/dev/null || true
    exit
}

# Trap Ctrl+C and call cleanup
trap cleanup INT TERM

# Start API
echo "🔧 Starting API server (port 3001)..."
cd dashboard-api
npm run start:dev &
API_PID=$!
cd ..

# Wait a bit for API to start
sleep 3

# Start Frontend
echo "🎨 Starting Frontend server (port 5173)..."
cd dashboard-frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "✅ Services started!"
echo "   📡 API:      http://localhost:3001"
echo "   🎨 Frontend: http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for both processes
wait
