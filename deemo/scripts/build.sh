#!/bin/bash
set -e

echo "Building Deemo Binary Analysis Environment..."

if [ ! -f "pyproject.toml" ]; then
    echo "Error: pyproject.toml not found. Run from project root."
    exit 1
fi

echo "1. Creating necessary directories..."
mkdir -p workspace data reports

echo "2. Building Docker image..."
docker build -t deemo:latest .

echo "3. Creating Docker network..."
docker network create deemo-network 2>/dev/null || true

echo "4. Starting services..."
docker-compose up -d

echo ""
echo "Deemo environment is now running!"
echo "To access the analysis container:"
echo "  docker exec -it deemo-analysis /bin/bash"
echo ""
echo "To run the CLI:"
echo "  docker exec -it deemo-analysis python -m modules.cli --help"
echo ""
echo "Workspace directory: ./workspace"
echo "Reports