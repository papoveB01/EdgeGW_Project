#!/bin/bash

# Test script for Edge Gateway
# This simulates a transaction from a Core Banking System

echo "Testing Edge Gateway..."
echo "=========================="

# Test health endpoint
echo ""
echo "1. Testing Health Check..."
curl -s http://localhost:8080/health | jq '.' || echo "Health check failed"

# Test transaction processing (with optional fraud-detection fields: device_id, branch_id, ip)
echo ""
echo "2. Testing Transaction Processing..."
curl -X POST http://localhost:8080/process \
  -H "Content-Type: application/json" \
  -d '{
    "id": "1234567890",
    "name": "John Doe",
    "account": "ACC123456",
    "amount": 1250.00,
    "latitude": 6.5244,
    "longitude": 3.3792,
    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "device_id": "test-device-001",
    "branch_id": "LAG-01",
    "ip": "192.168.1.100"
  }' | jq '.' || echo "Transaction processing failed"

echo ""
echo "=========================="
echo "Test complete!"


