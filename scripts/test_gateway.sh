#!/bin/bash
# Integration test for Edge Gateway
# Usage: ./scripts/test_gateway.sh [gateway_url]

GW_URL="${1:-http://localhost:8080}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")

echo "=== Testing Edge Gateway at $GW_URL ==="

echo -e "\n--- Health Check ---"
curl -s "$GW_URL/health" | python3 -m json.tool 2>/dev/null || curl -s "$GW_URL/health"

echo -e "\n--- Metrics ---"
curl -s "$GW_URL/metrics" | python3 -m json.tool 2>/dev/null || curl -s "$GW_URL/metrics"

echo -e "\n--- Process Transaction ---"
curl -s -X POST "$GW_URL/process" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"CUST-001\",
    \"name\": \"John Doe\",
    \"national_id\": \"22345678901\",
    \"account\": \"ACC-1234567890\",
    \"amount\": 9500.00,
    \"latitude\": 6.4541,
    \"longitude\": 3.3947,
    \"timestamp\": \"$TIMESTAMP\",
    \"device_id\": \"DEV-MOBILE-001\",
    \"ip\": \"192.168.1.100\",
    \"branch_id\": \"LAG-01\",
    \"signal_type\": \"transaction\",
    \"endpoint_type\": \"MOBILE_APP\"
  }" | python3 -m json.tool 2>/dev/null || echo "(raw output above)"

echo -e "\n--- Process Transfer (with counterparty) ---"
curl -s -X POST "$GW_URL/process" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"CUST-001\",
    \"name\": \"John Doe\",
    \"account\": \"ACC-1234567890\",
    \"amount\": 5000.00,
    \"latitude\": 6.4541,
    \"longitude\": 3.3947,
    \"timestamp\": \"$TIMESTAMP\",
    \"counterparty_id\": \"CUST-999\",
    \"counterparty_national_id\": \"99887766554\",
    \"signal_type\": \"transaction\",
    \"endpoint_type\": \"BRANCH\"
  }" | python3 -m json.tool 2>/dev/null || echo "(raw output above)"

echo -e "\n=== Done ==="
