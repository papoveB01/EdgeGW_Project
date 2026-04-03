#!/bin/bash

# Script to get API credentials for Edge Gateway testing
# This extracts credentials from the database for a test institution

INSTITUTION_ID=${1:-BNK_WEST_001}

echo "Getting credentials for institution: $INSTITUTION_ID"
echo "Note: This script requires access to the database and encryption key"

# This would need to be run from within the intel-api container
# or with proper database access
echo ""
echo "To get credentials, you need to:"
echo "1. Access the institution onboarding page in the admin dashboard"
echo "2. Or use the API endpoint: GET /api/v1/institutions/{institution_id}"
echo ""
echo "For testing, you can create a new institution via the admin dashboard"
echo "and use the API_KEY and HMAC_SECRET provided during onboarding."


