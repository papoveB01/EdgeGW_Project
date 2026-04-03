#!/bin/bash

# Script to create test credentials for Edge Gateway
# This generates a test institution with known credentials

INSTITUTION_ID="EDGE_GATEWAY_TEST"
BANK_SALT="test_bank_salt_32_characters_minimum_required_for_security"
REGIONAL_PEPPER="test_regional_pepper_shared_across_network_for_consistency"

echo "Setting up test credentials for Edge Gateway..."
echo "Institution ID: $INSTITUTION_ID"
echo ""
echo "Note: You need to create this institution via the admin dashboard"
echo "or use the onboarding API to get real API_KEY and HMAC_SECRET."
echo ""
echo "For testing, you can use these environment variables:"
echo ""
echo "export EDGE_GATEWAY_INSTITUTION_ID=$INSTITUTION_ID"
echo "export EDGE_GATEWAY_BANK_SALT=$BANK_SALT"
echo "export EDGE_GATEWAY_REGIONAL_PEPPER=$REGIONAL_PEPPER"
echo ""
echo "Then create the institution and set:"
echo "export EDGE_GATEWAY_API_KEY=<from_onboarding>"
echo "export EDGE_GATEWAY_HMAC_SECRET=<from_onboarding>"


