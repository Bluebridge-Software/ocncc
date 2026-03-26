#!/usr/bin/env node
/**
 * OCNCC Billing Engine Example Integration.
 * A simple example of how to integrate with the OCNCC Billing Engine REST API
 * using native JavaScript (Node.js 18+ or Browser environment).
 * 
 * Usage: node example-integration.js
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

const jwt = require('jsonwebtoken');

// Load settings directly from environment or defaults
require('dotenv').config();
const SECRET = process.env.BE_JWT_SECRET || 'YOUR_SUPER_SECRET_KEY_CHANGE_IN_PRODUCTION';
const API_BASE_URL = 'http://localhost:3010/api';
const CLIENT_ID = 'ExampleNodeClient'; // Tracked in /api/stats

// Generate a valid token with permissions to our test endpoints
const MOCK_TOKEN = jwt.sign(
  { clientId: CLIENT_ID, allowedEndpoints: ['/wallet-info', '/initial-reservation', '/stats'] },
  SECRET,
  { expiresIn: '1h' }
);

/**
 * Sends a message to the OCNCC REST API.
 * 
 * @param {string} endpoint - The specific API endpoint (e.g., '/wallet-info')
 * @param {Object} payload - The JSON message (either raw symbols or friendly labels)
 * @param {Object} [options] - Optional parameters like billingEngineId and preferredEngine
 * @returns {Promise<Object>} The response JSON containing the result
 */
async function sendOcNccRequest(endpoint, payload, options = {}) {
  let url = new URL(`${API_BASE_URL}${endpoint}`);

  if (options.billingEngineId !== undefined) {
    url.searchParams.append('billingEngineId', options.billingEngineId);
  }

  if (options.preferredEngine) {
    url.searchParams.append('preferredEngine', options.preferredEngine);
  }

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      // Provide valid authentication token
      'Authorization': `Bearer ${MOCK_TOKEN}`,
      // (Optional) 'x-client-id' is natively extracted from the JWT token by the server now!
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    // If the BE times out or is offline, the API translates it gracefully into a 5xx error
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(`API Error ${response.status}: ${errorBody.error || response.statusText}`);
  }

  return response.json();
}

/**
 * Main sequence demonstrating API usage.
 */
async function runExample() {
  console.log('--- OCNCC Billing Engine Client Integration Example ---\n');

  try {
    // ----------------------------------------------------------------------
    // Example 1: Sending a "Friendly" formatted JSON Request
    // The server will automatically detect the format and return friendly JSON
    // ----------------------------------------------------------------------
    console.log('1. Fetching Wallet Info (using Friendly format)...');

    const friendlyPayload = {
      "FOX Action": "REQ ",
      "FOX Type": "WI  ",
      "Header": {
        "Request Number (CMID)": 1055,
        "BE Server ID": 1
      },
      "Body": {
        "Wallet Reference": 447700900123,
        "Balance Type": 2
      }
    };

    try {
      const friendlyRes = await sendOcNccRequest('/wallet-info', friendlyPayload);
      console.log('Received Response Format:', friendlyRes.format);
      console.log('Response:', JSON.stringify(friendlyRes.message, null, 2));
    } catch (err) {
      console.log(`Request failed (Expected if no real BE is connected): ${err.message}`);
    }

    console.log('\n-----------------------------------------------------\n');

    // ----------------------------------------------------------------------
    // Example 2: Sending a "Raw" 4-char Symbol JSON Request
    // Handled perfectly natively for older systems or raw integrations
    // ----------------------------------------------------------------------
    console.log('2. Reserving Time (using Raw symbol format)...');

    const rawPayload = {
      "ACTN": "REQ ",
      "TYPE": "IR  ",
      "HEAD": {
        "CMID": 2044,
        "SVID": 1
      },
      "BODY": {
        "WALT": 447700900123,
        "SPID": 101,
        "ERSL": 300 // Expected length = 300s
      }
    };

    try {
      // Pass { preferredEngine: 'secondary' } to test fallback logic
      const rawRes = await sendOcNccRequest('/initial-reservation', rawPayload, { preferredEngine: 'secondary' });
      console.log('Received Response Format:', rawRes.format);
      console.log('Response:', JSON.stringify(rawRes.message, null, 2));
    } catch (err) {
      console.log(`Request failed (Expected if no real BE is connected): ${err.message}`);
    }

    console.log('\n-----------------------------------------------------\n');

    // ----------------------------------------------------------------------
    // Example 3: Pulling the newly created API usage statistics
    // ----------------------------------------------------------------------
    console.log('3. Fetching recent API usage statistics...');
    const statsRes = await fetch(`${API_BASE_URL}/stats`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${MOCK_TOKEN}` }
    });

    if (statsRes.ok) {
      const stats = await statsRes.json();
      console.log('API Stats retrieved successfully!');

      // Dump simplified metrics
      const currentBucket = stats.periodAggregates[stats.periodAggregates.length - 1];
      if (currentBucket) {
        console.log(`   Calls in current ${stats.periodMinutes}m window: ${currentBucket.totalCalls}`);
        console.log(`   Calls broken by endpoint:`, currentBucket.byEndpoint);
        console.log(`   Calls broken by Client:`, currentBucket.byClient);
      } else {
        console.log('   No calls logged in the current window yet.');
      }
    } else {
      console.log('Failed to fetch stats.');
    }

  } catch (err) {
    console.error(`Unexpected Error:`, err);
  }
}

// Execute
runExample();
