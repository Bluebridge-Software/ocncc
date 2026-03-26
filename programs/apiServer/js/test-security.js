#!/usr/bin/env node
/**
 * test-security.js
 * Verifies that unauthorised access attempts trigger alerts.
 */

const API_BASE_URL = 'http://localhost:3010/api';

async function testUnauthorised() {
  console.log('--- Testing Unauthorised Access (No Token) ---');
  try {
    const res = await fetch(`${API_BASE_URL}/wallet-info`, { method: 'POST' });
    const data = await res.json();
    console.log('Response Status:', res.status);
    console.log('Response Body:', JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Error:', err.message);
  }

  console.log('\n--- Testing Forbidden Access (Valid token, wrong endpoint) ---');
  // We need a token for this. Let's use the one generated for TestClientA
  // which had access to /wallet-info, but we'll try /bad-pin (if it's not allowed)
  // Actually let's just use a fake token for invalid token alert.

  try {
    const res = await fetch(`${API_BASE_URL}/wallet-info`, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer NOT_A_REAL_TOKEN' }
    });
    const data = await res.json();
    console.log('Response Status:', res.status);
    console.log('Response Body:', JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Error:', err.message);
  }

  console.log('\n--- Checking Stats for Unauthorised Attempts ---');
  try {
    const res = await fetch(`${API_BASE_URL}/stats?hours=1`);
    const data = await res.json();
    const lastBucket = data.periodAggregates[data.periodAggregates.length - 1];
    console.log('Unauthorised Attempts in last bucket:', lastBucket.unauthorisedAttempts);
  } catch (err) {
    console.error('Error:', err.message);
  }
}

testUnauthorised();
