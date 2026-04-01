/**
 * OCNCC Billing Engine - Ultimate End-to-End Integration Test Runner
 *
 * This script runs the actual API server, mocks the backend OCNCC engines,
 * and performs real HTTP requests to verify the full stack.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');

// Load test data
const testMsgs = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'testMessages.json'), 'utf-8'));
const testMsgsFriendly = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'testMessagesNew.json'), 'utf-8'));

// Configuration for testing
const MOCK_PORT_PRIMARY = 1501;
const MOCK_PORT_SECONDARY = 1502;
const SERVER_PORT = 3010;
const TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRJZCI6IlRlc3RDbGllbnRBIiwiYWxsb3dlZEVuZHBvaW50cyI6WyIqIl0sImlhdCI6MTc3NDYwODU5MywiZXhwIjoyMDkwMTg0NTkzfQ.wMEPyTUy1at32YSaqJP5_r-5tO_nBtp36-8SLu7X2LA"; // Wildcard token

let mockProcess, serverProcess;

function log(msg) {
  console.log(`[TestRunner] ${msg}`);
}

async function runTests() {
  log('Starting Comprehensive Integration Test Suite...');

  try {
    // 1. Start Mock Servers (in-process for easier control)
    const MockBeServer = require('./mock-be-server');
    const mockPrimary = new MockBeServer(MOCK_PORT_PRIMARY);
    const mockSecondary = new MockBeServer(MOCK_PORT_SECONDARY);
    await mockPrimary.start();
    await mockSecondary.start();
    log('Mock BE Servers started.');

    // 2. Start Main API Server (as child process)
    log('Starting Main API Server...');
    serverProcess = spawn('node', ['server.js'], {
      cwd: __dirname,
      env: {
        ...process.env,
        BE_PORT: SERVER_PORT,
        BE_ENGINES: `1:127.0.0.1:${MOCK_PORT_PRIMARY}:127.0.0.1:${MOCK_PORT_SECONDARY}`,
        BE_JWT_ENABLED: 'true',
        BE_JWT_SECRET: 'YOUR_SUPER_SECRET_KEY_CHANGE_IN_PRODUCTION', // Default from config.js
        BE_PRIMARY_FAILBACK_MS: '1000' // Failback after 1 second for test speed
      }
    });

    serverProcess.stdout.on('data', (data) => console.log(`[Server] ${data.toString().trim()}`));
    serverProcess.stderr.on('data', (data) => console.error(`[Server Error] ${data.toString().trim()}`));

    // Wait for server to start
    await new Promise(r => setTimeout(r, 3000));
    log('API Server should be ready.');

    // 3. Define Test Helper
    const apiCall = (endpoint, payload) => {
      return new Promise((resolve, reject) => {
        const req = http.request({
          hostname: 'localhost',
          port: SERVER_PORT,
          path: `/api${endpoint}`,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${TEST_TOKEN}`
          }
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              resolve({ status: res.status, body: JSON.parse(data) });
            } catch (e) {
              resolve({ status: res.status, raw: data });
            }
          });
        });
        req.on('error', reject);
        req.write(JSON.stringify(payload));
        req.end();
      });
    };

    let passed = 0, total = 0;
    const assert = (cond, msg) => {
      total++;
      if (cond) { passed++; log(`  ✓ ${msg}`); }
      else { console.error(`  ✗ ${msg} (FAILED)`); }
    };

    // 4. Run Message Tests
    log('\n--- Phase 1: Raw Message Format Tests ---');
    for (const msg of testMsgs) {
      if (msg.ACTN !== 'REQ ') continue;
      
      let endpoint = '/wallet-info'; // Default fallback
      if (msg.TYPE === 'IR  ') endpoint = '/initial-reservation';
      if (msg.TYPE === 'WU  ') endpoint = '/wallet-info'; // WU uses wallet-info endpoint in some logic, let's verify routes/api.js
      
      // Map to correct endpoint based on TYPE
      const typeToEndpoint = {
        'WI  ': '/wallet-info',
        'IR  ': '/initial-reservation',
        'DA  ': '/direct-time-charge',
        'NE  ': '/named-event',
        'VR  ': '/voucher-redeem'
      };
      endpoint = typeToEndpoint[msg.TYPE] || '/wallet-info';

      // Mock the response for this specific message
      const ack = testMsgs.find(m => m.TYPE === msg.TYPE && m.ACTN === 'ACK ' && m.HEAD.CMID === msg.HEAD.CMID);
      if (ack) mockPrimary.setDefaultResponse(msg.TYPE, ack);

      const result = await apiCall(endpoint, msg);
      assert(result.body && (result.body.ACTN === 'ACK ' || result.body.ACTN === 'NACK'), 
             `Handled ${msg.TYPE} (${msg._comment || ''})`);
    }

    log('\n--- Phase 2: Friendly Message Format Tests ---');
    for (const msg of testMsgsFriendly) {
      if (msg['FOX Action'] !== 'REQ ') continue;
      
      const typeToEndpoint = {
        'WI  ': '/wallet-info',
        'IR  ': '/initial-reservation',
        'DA  ': '/direct-time-charge',
        'NE  ': '/named-event',
        'VR  ': '/voucher-redeem'
      };
      const endpoint = typeToEndpoint[msg['FOX Type']] || '/wallet-info';

      const result = await apiCall(endpoint, msg);
      assert(result.body && result.body['Body'], `Handled Friendly ${msg['FOX Type']} (${msg._comment || ''})`);
    }

    log('\n--- Phase 3: Failover & Failback Tests ---');
    const wiRequest = testMsgs.find(m => m.TYPE === 'WI  ' && m.ACTN === 'REQ ');
    const wiResponsePayload = testMsgs.find(m => m.TYPE === 'WI  ' && m.ACTN === 'ACK ');
    
    // 1. Failover to Secondary
    log('  Stopping primary mock...');
    await mockPrimary.stop();
    await new Promise(r => setTimeout(r, 1000)); // wait for client to detect drop

    mockSecondary.setDefaultResponse('WI  ', wiResponsePayload);
    const resFailover = await apiCall('/wallet-info', wiRequest);
    assert(resFailover.body.ACTN === 'ACK ', 'Secondary backend fulfilled the request during failover');

    // 2. Failback to Primary
    log('  Restarting primary mock...');
    await mockPrimary.start();
    log('  Waiting for failback (2s)...');
    await new Promise(r => setTimeout(r, 2000));
    
    mockPrimary.setDefaultResponse('WI  ', wiResponsePayload);
    const resFailback = await apiCall('/wallet-info', wiRequest);
    assert(resFailback.body.ACTN === 'ACK ', 'Primary backend fulfilled the request after failback');

    log('\n--- Phase 4: Flow & State Tests ---');
    // Test IR -> SR -> CR flow
    const ir = testMsgs.find(m => m.TYPE === 'IR  ');
    mockPrimary.setDefaultResponse('IR  ', { ACTN: 'ACK ', TYPE: 'IR  ', BODY: { NUM : 100 } });
    const irRes = await apiCall('/initial-reservation', ir);
    assert(irRes.body.BODY.NUM === 100, 'IR Sequence started');

    log('\n--- Phase 5: Security & Alerts ---');
    const unauthorized = await new Promise((resolve) => {
      http.get(`http://localhost:${SERVER_PORT}/api/stats`, (res) => resolve(res.statusCode)).on('error', () => resolve(500));
    });
    assert(unauthorized === 401, 'Unauthorized request correctly blocked (401)');

    log(`\nFinal Result: ${passed}/${total} passed`);

    // Clean up
    await mockPrimary.stop();
    await mockSecondary.stop();
    serverProcess.kill();
    process.exit(passed === total ? 0 : 1);

  } catch (err) {
    console.error('Integration test failed:', err);
    if (serverProcess) serverProcess.kill();
    process.exit(1);
  }
}

runTests();
