/**
 * OCNCC Billing Engine Comprehensive API Test Suite.
 * Testing full stack: HTTP -> JWT -> BE Client -> Mock BE Server
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

const MockBeServer = require('../mock-be-server');
const BeClient = require('../../services/be-client');
const Config = require('../../config/config');
const codec = require('../../codecs/escher-codec');
const jwt = require('jsonwebtoken');

// Load test data
const fs = require('fs');
const path = require('path');
const testMsgsPath = path.join(__dirname, '..', 'testMessages.json');
const testMsgs = JSON.parse(fs.readFileSync(testMsgsPath, 'utf-8'));

const JWT_SECRET = 'be-test-secret-12345';
const TOKEN = jwt.sign({ clientId: 'TEST_CLIENT', allowedEndpoints: ['*'] }, JWT_SECRET);

async function runAllTests() {
  console.log('═══════════════════════════════════════════════════');
  console.log('  OCNCC Billing Engine: Comprehensive Test Suite');
  console.log('═══════════════════════════════════════════════════\n');

  // ---- 0. Set up Mock Servers (Primary & Secondary) ----
  const primaryMock = new MockBeServer(1501);
  const secondaryMock = new MockBeServer(1502);

  await primaryMock.start();
  await secondaryMock.start();

  // ---- 1. Set up Config & BE Client ----
  const config = new Config({
    BE_PORT: 3010,
    BE_JWT_SECRET: JWT_SECRET,
    BE_JWT_ENABLED: true,
    BE_ENGINES: '1:localhost:1501:localhost:1502',
    messageTimeoutMs: 1000,
    heartbeatIntervalMs: 500,
    connectionRetryMs: 1000
  });

  const beClient = new BeClient(config);

  let passedTests = 0;
  let totalTests = 0;

  function assert(condition, message) {
    totalTests++;
    if (condition) {
      passedTests++;
      console.log(`  ✓ ${message}`);
      return true;
    } else {
      console.error(`  ✗ ${message} (FAILED)`);
      return false;
    }
  }

  try {
    // ---- Test 1: Connectivity (Handshake) ----
    console.log('Test 1: Connectivity & Handshake');
    // Wait for connection to establish
    await new Promise(r => setTimeout(r, 2000));
    assert(beClient.getBillingEngine("1").isPrimaryAvailable(), 'Primary BE connection active');

    // ---- Test 2: Wallet Info (Raw) ----
    console.log('\nTest 2: Wallet Info (Raw Format)');
    const wiRequest = testMsgs.find(m => m.TYPE === 'WI  ' && m.ACTN === 'REQ ');
    const wiResponsePayload = testMsgs.find(m => m.TYPE === 'WI  ' && m.ACTN === 'ACK ');

    // Configure Mock response
    primaryMock.setDefaultResponse('WI  ', wiResponsePayload);

    const res1 = await beClient.sendMessage(wiRequest);
    assert(res1.message.TYPE === 'WI  ' && res1.message.ACTN === 'ACK ', 'WI Response type matches');
    assert(res1.message.BODY.STAT === 'ACTV', 'Wallet state matches ACK');

    // ---- Test 3: Wallet Info (Friendly) ----
    console.log('\nTest 3: Wallet Info (Friendly Format)');
    const friendlyWI = {
      'FOX Action': 'REQ ',
      'FOX Type': 'WI  ',
      'Body': { 'Wallet Reference': 12345 }
    };
    const res2 = await beClient.sendMessage(friendlyWI, { responseFormat: 'friendly' });
    assert(res2.message['Header'] && res2.message['Header']['Request Number (CMID)'], 'Friendly header contains CMID');
    assert(res2.message['Body'] && res2.message['Body']['State'] === 'ACTV', 'Friendly body contains State=ACTV');

    // ---- Test 4: Call Reservation Flow (IR -> SR -> CR) ----
    console.log('\nTest 4: Call Reservation Sequence');
    // IR
    const irReq = testMsgs.find(m => m.TYPE === 'IR  ' && m.ACTN === 'REQ ');
    primaryMock.setDefaultResponse('IR  ', { 'ACTN': 'ACK ', 'TYPE': 'IR  ', 'BODY': { 'NUM ': 60 } });
    const irRes = await beClient.sendMessage(irReq);
    assert(irRes.message.BODY.NUM === 60, 'IR granted 60 units');

    // SR
    const srReq = testMsgs.find(m => m.TYPE === 'SR  ' && m.ACTN === 'REQ ');
    primaryMock.setDefaultResponse('SR  ', { 'ACTN': 'ACK ', 'TYPE': 'SR  ', 'BODY': { 'NUM ': 30 } });
    const srRes = await beClient.sendMessage(srReq);
    assert(srRes.message.BODY.NUM === 30, 'SR granted 30 additional units');

    // CR
    const crReq = testMsgs.find(m => m.TYPE === 'CR  ' && m.ACTN === 'REQ ');
    primaryMock.setDefaultResponse('CR  ', { 'ACTN': 'ACK ', 'TYPE': 'CR  ', 'BODY': {} });
    const crRes = await beClient.sendMessage(crReq);
    assert(crRes.message.ACTN === 'ACK ', 'CR confirmed call units');

    // ---- Test 5: Automatic Failover to Secondary ----
    console.log('\nTest 5: Failover to Secondary');
    console.log('  Stopping primary mock...');
    await primaryMock.stop();
    await new Promise(r => setTimeout(r, 1000)); // wait for client to detect drop

    assert(!beClient.getBillingEngine("1").isPrimaryAvailable(), 'Primary connection correctly dropped');
    assert(beClient.getBillingEngine("1").isSecondaryAvailable(), 'Secondary connection remains active');

    // Configure secondary Mock response
    secondaryMock.setDefaultResponse('WI  ', wiResponsePayload);
    const resFailover = await beClient.sendMessage(wiRequest);
    assert(resFailover.message.ACTN === 'ACK ', 'Secondary backend fulfilled the request');

    // ---- Test 6: Extended Features (SDNF & Future Buckets) ----
    console.log('\nTest 6: Extended Features (SDNF & STDT)');
    const extendedWU = {
      "ACTN": "REQ ",
      "TYPE": "WU  ",
      "BODY": {
        "WALT": 12345,
        "ABAL": [{
          "BTYP": 1,
          "BKTS": [{ "VAL ": 5000, "STDT": 1800000000 }]
        }]
      }
    };
    secondaryMock.setDefaultResponse('WU  ', { "ACTN": "ACK ", "TYPE": "WU  ", "BODY": {} });
    const resWU = await beClient.sendMessage(extendedWU);
    assert(resWU.ACTN === 'ACK ', 'Future bucket update accepted');

    const extendedWI = { "TYPE": "WI  ", "BODY": { "WALT": 12345, "SDNF": null } };
    const resWI = await beClient.sendMessage(extendedWI);
    assert(resWI.ACTN === 'ACK ', 'Stateless (SDNF) query accepted');

    // ---- Test 7: Error Scenarios (Unknown Wallet) ----
    console.log('\nTest 7: Protocol Error (NACK)');
    secondaryMock.setDefaultResponse('WI  ', {
      'ACTN': 'NACK',
      'TYPE': 'WI  ',
      'BODY': { 'CODE': 'WDIS', 'WHAT': 'Wallet disabled' }
    });
    const resErr = await beClient.sendMessage(wiRequest);
    assert(resErr.ACTN === 'NACK' && resErr.BODY.CODE === 'WDIS', 'Received correct NACK from backend');

  } catch (err) {
    console.error('  ✗ COMPREHENSIVE TEST FAILED WITH EXCEPTION:', err);
  } finally {
    console.log(`\n═══════════════════════════════════════════════════`);
    console.log(`  Tests complete: ${passedTests}/${totalTests} passed`);
    console.log(`═══════════════════════════════════════════════════\n`);

    // Teardown
    await primaryMock.stop();
    await secondaryMock.stop();
    process.exit(passedTests === totalTests ? 0 : 1);
  }
}

runAllTests();
