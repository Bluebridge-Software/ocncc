#!/usr/bin/env node
/**
 * OCNCC Billing Engine Escher Codec Tests.
 * Verify Escher codec roundtrip with test messages
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const fs = require('fs');
const path = require('path');
const codec = require('./escher-codec');

console.log('═══════════════════════════════════════════════════');
console.log('  Escher Codec Roundtrip Tests');
console.log('═══════════════════════════════════════════════════\n');

// ---- Test 1: Symbol encode/decode roundtrip ----
console.log('Test 1: Symbol encode/decode roundtrip');
const symbols = ['TYPE', 'HEAD', 'BODY', 'ACTN', 'CMID', 'SVID', 'HTBT', 'WI  ', 'IR  ', 'INER'];
let pass = true;
for (const sym of symbols) {
  const encoded = codec.encodeSymbolInt(sym);
  const decoded = codec.decodeSymbol(encoded);
  if (decoded !== sym) {
    console.log(`  ✗ Symbol "${sym}" -> ${encoded} -> "${decoded}" (MISMATCH)`);
    pass = false;
  }
}
console.log(pass ? '  ✓ All symbols encode/decode correctly\n' : '  ✗ FAILED\n');

// ---- Test 2: Simple map encode/decode ----
console.log('Test 2: Simple map encode/decode');
const simpleMsg = {
  'TYPE': 'HTBT',
  'HEAD': {},
  'BODY': {}
};
try {
  const encoded = codec.encodeMap(simpleMsg);
  const decoded = codec.decodeMap(encoded, false);
  console.log(`  ✓ HTBT message encoded to ${encoded.length} bytes`);
  console.log(`    Decoded TYPE: "${decoded['TYPE']}"`);
  console.log('');
} catch (err) {
  console.log(`  ✗ Error: ${err.message}\n`);
}

// ---- Test 3: Complex message roundtrip ----
console.log('Test 3: Complex message (WI Request) roundtrip');
const wiRequest = {
  "ACTN": "REQ ",
  "TYPE": "WI  ",
  "HEAD": {
    "CMID": 1001,
    "DATE": "~date:1774035629",
    "DUP ": 0,
    "SVID": 1,
    "USEC": 247024,
    "VER ": 100
  },
  "BODY": {
    "WALT": 12345,
    "BTYP": 2,
    "BUNT": 1,
    "UCUR": 840,
    "SPID": 101,
    "LOCK": 500,
    "ACTY": 5,
    "AREF": 999,
    "WTYP": 1
  }
};
try {
  const encoded = codec.encodeMap(wiRequest);
  const decoded = codec.decodeMap(encoded, false);
  console.log(`  ✓ WI Request encoded to ${encoded.length} bytes`);
  console.log(`    TYPE: "${decoded['TYPE']}", ACTN: "${decoded['ACTN']}"`);
  console.log(`    HEAD.CMID: ${decoded['HEAD']['CMID']}`);
  console.log(`    HEAD.SVID: ${decoded['HEAD']['SVID']}`);
  console.log(`    HEAD.DATE: ${decoded['HEAD']['DATE']}`);
  console.log(`    HEAD.VER : ${decoded['HEAD']['VER ']}`);
  console.log(`    BODY.WALT: ${decoded['BODY']['WALT']}`);
  console.log(`    BODY.BTYP: ${decoded['BODY']['BTYP']}`);

  // Verify values
  const checks = [
    ['TYPE', decoded['TYPE'], 'WI  '],
    ['ACTN', decoded['ACTN'], 'REQ '],
    ['HEAD.CMID', decoded['HEAD']['CMID'], 1001],
    ['HEAD.SVID', decoded['HEAD']['SVID'], 1],
    ['HEAD.VER ', decoded['HEAD']['VER '], 100],
    ['BODY.WALT', decoded['BODY']['WALT'], 12345],
    ['BODY.BTYP', decoded['BODY']['BTYP'], 2],
  ];
  let allMatch = true;
  for (const [field, actual, expected] of checks) {
    if (actual !== expected) {
      console.log(`  ✗ ${field}: expected ${expected}, got ${actual}`);
      allMatch = false;
    }
  }
  if (allMatch) console.log('  ✓ All fields match\n');
  else console.log('  ✗ Some fields MISMATCH\n');
} catch (err) {
  console.log(`  ✗ Error: ${err.message}\n`);
}

// ---- Test 4: Friendly format detection ----
console.log('Test 4: Format detection');
const rawMsg = { 'TYPE': 'WI  ', 'HEAD': {}, 'BODY': {} };
const friendlyMsg = { 'FOX Type': 'WI  ', 'Header': {}, 'Body': {} };
console.log(`  Raw message detected as friendly: ${codec.isFriendlyFormat(rawMsg)} (expected: false)`);
console.log(`  Friendly message detected as friendly: ${codec.isFriendlyFormat(friendlyMsg)} (expected: true)`);
console.log('');

// ---- Test 5: Friendly <-> Raw conversion ----
console.log('Test 5: Friendly <-> Raw conversion');
const friendly = {
  'FOX Action': 'REQ ',
  'FOX Type': 'WI  ',
  'Header': {
    'Request Number (CMID)': 1001,
    'BE Server ID': 1,
    'Protocol Version': 100
  },
  'Body': {
    'Wallet Reference': 12345,
    'Balance Type': 2
  }
};
const normalised = codec.normaliseToRaw(friendly);
console.log(`  Normalised TYPE: "${normalised['TYPE']}"`);
console.log(`  Normalised ACTN: "${normalised['ACTN']}"`);
console.log(`  Normalised HEAD.CMID: ${normalised['HEAD'] && normalised['HEAD']['CMID']}`);
console.log(`  Normalised HEAD.SVID: ${normalised['HEAD'] && normalised['HEAD']['SVID']}`);
console.log('');

// ---- Test 6: String encoding ----
console.log('Test 6: String encoding');
const stringMsg = {
  'TYPE': 'WI  ',
  'BODY': {
    'CLI ': '447700900123'
  }
};
try {
  const encoded = codec.encodeMap(stringMsg);
  const decoded = codec.decodeMap(encoded, false);
  const cli = decoded['BODY']['CLI '];
  console.log(`  CLI value: "${cli}" (expected: "447700900123")`);
  console.log(`  ✓ String passed: ${cli === '447700900123'}\n`);
} catch (err) {
  console.log(`  ✗ Error: ${err.message}\n`);
}

// ---- Test 7: Null values ----
console.log('Test 7: Null values');
const nullMsg = {
  'TYPE': 'WD  ',
  'BODY': {
    'WALT': 12345,
    'DLKW': null,
    'DLRM': null
  }
};
try {
  const encoded = codec.encodeMap(nullMsg);
  const decoded = codec.decodeMap(encoded, false);
  console.log(`  DLKW: ${decoded['BODY']['DLKW']} (expected: null)`);
  console.log(`  DLRM: ${decoded['BODY']['DLRM']} (expected: null)`);
  console.log(`  ✓ Nulls passed: ${decoded['BODY']['DLKW'] === null && decoded['BODY']['DLRM'] === null}\n`);
} catch (err) {
  console.log(`  ✗ Error: ${err.message}\n`);
}

// ---- Test 8: Array encoding (Named Events) ----
console.log('Test 8: Array encoding (Named Events)');
const neMsg = {
  'TYPE': 'NE  ',
  'BODY': {
    'EVTS': [
      {
        'CLSS': 'Data',
        'NAME': 'GPRS_Session',
        'MIN ': 1,
        'MAX ': 100,
        'DISC': 0
      }
    ]
  }
};
try {
  const encoded = codec.encodeMap(neMsg);
  const decoded = codec.decodeMap(encoded, false);
  const evts = decoded['BODY']['EVTS'];
  console.log(`  EVTS array length: ${evts.length} (expected: 1)`);
  console.log(`  EVTS[0].NAME: "${evts[0]['NAME']}" (expected: "GPRS_Session")`);
  console.log(`  EVTS[0].MIN : ${evts[0]['MIN ']} (expected: 1)`);
  console.log(`  EVTS[0].MAX : ${evts[0]['MAX ']} (expected: 100)`);
  console.log(`  ✓ Array passed\n`);
} catch (err) {
  console.log(`  ✗ Error: ${err.message}\n`);
}

// ---- Test 9: Full roundtrip of all messages from testMessages.json ----
console.log('Test 9: Full roundtrip of testMessages.json');
try {
  const testMsgsPath = path.join(__dirname, '..', 'testMessages.json');
  const testMsgs = JSON.parse(fs.readFileSync(testMsgsPath, 'utf-8'));
  let ok = 0, fail = 0;
  for (const msg of testMsgs) {
    try {
      const encoded = codec.encodeMap(msg);
      const decoded = codec.decodeMap(encoded, false);

      // Verify TYPE roundtrips
      const origType = msg['TYPE'];
      const decodedType = decoded['TYPE'];
      if (origType && decodedType !== origType) {
        console.log(`  ✗ TYPE mismatch: "${origType}" -> "${decodedType}" (${msg._comment})`);
        fail++;
      } else {
        ok++;
      }
    } catch (err) {
      console.log(`  ✗ ${msg._comment || 'unknown'}: ${err.message}`);
      fail++;
    }
  }
  console.log(`  Results: ${ok} passed, ${fail} failed out of ${testMsgs.length} messages\n`);
} catch (err) {
  console.log(`  ✗ Could not load testMessages.json: ${err.message}\n`);
}

// ---- Test 10: Full roundtrip of testMessagesNew.json (friendly format) ----
console.log('Test 10: Full roundtrip of testMessagesNew.json (friendly format)');
try {
  const testMsgsPath = path.join(__dirname, '..', 'testMessagesNew.json');
  const testMsgs = JSON.parse(fs.readFileSync(testMsgsPath, 'utf-8'));
  let ok = 0, fail = 0;
  for (const msg of testMsgs) {
    try {
      // Normalise to raw, encode, decode
      const normalised = codec.normaliseToRaw(msg);
      const encoded = codec.encodeMap(normalised);
      const decoded = codec.decodeMap(encoded, false);

      // Verify TYPE roundtrips
      const origType = msg['FOX Type'] || normalised['TYPE'];
      const decodedType = decoded['TYPE'];
      if (origType && decodedType !== origType) {
        console.log(`  ✗ TYPE mismatch: "${origType}" -> "${decodedType}" (${msg._comment})`);
        fail++;
      } else {
        ok++;
      }
    } catch (err) {
      console.log(`  ✗ ${msg._comment || 'unknown'}: ${err.message}`);
      fail++;
    }
  }
  console.log(`  Results: ${ok} passed, ${fail} failed out of ${testMsgs.length} messages\n`);
} catch (err) {
  console.log(`  ✗ Could not load testMessagesNew.json: ${err.message}\n`);
}

console.log('═══════════════════════════════════════════════════');
console.log('  Tests complete');
console.log('═══════════════════════════════════════════════════');
