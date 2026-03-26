#!/usr/bin/env node

/**
 * generate-token.js
 * A helper script used to generate a JWT token bounded to a client identifier.
 * 
 * Usage: 
 *   node generate-token.js <input.json>
 * 
 * input.json format:
 * {
 *   "clientId": "ExampleNodeClient",
 *   "allowedEndpoints": ["/wallet-info", "/initial-reservation", "/stats"],
 *   "expiresIn": "7d"
 * }
 */

const fs = require('fs');
const path = require('path');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const Config = require('./config');

const config = new Config();
const secret = config.get('jwtSecret');
const MASTER_FILE = path.join(__dirname, 'auth-tokens.json');

// Read args
const args = process.argv.slice(2);
if (args.length !== 1) {
  console.log('Usage: node generate-token.js <input.json>');
  console.log('Example input.json:');
  console.log(JSON.stringify({
    clientId: 'ExampleClient',
    allowedEndpoints: ['/wallet-info', '/initial-reservation'],
    expiresIn: '7d'
  }, null, 2));
  process.exit(1);
}

const inputFile = args[0];
let inputConfig;

try {
  const content = fs.readFileSync(inputFile, 'utf-8');
  inputConfig = JSON.parse(content);
} catch (err) {
  console.error(`Error reading or parsing ${inputFile}:`, err.message);
  process.exit(1);
}

if (!inputConfig.clientId) {
  console.error('Error: "clientId" is required in the JSON configuration.');
  process.exit(1);
}

const clientId = inputConfig.clientId;
const allowedEndpoints = Array.isArray(inputConfig.allowedEndpoints) ? inputConfig.allowedEndpoints : ['*'];
const expiresIn = inputConfig.expiresIn || '7d';

// Prepare payload
const payload = {
  clientId,
  allowedEndpoints
};

// Sign Token
const token = jwt.sign(payload, secret, { expiresIn });

// Load Master JSON
let masterDb = {};
if (fs.existsSync(MASTER_FILE)) {
  try {
    masterDb = JSON.parse(fs.readFileSync(MASTER_FILE, 'utf-8'));
  } catch (err) {
    console.error(`Warning: Could not read ${MASTER_FILE}, treating as empty.`);
  }
}

// Update Master JSON
masterDb[clientId] = {
  token,
  allowedEndpoints,
  expiresIn,
  generatedAt: new Date().toISOString()
};

try {
  fs.writeFileSync(MASTER_FILE, JSON.stringify(masterDb, null, 2), 'utf-8');
} catch (err) {
  console.error(`Error saving to ${MASTER_FILE}:`, err.message);
}

console.log('');
console.log(`Token Generated for Client:   '${clientId}'`);
console.log(`Allowed Remote Endpoints:     ${JSON.stringify(allowedEndpoints)}`);
console.log(`Expiry Time:                  ${expiresIn}`);
console.log(`Master DB Updated:            ${MASTER_FILE}`);
console.log('\nCopy the following token and include it as an Authorization Bearer header:');
console.log(`\n${token}\n`);
