/**
 * OCNCC Billing Engine Escher Fields.
 * Symbol <-> human-readable label mapping for the Escher protocol

 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

const fs = require('fs');
const path = require('path');

let SYMBOL_TO_LABEL = {};
let LABEL_TO_SYMBOL = {};

try {
  const mappingPath = path.join(__dirname, '..', 'escher_fields.json');
  SYMBOL_TO_LABEL = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));

  // Build reverse mapping
  for (const [sym, label] of Object.entries(SYMBOL_TO_LABEL)) {
    LABEL_TO_SYMBOL[label] = sym;
  }
} catch (err) {
  console.error('[escher-fields] Failed to load escher_fields.json:', err.message);
}

module.exports = { SYMBOL_TO_LABEL, LABEL_TO_SYMBOL };
