const jwt = require('jsonwebtoken');
const fs = require('fs');
const secret = process.env.JWT_SECRET || 'BBS-OCNCC-BE-SECRET-2026';

const payload = {
  clientId: 'TestClientA',
  allowedEndpoints: ['*']
};

const token = jwt.sign(payload, secret, { expiresIn: '10y' });
const result = {
  'TestClientA': {
    token,
    allowedEndpoints: ['*'],
    expiresIn: '10y',
    generatedAt: new Date().toISOString()
  }
};

fs.writeFileSync('/Users/tcraven/Desktop/BeClient/js/auth-tokens.json', JSON.stringify(result, null, 2));
console.log('New Token:', token);
