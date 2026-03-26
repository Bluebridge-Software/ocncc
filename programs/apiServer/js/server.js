/**
 * OCNCC Billing Engine REST API Server.
 * Express Server with Swagger UI
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const rateLimit = require('express-rate-limit');
const Config = require('./config');
const BeClient = require('./be-client');
const StatsTracker = require('./stats-tracker');
const createRouter = require('./routes/api');
const buildSpec = require('./swagger-spec');
const createAuthMiddleware = require('./auth');
const AlertManager = require('./alert-manager');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const config = new Config();
const PORT = config.get('port');

// ---------------------------------------------------------------------------
// Initialise BeClient and StatsTracker
// ---------------------------------------------------------------------------
const beClient = new BeClient(config);
const statsTracker = new StatsTracker(config);
const alertManager = new AlertManager(config);

// ---------------------------------------------------------------------------
// Express app setup
// ---------------------------------------------------------------------------
const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Request logging
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
    });
  }
  next();
});

// ---------------------------------------------------------------------------
// Swagger UI
// ---------------------------------------------------------------------------
const swaggerSpec = buildSpec(config.get('serverUrl'), config.get('serverDescription'));
const swaggerOptions = {
  customCss: `
    .swagger-ui .topbar { 
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); 
    }
    .swagger-ui .topbar .link { 
      display: flex; 
      align-items: center; 
    }
    .swagger-ui .topbar .link::before {
      content: '⚡';
      font-size: 24px;
      margin-right: 8px;
    }
    .swagger-ui .info .title { 
      color: #0f3460; 
    }
    .swagger-ui .btn.execute {
      background-color: #0f3460;
      border-color: #0f3460;
    }
    .swagger-ui .btn.execute:hover {
      background-color: #16213e;
    }
  `,
  customSiteTitle: 'OCNCC BE Client API',
  customfavIcon: '',
  swaggerOptions: {
    docExpansion: 'list',
    filter: true,
    defaultModelsExpandDepth: -1,
    tryItOutEnabled: true,
    requestSnippetsEnabled: true
  }
};

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, swaggerOptions));

// ---------------------------------------------------------------------------
// API routes, Rate Limiting & Auth
// ---------------------------------------------------------------------------
const apiLimiter = rateLimit({
  windowMs: 1000, // 1 second
  max: config.get('rateLimitPerSecond') || 100, // max requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many API requests, please try again later.' }
});

app.use('/api', apiLimiter, createAuthMiddleware(config, statsTracker, alertManager), createRouter(beClient, statsTracker));

// ---------------------------------------------------------------------------
// Root redirect
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.redirect('/api-docs');
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('[Server Error]', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
const WIDTH = 59; // total inner width between ║ ║

function line(label, value = '') {
  const content = value ? `${label}${value}` : label;
  return `║ ${content.padEnd(WIDTH - 1)}║`;
}

const server = app.listen(PORT, config.get('host'), () => {
  const baseUrl = config.get('serverUrl');

  console.log('');
  console.log('╔' + '═'.repeat(WIDTH) + '╗');

  console.log(line('      OCNCC Billing Engine Client - REST API Server'));

  console.log('╠' + '═'.repeat(WIDTH) + '╣');

  console.log(line('  Server:     ', baseUrl));
  console.log(line('  Swagger UI: ', `${baseUrl}/api-docs`));
  console.log(line('  API Base:   ', `${baseUrl}/api`));
  console.log(line('  Health:     ', `${baseUrl}/api/health`));

  console.log('╠' + '═'.repeat(WIDTH) + '╣');

  console.log(line('  Client Name:     ', config.get('clientName')));
  console.log(line('  Message Timeout: ', `${config.get('messageTimeoutMs')}ms`));
  console.log(line('  Heartbeat:       ', `${config.get('heartbeatIntervalMs')}ms`));
  console.log(line('  Billing Engines: ', `${config.getBillingEngines().length} configured`));

  console.log('╚' + '═'.repeat(WIDTH) + '╝');
  console.log('');

  if (config.getBillingEngines().length === 0) {
    console.log('⚠  No billing engines configured. Add them via:');
    console.log('   POST /api/config/engines');
    console.log('   or set BE_ENGINES env var: "1:10.0.0.1:1500:10.0.0.2:1500"');
    console.log('');
  }
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------
process.on('SIGINT', () => {
  console.log('\n[Server] Shutting down...');
  beClient.destroy();
  statsTracker.destroy();
  alertManager.destroy();
  server.close(() => {
    console.log('[Server] Stopped.');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('[Server] Received SIGTERM, shutting down...');
  beClient.destroy();
  statsTracker.destroy();
  alertManager.destroy();
  server.close(() => {
    process.exit(0);
  });
});

module.exports = app;
