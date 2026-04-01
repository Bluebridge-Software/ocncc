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

const Config = require('./config/config');
const BeClient = require('./services/be-client');
const { getRedisClient } = require('./services/redis-client');
const StatsTracker = require('./services/stats-tracker');
const createRouter = require('./routes/api');
const createDatabaseRouter = require('./routes/database-api');
const buildSpec = require('./config/swagger-spec');
const buildDatabaseSpec = require('./config/swagger-database-spec');
const createAuthMiddleware = require('./middleware/auth');
const AlertManager = require('./services/alert-manager');

// Database
const OracleConnector = require('./database/oracle-connector');
const { BbsProfileBlock } = require('./database/BbsProfileBlock');
const { getProfileTags, getVWSNodes, formatVWSNodes } = require('./database/database-queries');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const config = new Config();
const PORT = config.get('port');

// ---------------------------------------------------------------------------
// Initialise core services
// ---------------------------------------------------------------------------
const db = new OracleConnector();
const beClient = new BeClient(config);
const statsTracker = new StatsTracker(config);
const alertManager = new AlertManager(config);

// ---------------------------------------------------------------------------
// Initialise Redis (shared across stats + DB cache)
// ---------------------------------------------------------------------------
let redis = null;
if (config.get('redisEnabled')) {
  (async () => {
    redis = await getRedisClient();

    if (!redis) {
      console.warn('[Redis] Redis unavailable — caching disabled');
    }
  })();
}

// ---------------------------------------------------------------------------
// Initialise profile parser (singleton shared across the whole process)
// ---------------------------------------------------------------------------
const profileParser = new BbsProfileBlock({ debug: false });

/**
 * Load (or reload) profile tag metadata into profileParser.
 * Called once at startup and then on a configurable interval.
 *
 * @param {object}  [opts]
 * @param {boolean} [opts.forceRefresh=false]  Bypass Redis cache
 */
async function loadProfileTags(opts = {}) {
  try {
    const payload = await getProfileTags(db, redis, opts);

    if (!payload || payload.count === 0) {
      console.warn('[ProfileParser] No tag definitions returned — parser will run without friendly names');
      return;
    }

    // Inject directly into the parser (same shape as loadTagMeta expects)
    profileParser._tagMeta = new Map(payload.data.map(t => [t.tagId.toUpperCase(), t]));
    profileParser._tagTree = payload.tree;

    console.log(`[ProfileParser] Loaded ${payload.count} tag definitions`);
  } catch (err) {
    // Non-fatal — the server still starts, profiles decode without friendly names
    console.error('[ProfileParser] Failed to load tag metadata:', err.message);
  }
}

// ---------------------------------------------------------------------------
// Express app setup
// ---------------------------------------------------------------------------
const app = express();

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Request logging
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/db/')) {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
    });
  }
  next();
});

// ---------------------------------------------------------------------------
// Swagger — merge billing engine spec + database spec into one UI
// ---------------------------------------------------------------------------
const mainSpec = buildSpec(config.get('serverUrl'), config.get('serverDescription'));
const dbSpec = buildDatabaseSpec();

// Merge tags
mainSpec.tags = [...(mainSpec.tags || []), ...dbSpec.tags];

// Merge paths
Object.assign(mainSpec.paths, dbSpec.paths);

// Merge components (schemas + responses)
mainSpec.components.schemas = Object.assign({}, mainSpec.components.schemas || {}, dbSpec.components.schemas);
mainSpec.components.responses = Object.assign({}, mainSpec.components.responses || {}, dbSpec.components.responses);

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
    requestSnippetsEnabled: true,
  },
};

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(mainSpec, swaggerOptions));

// ---------------------------------------------------------------------------
// Rate limiting & Auth (applied to both /api and /db routes)
// ---------------------------------------------------------------------------
const apiLimiter = rateLimit({
  windowMs: 1000,
  max: config.get('rateLimitPerSecond') || 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many API requests, please try again later.' },
});

const authMiddleware = createAuthMiddleware(config, statsTracker, alertManager);

// ---------------------------------------------------------------------------
// Mount routers
// ---------------------------------------------------------------------------

// Billing engine API  →  /api/*
app.use('/api', apiLimiter, authMiddleware, createRouter(beClient, statsTracker));

// Database / subscriber API  →  /db/*
// db router gets the shared oracle connector, profileParser singleton, and redis
app.use('/db', apiLimiter, authMiddleware, createDatabaseRouter(db, profileParser, redis));

// ---------------------------------------------------------------------------
// Root redirect
// ---------------------------------------------------------------------------
app.get('/', (req, res) => res.redirect('/api-docs'));

// ---------------------------------------------------------------------------
// Error handler
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('[Server Error]', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
const WIDTH = 59;

function line(label, value = '') {
  const content = value ? `${label}${value}` : label;
  return `║ ${content.padEnd(WIDTH - 1)}║`;
}

const server = app.listen(PORT, config.get('host'), async () => {
  const baseUrl = config.get('serverUrl');

  // -------------------------------------------------------------------------
  // Post-listen async initialisation
  // -------------------------------------------------------------------------
  let dbReady = false;
  try {
    // 1. Initialise Oracle connection pool
    await db.initialise();

    // Pool creation succeeds even when DB is unreachable — probe it
    await db.testConnection(); // e.g. SELECT 1 FROM DUAL

    dbReady = true;
    console.log('[DB] Oracle connection pool ready');
  } catch (err) {
    console.warn('[DB] Oracle unreachable, continuing without DB:', err.message);
  }

  try {
    // 2. Load profile tag metadata into the parser immediately
    await loadProfileTags();
    console.log('[ProfileParser] Profiles loaded');

    // 3. Schedule periodic refresh (default: every 60 minutes)
    const refreshIntervalMs = (config.get('profileTagRefreshMinutes') || 60) * 60 * 1000;
    const refreshTimer = setInterval(async () => {
      console.log('[ProfileParser] Scheduled tag metadata refresh...');
      await loadProfileTags({ forceRefresh: true });
    }, refreshIntervalMs);

    // Don't block graceful shutdown
    if (refreshTimer.unref) refreshTimer.unref();

    console.log(`[ProfileParser] Tag metadata will refresh every ${refreshIntervalMs / 60000} minutes`);

  } catch (err) {
    // DB unavailable at startup — server still runs, DB routes will 500 until DB is up
    console.error('[Startup] Database initialisation failed:', err.message);
    console.error('[Startup] Server is running but /db/* routes will be unavailable until DB connects');
  }

  if (redis) {
    console.log('[Redis] Redis is available');
  } else {
    console.log('[Redis] Redis is unavailable');
  }

  if (db._initialised && config.get('useDatabaseForBillingEngines')) {
    console.log('[BeClient] Using database for billing engine initialisation');
    const engineJSON = await getVWSNodes(db, redis);
    const engineConfigs = formatVWSNodes(engineJSON);
    console.log(engineConfigs);
    for (const engineConfig of engineConfigs) {
      beClient.addBillingEngine(engineConfig);
    }
  } else {
    console.log('[BeClient] Using config file for billing engine initialisation');
    const engineConfigs = config.getBillingEngines();
    for (const engineConfig of engineConfigs) {
      beClient.addBillingEngine(engineConfig);
    }
  }

  console.log('');
  console.log('╔' + '═'.repeat(WIDTH) + '╗');
  console.log(line('      OCNCC Billing Engine Client - REST API Server'));
  console.log('╠' + '═'.repeat(WIDTH) + '╣');
  console.log(line('  Server:      ', baseUrl));
  console.log(line('  Swagger UI:  ', `${baseUrl}/api-docs`));
  console.log(line('  API Base:    ', `${baseUrl}/api`));
  console.log(line('  DB API:      ', `${baseUrl}/db`));
  console.log(line('  Health:      ', `${baseUrl}/api/health`));
  console.log('╠' + '═'.repeat(WIDTH) + '╣');
  console.log(line('  Client Name:     ', config.get('clientName')));
  console.log(line('  Message Timeout: ', `${config.get('messageTimeoutMs')}ms`));
  console.log(line('  Heartbeat:       ', `${config.get('heartbeatIntervalMs')}ms`));
  console.log(line('  Billing Engines: ', `${config.getBillingEngines().length} configured`));
  console.log(line('  Redis:           ', redis ? (config.get('redisUrl') || 'redis://localhost:6379') : 'disabled'));
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
function shutdown(signal) {
  console.log(`\n[Server] ${signal} received — shutting down...`);
  beClient.destroy();
  statsTracker.destroy();
  alertManager.destroy();
  if (redis) redis.disconnect();
  server.close(async () => {
    try { await db.close(); } catch { /* best-effort */ }
    console.log('[Server] Stopped.');
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = { app, db, profileParser, redis };