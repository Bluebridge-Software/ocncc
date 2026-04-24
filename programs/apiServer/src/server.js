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
const createDbGuard = require('./middleware/db-guard');
const createDatabaseRouter = require('./routes/database-api');
const createProfileRouter = require('./routes/profileBlock-api');
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
// Feature flags (from .env)
//
//   DATABASE_ENABLED=false  — disables all Oracle connection attempts entirely.
//                             /db routes return 503, Swagger DB paths never merged.
// ---------------------------------------------------------------------------
const DB_ENABLED = config.get('databaseEnabled') !== false &&
  String(config.get('databaseEnabled')).toLowerCase() !== 'false';

// ---------------------------------------------------------------------------
// Initialise core services
// ---------------------------------------------------------------------------
const db = DB_ENABLED ? new OracleConnector() : null;
const beClient = new BeClient(config);
const statsTracker = new StatsTracker(config);
const alertManager = new AlertManager(config);

// ---------------------------------------------------------------------------
// State — module-level so routes, guards, and timers can share it
// ---------------------------------------------------------------------------

// DB readiness
let dbReady = false;
let dbRetryTimer = null;
let profileRefreshTimer = null;

// Billing engine readiness — true once at least one engine connection is active
let enginesReady = false;
let engineConfigRefreshTimer = null;
let enginesReadinessTimer = null;  // polls availability after engines are configured

// Stable hash of the last known engine config from DB, used to diff on refresh
let lastEngineConfigHash = null;

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
const profileParser = DB_ENABLED ? new BbsProfileBlock({ debug: false }) : null;

/**
 * Load (or reload) profile tag metadata into profileParser.
 * Only called when DB_ENABLED is true and dbReady is true.
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

    profileParser._tagMeta = new Map(payload.data.map(t => [t.tagId.toUpperCase(), t]));
    profileParser._tagTree = payload.tree;

    console.log(`[ProfileParser] Loaded ${payload.count} tag definitions`);
  } catch (err) {
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
// Swagger — billing engine spec only at startup.
// DB paths are merged in once the DB is reachable (when DB_ENABLED is true).
// ---------------------------------------------------------------------------
const mainSpec = buildSpec(config.get('serverUrl'), config.get('serverDescription'));
const dbSpec = DB_ENABLED ? buildDatabaseSpec() : null;

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

/**
 * Merge DB paths/schemas into the live Swagger spec once.
 * swagger-ui-express holds a reference to mainSpec so changes appear on next
 * browser reload without restarting the server.
 */
let dbSpecMerged = false;
function mergeDbSpec() {
  if (!DB_ENABLED || !dbSpec || dbSpecMerged) return;
  dbSpecMerged = true;
  dbReady = true;

  mainSpec.tags = [...(mainSpec.tags || []), ...dbSpec.tags];
  Object.assign(mainSpec.paths, dbSpec.paths);
  mainSpec.components.schemas = Object.assign({}, mainSpec.components.schemas || {}, dbSpec.components.schemas);
  mainSpec.components.responses = Object.assign({}, mainSpec.components.responses || {}, dbSpec.components.responses);

  console.log('[Swagger] Database endpoints merged into API spec');

  // 🔥 Re-mount swagger
  app._router.stack = app._router.stack.filter(
    layer => !(layer.route && layer.route.path === '/api-docs')
  );

  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(mainSpec, swaggerOptions));
}
/*
function mergeDbSpec() {
  console.log('[Swagger] Merging DB spec into API spec');
  if (!DB_ENABLED || !dbSpec || dbSpecMerged) return;
  dbSpecMerged = true;
  dbReady = true;

  mainSpec.tags = [...(mainSpec.tags || []), ...dbSpec.tags];
  Object.assign(mainSpec.paths, dbSpec.paths);
  mainSpec.components.schemas = Object.assign({}, mainSpec.components.schemas || {}, dbSpec.components.schemas);
  mainSpec.components.responses = Object.assign({}, mainSpec.components.responses || {}, dbSpec.components.responses);

  console.log('[Swagger] Database endpoints merged into API spec');
}
  */

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(mainSpec, swaggerOptions));

// ---------------------------------------------------------------------------
// Rate limiting & Auth
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
// createRouter receives a getter so the health endpoint reflects live state.
// All non-health endpoints are gated behind an enginesReady check.
const apiRouter = createRouter(beClient, statsTracker, () => dbReady);

app.use('/api', apiLimiter, authMiddleware, (req, res, next) => {
  // Always let health checks through — this is how callers detect readiness
  if (req.path === '/health') return next();

  if (!enginesReady) {
    return res.status(503).json({
      error: 'No billing engines available',
      message: 'No billing engine connections are currently active. Check /api/health for status.',
    });
  }
  next();
}, apiRouter);

// Database / subscriber API  →  /db/*
// createDbGuard returns 503 when dbReady is false or DB_ENABLED is false.
const dbRouter = DB_ENABLED ? createDatabaseRouter(db, profileParser, redis) : null;

app.use('/db', apiLimiter, authMiddleware, createDbGuard(() => dbReady), (req, res, next) => {
  if (!dbRouter) {
    return res.status(503).json({
      error: 'Database is disabled',
      message: 'DATABASE_ENABLED=false in server configuration.',
    });
  }
  dbRouter(req, res, next);
});

const profileRouter = createProfileRouter(profileParser);
app.use('/profile', apiLimiter, authMiddleware, createDbGuard(() => dbReady), (req, res, next) => {
  if (!profileRouter) {
    return res.status(503).json({
      error: 'Database is disabled',
      message: 'DATABASE_ENABLED=false in server configuration.',
    });
  }
  profileRouter(req, res, next);
});

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
// Billing engine management
// ---------------------------------------------------------------------------

/**
 * Stable hash of an engine config array — cheap change detection on refresh.
 */
function hashEngineConfigs(configs) {
  return JSON.stringify(
    configs
      .map(e => ({ id: e.id, primary: e.primary, secondary: e.secondary }))
      .sort((a, b) => a.id - b.id)
  );
}

/**
 * Evaluate current engine availability and update enginesReady.
 * Starts/stops statsTracker in step with readiness transitions.
 * Called by the readiness polling loop.
 */
function evaluateEngineReadiness() {
  const status = beClient.getStatus();
  const wasReady = enginesReady;
  enginesReady = Object.values(status).some(e =>
    e.primary.available || (e.secondary && e.secondary.available)
  );

  if (!wasReady && enginesReady) {
    console.log('[BeClient] Billing engines active — /api routes open');
    // Start collecting statistics now that requests can flow
    if (statsTracker && typeof statsTracker.start === 'function') statsTracker.start();
  }

  if (wasReady && !enginesReady) {
    console.warn('[BeClient] All billing engine connections lost — /api routes suspended');
    // Pause statistics while no engines are reachable
    if (statsTracker && typeof statsTracker.pause === 'function') statsTracker.pause();
  }
}

/**
 * Start (or restart) the readiness polling loop.
 * Idempotent — safe to call multiple times; only one timer runs at a time.
 * Polls quickly at first (every 5 s) while engines are connecting, then
 * settles to the configured interval once stable.
 */
function startReadinessPolling() {
  if (enginesReadinessTimer) return; // already running

  const stableMs = (config.get('engineReadinessCheckMinutes') || 1) * 60 * 1000;

  // Use a short initial interval so the first connection is detected quickly,
  // then switch to the configured interval once we first become ready.
  let currentMs = 5000;
  let switched = false;

  function poll() {
    evaluateEngineReadiness();

    if (enginesReady && !switched) {
      // Engines came up — switch to the slower stable interval
      switched = true;
      currentMs = stableMs;
    }

    enginesReadinessTimer = setTimeout(poll, currentMs);
    if (enginesReadinessTimer.unref) enginesReadinessTimer.unref();
  }

  enginesReadinessTimer = setTimeout(poll, currentMs);
  if (enginesReadinessTimer.unref) enginesReadinessTimer.unref();

  console.log(`[BeClient] Readiness polling started (initial: ${currentMs / 1000}s, stable: ${stableMs / 1000}s)`);
}

/**
 * Apply a new set of engine configs to the live beClient:
 *   - Add engines that are new
 *   - Remove engines no longer present
 *   - Update (replace) engines whose connection details changed
 * Does NOT evaluate readiness immediately — the async TCP connections won't be
 * established yet. Readiness is tracked by startReadinessPolling() instead.
 */
function applyEngineConfigs(engineConfigs) {
  const incoming = new Map(engineConfigs.map(e => [e.id, e]));
  const currentStatus = beClient.getStatus();
  const existing = new Set(Object.keys(currentStatus).map(Number));

  // Remove engines no longer in config
  for (const id of existing) {
    if (!incoming.has(id)) {
      console.log(`[BeClient] Removing billing engine ${id} (dropped from config)`);
      beClient.removeBillingEngine(id);
    }
  }

  // Add or update engines (addBillingEngine is idempotent)
  for (const [id, cfg] of incoming) {
    if (!existing.has(id)) {
      console.log(`[BeClient] Adding billing engine ${id}`);
    }
    beClient.addBillingEngine(cfg);
  }

  // Kick off readiness polling — connections are async so we cannot evaluate
  // availability here. The polling loop will detect when they come up.
  startReadinessPolling();
}

/**
 * Poll the DB for VWS node config and reconcile with the live beClient.
 * Called once at DB-ready time, then on a periodic interval.
 */
async function refreshEngineConfigFromDb() {
  try {
    const engineJSON = await getVWSNodes(db, redis);
    const engineConfigs = formatVWSNodes(engineJSON);
    const newHash = hashEngineConfigs(engineConfigs);

    if (newHash === lastEngineConfigHash) return; // no change

    console.log('[BeClient] Engine configuration change detected — reconciling');
    lastEngineConfigHash = newHash;
    applyEngineConfigs(engineConfigs);
  } catch (err) {
    console.error('[BeClient] Failed to refresh engine config from DB:', err.message);
  }
}

/**
 * Initialise billing engines from the flat config file (non-DB path).
 * Also starts a periodic readiness check so enginesReady tracks live state.
 */
function initEnginesFromConfig() {
  console.log('[BeClient] Using config file for billing engine initialisation');
  const engineConfigs = config.getBillingEngines();

  if (engineConfigs.length === 0) {
    console.warn('[BeClient] No billing engines in config — /api routes suspended until engines are added');
    return;
  }

  applyEngineConfigs(engineConfigs);
  // Readiness polling is started inside applyEngineConfigs
}

// ---------------------------------------------------------------------------
// DB-dependent initialisation — runs once the connection probe succeeds
// ---------------------------------------------------------------------------
async function onDbReady() {
  // 1. Load profile tag metadata
  await loadProfileTags();
  console.log('[ProfileParser] Profiles loaded');

  // 2. Schedule periodic profile tag refresh
  const tagRefreshMs = (config.get('profileTagRefreshMinutes') || 60) * 60 * 1000;
  profileRefreshTimer = setInterval(async () => {
    console.log('[ProfileParser] Scheduled tag metadata refresh...');
    await loadProfileTags({ forceRefresh: true });
  }, tagRefreshMs);
  if (profileRefreshTimer.unref) profileRefreshTimer.unref();
  console.log(`[ProfileParser] Tag metadata will refresh every ${tagRefreshMs / 60000} minutes`);

  // 3. Load/reconcile billing engines from DB (if DB is the source of truth)
  if (config.get('useDatabaseForBillingEngines')) {
    console.log('[BeClient] Using database for billing engine configuration');
    await refreshEngineConfigFromDb();

    const engineRefreshMs = (config.get('engineConfigRefreshMinutes') || 5) * 60 * 1000;
    engineConfigRefreshTimer = setInterval(async () => {
      await refreshEngineConfigFromDb();
    }, engineRefreshMs);
    if (engineConfigRefreshTimer.unref) engineConfigRefreshTimer.unref();
    console.log(`[BeClient] Engine config will re-sync from DB every ${engineRefreshMs / 60000} minutes`);
  }

  // 4. Merge DB paths into the live Swagger spec
  mergeDbSpec();
}

// ---------------------------------------------------------------------------
// DB connection loop — tries once immediately, retries on schedule.
// Only entered when DB_ENABLED is true.
// ---------------------------------------------------------------------------
async function tryConnectDb() {
  dbRetryTimer = null;

  try {
    if (!db._initialised) {
      await db.initialise();
    }

    // Pool creation succeeds even when the host is unreachable — probe with a
    // real query to confirm the connection is actually usable.
    await db.testConnection();

    dbReady = true;
    console.log('[DB] Oracle connection pool ready');

    await onDbReady();

  } catch (err) {
    dbReady = false;
    const retryMs = (config.get('dbRetryIntervalMinutes') || 1) * 60 * 1000;
    console.warn(`[DB] Oracle unreachable (${err.message}) — retrying in ${retryMs / 1000}s`);

    dbRetryTimer = setTimeout(tryConnectDb, retryMs);
    if (dbRetryTimer.unref) dbRetryTimer.unref();
  }
}

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

  if (redis) {
    console.log('[Redis] Redis is available');
  } else {
    console.log('[Redis] Redis is unavailable');
  }

  // Billing engines from config loaded now; DB-sourced engines loaded in onDbReady()
  if (!config.get('useDatabaseForBillingEngines')) {
    initEnginesFromConfig();
  }

  const dbStatusLabel = !DB_ENABLED ? 'disabled' : 'connecting (non-blocking)...';

  console.log('');
  console.log('╔' + '═'.repeat(WIDTH) + '╗');
  console.log(line('      OCNCC Billing Engine Client - REST API Server'));
  console.log('╠' + '═'.repeat(WIDTH) + '╣');
  console.log(line('  Server:           ', baseUrl));
  console.log(line('  Swagger UI:       ', `${baseUrl}/api-docs`));
  console.log(line('  API Base:         ', `${baseUrl}/api`));
  console.log(line('  DB API:           ', `${baseUrl}/db`));
  console.log(line('  Health:           ', `${baseUrl}/api/health`));
  console.log('╠' + '═'.repeat(WIDTH) + '╣');
  console.log(line('  Client Name:          ', config.get('clientName')));
  console.log(line('  Message Timeout:      ', `${config.get('messageTimeoutMs')}ms`));
  console.log(line('  Heartbeat:            ', `${config.get('heartbeatIntervalMs')}ms`));
  console.log(line('  File Billing Engines: ', `${config.getBillingEngines().length} configured`));
  console.log(line('  Redis:                ', redis ? (config.get('redisUrl') || 'redis://localhost:6379') : 'disabled'));
  console.log(line('  Database:             ', dbStatusLabel));
  console.log('╚' + '═'.repeat(WIDTH) + '╝');
  console.log('');

  if (!enginesReady && !config.get('useDatabaseForBillingEngines')) {
    console.log('⚠  No billing engines configured. Add them via:');
    console.log('   POST /api/config/engines');
    console.log('   or set BE_ENGINES env var: "1:10.0.0.1:1500:10.0.0.2:1500"');
    console.log('');
  }

  if (DB_ENABLED) {
    tryConnectDb();
  } else {
    console.log('[DB] Database disabled (DATABASE_ENABLED=false) — skipping connection');
  }
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------
let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return; // guard against duplicate signals
  shuttingDown = true;

  console.log(`\n[Server] ${signal} received — shutting down gracefully...`);

  // 1. Stop accepting new HTTP connections immediately
  server.close(() => console.log('[Server] HTTP server closed — no new connections accepted'));

  // 2. Cancel all background timers
  if (dbRetryTimer) clearTimeout(dbRetryTimer);
  if (profileRefreshTimer) clearInterval(profileRefreshTimer);
  if (engineConfigRefreshTimer) clearInterval(engineConfigRefreshTimer);
  if (enginesReadinessTimer) clearTimeout(enginesReadinessTimer);

  // 3. Close billing engine TCP connections cleanly (sends FIN to each BE)
  console.log('[BeClient] Closing billing engine connections...');
  try { beClient.destroy(); } catch (err) { console.warn('[BeClient] destroy error:', err.message); }

  // 4. Shut down supporting services
  try { statsTracker.destroy(); } catch { /* best-effort */ }
  try { alertManager.destroy(); } catch { /* best-effort */ }

  // 5. Disconnect Redis
  if (redis) {
    console.log('[Redis] Disconnecting...');
    try { redis.disconnect(); } catch { /* best-effort */ }
  }

  // 6. Close Oracle pool — allows in-flight queries to complete before draining
  if (DB_ENABLED && db) {
    console.log('[DB] Closing Oracle connection pool...');
    try {
      await db.close();
      console.log('[DB] Oracle pool closed');
    } catch (err) {
      console.warn('[DB] Error closing Oracle pool:', err.message);
    }
  }

  console.log('[Server] Shutdown complete.');
  process.exit(0);
}

// Guard: only run shutdown once even if both SIGINT and SIGTERM arrive
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// Surface unhandled rejections — prevents silent failures during async shutdown
process.on('unhandledRejection', (reason) => {
  console.error('[Server] Unhandled promise rejection:', reason);
});

module.exports = { app, db, profileParser, redis };