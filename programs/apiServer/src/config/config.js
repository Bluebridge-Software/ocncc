/**
 * OCNCC Billing Engine Configuration.
 * Configuration management for the BE Client service
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const DEFAULT_CONFIG = {
  // Server settings
  port: 3010,
  host: '0.0.0.0',
  serverUrl: '',  // Dynamic
  serverDescription: 'Local development',


  // Billing Engine defaults
  messageTimeoutMs: 2000,              // 2 seconds (DEFAULT_MESSAGE_TIMEOUT_SECONDS)
  heartbeatIntervalMs: 3000,           // 3 seconds (default heartBeatPeriod)
  connectionRetryMs: 5000,             // 5 seconds (connectionRetryTime)
  primaryFailbackIntervalMs: -1,       // -1 = disabled (PRIMARY_FAILBACK_DISABLED)
  maxOutstandingMessages: 0xFFFFFFFF,  // effectively unlimited
  reportPeriodSeconds: 10,

  // Client identification
  clientName: 'bbs-be-client',

  // Statistics collection
  statsPeriodMinutes: 5,               // Aggregate calls into 5-minute buckets
  statsRetentionDays: 3,               // Store stats for 3 days

  // Rate limiting (per second per IP)
  rateLimitPerSecond: 100,             // Max API calls per second

  // JWT Authentication
  jwtSecret: 'YOUR_SUPER_SECRET_KEY_CHANGE_IN_PRODUCTION',
  jwtEnabled: true,                    // Require JWT authentication for APIs

  // Redis Statistics Cache
  redisEnabled: true,                 // Optionally enable Redis for API statistics
  redisUrl: 'redis://swisspi:6379',   // Redis connection URL (overridden by individual fields below if set)
  redisHost: 'swisspi',               // BE_REDIS_HOST
  redisPort: 6379,                    // BE_REDIS_PORT
  redisUser: 'intellicharter',        // BE_REDIS_USER
  redisPassword: 'w1mbold345',        // BE_REDIS_PASSWORD

  // Alerting - Syslog
  syslogEnabled: false,
  syslogHost: 'localhost',
  syslogPort: 514,

  // Alerting - SNMP
  snmpEnabled: false,
  snmpHost: 'localhost',
  snmpPort: 162,                       // SNMP Traps usually go to port 162
  snmpCommunity: 'public',

  // Billing engines configuration
  // Each entry: { id, primary: { ip, port }, secondary: { ip, port } }
  billingEngines: [],
  useDatabaseForBillingEngines: true,

  // Database feature flag — set to false to disable all Oracle connection attempts
  databaseEnabled: true,

  // How often to retry a failed DB connection (minutes)
  dbRetryIntervalMinutes: 1,

  // How often to refresh profile tag metadata from DB (minutes)
  profileTagRefreshMinutes: 60,

  // How often to re-read VWS node config from DB and reconcile billing engines (minutes)
  engineConfigRefreshMinutes: 5,

  // How often to re-check billing engine readiness when using static config (minutes)
  engineReadinessCheckMinutes: 1,
};

class Config {
  constructor(overrides = {}) {
    this.settings = { ...DEFAULT_CONFIG, ...overrides };

    // Allow environment variable overrides
    if (process.env.BE_PORT) this.settings.port = parseInt(process.env.BE_PORT, 10);
    if (process.env.BE_HOST) this.settings.host = process.env.BE_HOST;
    if (process.env.BE_SERVER_DESCRIPTION) this.settings.serverDescription = process.env.BE_SERVER_DESCRIPTION;

    // Default serverUrl to port if not specified
    if (process.env.BE_SERVER_URL) {
      this.settings.serverUrl = process.env.BE_SERVER_URL;
    } else if (!this.settings.serverUrl) {
      this.settings.serverUrl = `http://localhost:${this.settings.port}`;
    }

    if (process.env.BE_CLIENT_NAME) this.settings.clientName = process.env.BE_CLIENT_NAME;
    if (process.env.BE_MESSAGE_TIMEOUT_MS) this.settings.messageTimeoutMs = parseInt(process.env.BE_MESSAGE_TIMEOUT_MS, 10);
    if (process.env.BE_HEARTBEAT_INTERVAL_MS) this.settings.heartbeatIntervalMs = parseInt(process.env.BE_HEARTBEAT_INTERVAL_MS, 10);
    if (process.env.BE_CONNECTION_RETRY_MS) this.settings.connectionRetryMs = parseInt(process.env.BE_CONNECTION_RETRY_MS, 10);
    if (process.env.BE_PRIMARY_FAILBACK_MS) this.settings.primaryFailbackIntervalMs = parseInt(process.env.BE_PRIMARY_FAILBACK_MS, 10);

    // Stats & Rate Limit Overrides
    if (process.env.BE_STATS_PERIOD_MINUTES) this.settings.statsPeriodMinutes = parseInt(process.env.BE_STATS_PERIOD_MINUTES, 10);
    if (process.env.BE_STATS_RETENTION_DAYS) this.settings.statsRetentionDays = parseInt(process.env.BE_STATS_RETENTION_DAYS, 10);
    if (process.env.BE_RATE_LIMIT_PER_SECOND) this.settings.rateLimitPerSecond = parseInt(process.env.BE_RATE_LIMIT_PER_SECOND, 10);

    // JWT Security Overrides
    if (process.env.BE_JWT_SECRET) this.settings.jwtSecret = process.env.BE_JWT_SECRET;
    if (process.env.BE_JWT_ENABLED) this.settings.jwtEnabled = process.env.BE_JWT_ENABLED === 'true';

    // Redis Cache Overrides
    if (process.env.BE_REDIS_ENABLED) this.settings.redisEnabled = process.env.BE_REDIS_ENABLED === 'true';
    if (process.env.BE_REDIS_URL) this.settings.redisUrl = process.env.BE_REDIS_URL;
    if (process.env.BE_REDIS_HOST) this.settings.redisHost = process.env.BE_REDIS_HOST;
    if (process.env.BE_REDIS_PORT) this.settings.redisPort = parseInt(process.env.BE_REDIS_PORT, 10);
    if (process.env.BE_REDIS_USER) this.settings.redisUser = process.env.BE_REDIS_USER;
    if (process.env.BE_REDIS_PASSWORD) this.settings.redisPassword = process.env.BE_REDIS_PASSWORD;

    // Syslog Overrides
    if (process.env.BE_SYSLOG_ENABLED) this.settings.syslogEnabled = process.env.BE_SYSLOG_ENABLED === 'true';
    if (process.env.BE_SYSLOG_HOST) this.settings.syslogHost = process.env.BE_SYSLOG_HOST;
    if (process.env.BE_SYSLOG_PORT) this.settings.syslogPort = parseInt(process.env.BE_SYSLOG_PORT, 10);

    // SNMP Overrides
    if (process.env.BE_SNMP_ENABLED) this.settings.snmpEnabled = process.env.BE_SNMP_ENABLED === 'true';
    if (process.env.BE_SNMP_HOST) this.settings.snmpHost = process.env.BE_SNMP_HOST;
    if (process.env.BE_SNMP_PORT) this.settings.snmpPort = parseInt(process.env.BE_SNMP_PORT, 10);
    if (process.env.BE_SNMP_COMMUNITY) this.settings.snmpCommunity = process.env.BE_SNMP_COMMUNITY;

    // Database feature flag & timing overrides
    if (process.env.DATABASE_ENABLED)
      this.settings.databaseEnabled = process.env.DATABASE_ENABLED !== 'false' &&
        process.env.DATABASE_ENABLED.toLowerCase() !== 'false';
    if (process.env.DB_RETRY_INTERVAL_MINUTES)
      this.settings.dbRetryIntervalMinutes = parseInt(process.env.DB_RETRY_INTERVAL_MINUTES, 10);
    if (process.env.PROFILE_TAG_REFRESH_MINUTES)
      this.settings.profileTagRefreshMinutes = parseInt(process.env.PROFILE_TAG_REFRESH_MINUTES, 10);
    if (process.env.ENGINE_CONFIG_REFRESH_MINUTES)
      this.settings.engineConfigRefreshMinutes = parseInt(process.env.ENGINE_CONFIG_REFRESH_MINUTES, 10);
    if (process.env.ENGINE_READINESS_CHECK_MINUTES)
      this.settings.engineReadinessCheckMinutes = parseInt(process.env.ENGINE_READINESS_CHECK_MINUTES, 10);
    if (process.env.USE_DATABASE_FOR_BILLING_ENGINES)
      this.settings.useDatabaseForBillingEngines = process.env.USE_DATABASE_FOR_BILLING_ENGINES === 'true';

    // Parse BE_ENGINES env var: "1:10.0.0.1:1500:10.0.0.2:1500,2:10.0.0.3:1500:10.0.0.4:1500"
    if (process.env.BE_ENGINES) {
      this.settings.billingEngines = process.env.BE_ENGINES.split(',').map(entry => {
        const parts = entry.trim().split(':');
        const engine = {
          id: parseInt(parts[0], 10),
          primary: { ip: parts[1], port: parseInt(parts[2], 10) }
        };
        if (parts.length >= 5) {
          engine.secondary = { ip: parts[3], port: parseInt(parts[4], 10) };
        }
        return engine;
      });
    }
  }

  get(key) {
    return this.settings[key];
  }

  getBillingEngines() {
    return this.settings.billingEngines;
  }

  addBillingEngine(engineConfig) {
    // Remove existing with same ID
    this.settings.billingEngines = this.settings.billingEngines.filter(e => e.id !== engineConfig.id);
    this.settings.billingEngines.push(engineConfig);
  }

  removeBillingEngine(id) {
    this.settings.billingEngines = this.settings.billingEngines.filter(e => e.id !== id);
  }

  toJSON() {
    return { ...this.settings };
  }

  getLoggerConfig() {
    const env = process.env.NODE_ENV || 'development';

    const configs = {
      development: {
        level: 'DEBUG',
        enabled: true,
        json: false,
        colors: true,
        timestamp: true,
      },
      staging: {
        level: 'TRACE',
        enabled: true,
        json: true,
        colors: false,
        timestamp: true,
      },
      production: {
        level: 'INFO',
        enabled: true,
        json: true,
        colors: false,
        timestamp: true,
      },
    };

    return {
      ...configs[env],
      level: CONFIG.LOG_LEVEL,
      enabled: CONFIG.LOG_ENABLED,
      json: CONFIG.LOG_JSON,
      colors: CONFIG.LOG_COLORS,
      timestamp: CONFIG.LOG_TIMESTAMPS,
    };
  }
}

module.exports = Config;