/**
 * OCNCC Oracle Database Connector.
 * Manages an oracledb connection pool with automatic retry and FAN failover.
 *
 * Profile parsing is NOT the responsibility of this class — the profileParser
 * singleton lives in server.js and is injected into the database query layer.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

require('dotenv').config();
const oracledb = require('oracledb');

// Automatically cast CLOBs to strings
oracledb.fetchAsString = [oracledb.CLOB];

class OracleConnector {

    constructor(overrideConfig = {}) {
        this.poolAlias = overrideConfig.poolAlias || 'default_pool';

        this.config = {
            user: overrideConfig.user || process.env.ORACLE_USER,
            password: overrideConfig.password || process.env.ORACLE_PASSWORD,
            connectString: overrideConfig.connectString || this._getTnsDescription(),
            poolMin: overrideConfig.poolMin || 2,
            poolMax: overrideConfig.poolMax || 10,
            poolIncrement: overrideConfig.poolIncrement || 2,
            poolTimeout: overrideConfig.poolTimeout || 60,

            // CRITICAL FOR FAILOVER: Enables Fast Application Notification (FAN).
            // Allows the pool to receive "down" events from the DB cluster and
            // purge dead connections instantly, without waiting for TCP timeouts.
            events: true,
        };

        this.maxRetries = overrideConfig.maxRetries || 3;
        this.retryDelayMs = overrideConfig.retryDelayMs || 1000;
        this._initialised = false;
    }

    // -------------------------------------------------------------------------
    // TNS helper
    // -------------------------------------------------------------------------

    _getTnsDescription() {
        const tns = process.env.ORACLE_SMF_SERVICE;
        if (!tns) {
            throw new Error('TNS description not found in .env — ensure ORACLE_SMF_SERVICE is set');
        }
        return tns.replace(/\\n/g, '\n').trim();
    }

    // -------------------------------------------------------------------------
    // Pool lifecycle
    // -------------------------------------------------------------------------

    /**
     * Initialise the connection pool.  Called explicitly by server.js after
     * the HTTP server is listening — NOT from the constructor.
     */
    async initialise() {
        // If pool already exists under this alias, nothing to do
        try {
            oracledb.getPool(this.poolAlias);
            console.log(`[OracleConnector] Pool '${this.poolAlias}' already exists`);
            this._initialised = true;
            return;
        } catch {
            // Pool does not exist yet — fall through to create it
        }

        await oracledb.createPool({
            ...this.config,
            poolAlias: this.poolAlias,
        });

        this._initialised = true;
        console.log(`[OracleConnector] Pool '${this.poolAlias}' created (FAN enabled, min=${this.config.poolMin}, max=${this.config.poolMax})`);
    }

    /**
     * Gracefully drain and close the connection pool.
     * @param {number} [drainTimeoutSeconds=10]
     */
    async close(drainTimeoutSeconds = 10) {
        try {
            const pool = oracledb.getPool(this.poolAlias);
            await pool.close(drainTimeoutSeconds);
            this._initialised = false;
            console.log(`[OracleConnector] Pool '${this.poolAlias}' closed`);
        } catch (err) {
            console.error(`[OracleConnector] Error closing pool '${this.poolAlias}':`, err.message);
        }
    }

    // -------------------------------------------------------------------------
    // Query execution with retry on transient network errors
    // -------------------------------------------------------------------------

    _sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async testConnection() {
        let conn;
        try {
            conn = await oracledb.getConnection('default_pool');
            await conn.execute('SELECT 1 FROM DUAL');
            console.log('[OracleConnector] Connection probe successful');
        } finally {
            if (conn) await conn.close().catch(() => { });
        }
    }

    /**
     * Execute a query against the pool with automatic retry.
     *
     * @param {string}  query           SQL with :bind placeholders
     * @param {object}  [binds={}]      Bind variables
     * @param {object}  [options={}]    Extra oracledb execute options
     * @param {boolean} [returnAsJson=true]  OUT_FORMAT_OBJECT vs ARRAY
     * @returns {Promise<object[]>}
     */
    async executeQuery(query, binds = {}, options = {}, returnAsJson = true) {
        if (!this._initialised) {
            throw new Error('[OracleConnector] Pool not initialised — call initialise() first');
        }

        const execOptions = {
            ...options,
            outFormat: returnAsJson ? oracledb.OUT_FORMAT_OBJECT : oracledb.OUT_FORMAT_ARRAY,
        };

        let attempt = 0;
        while (attempt < this.maxRetries) {
            let connection;
            try {
                const pool = oracledb.getPool(this.poolAlias);
                connection = await pool.getConnection();

                const result = await connection.execute(query, binds, execOptions);
                return result.rows ?? result;

            } catch (err) {
                attempt++;
                console.warn(`[OracleConnector] Attempt ${attempt}/${this.maxRetries} failed: ${err.message}`);

                // Retry only on known transient network / failover ORA errors
                const isRetryable =
                    err.message.includes('ORA-03113') ||   // end-of-file on communication channel
                    err.message.includes('ORA-03114') ||   // not connected to Oracle
                    err.message.includes('ORA-12541') ||   // no listener
                    err.message.includes('ORA-12514') ||   // listener: unknown service
                    err.message.includes('ORA-25408');     // cannot safely replay call (AC)

                if (attempt >= this.maxRetries || !isRetryable) {
                    console.error(`[OracleConnector] Fatal query error after ${attempt} attempt(s)`);
                    throw err;
                }

                const delay = this.retryDelayMs * attempt;
                console.log(`[OracleConnector] Retryable — waiting ${delay}ms before attempt ${attempt + 1}`);
                await this._sleep(delay);

            } finally {
                if (connection) {
                    try {
                        await connection.close();
                    } catch (closeErr) {
                        console.error('[OracleConnector] Error releasing connection:', closeErr.message);
                    }
                }
            }
        }
    }
}

module.exports = OracleConnector;