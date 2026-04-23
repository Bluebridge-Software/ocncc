/**
 * OCNCC MCP Server — HTTP/SSE Transport
 *
 * Exposes the Oracle OCNCC database query layer as a persistent MCP service,
 * allowing external AI agents (Claude Code, Antigravity, custom tooling) to
 * query subscriber records, profile tag definitions, and VWS node topology
 * over a network connection.
 *
 * Transport : HTTP + Server-Sent Events (MCP StreamableHTTP spec)
 * Auth      : Bearer token (MCP_API_KEY env var)
 * Port      : MCP_PORT env var (default 3100)
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const http = require('http');
const crypto = require('crypto');
const express = require('express');

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');

const OracleConnector = require('./database/oracle-connector');
const getRedisClient = require('./services/redis-client.js');
const {
    getProfileTags,
    getSubscriberByCli,
    getVWSNodes,
    invalidateProfileTagsCache,
    invalidateSubscriberCache,
} = require('./database/database-queries');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.MCP_PORT || '3100', 10);
const API_KEY = process.env.MCP_API_KEY;
const SERVER_NAME = 'ocncc-oracle';
const VERSION = '1.0.0';

// Shutdown drain timeout for Oracle pool (seconds)
const POOL_DRAIN_TIMEOUT = 10;

// ---------------------------------------------------------------------------
// Validate required environment at startup — fail fast, fail loud
// ---------------------------------------------------------------------------

function validateEnv() {
    const required = ['ORACLE_USER', 'ORACLE_PASSWORD', 'ORACLE_SMF_SERVICE', 'MCP_API_KEY'];
    const missing = required.filter(k => !process.env[k]);
    if (missing.length) {
        console.error(`[MCP] FATAL: Missing required environment variables: ${missing.join(', ')}`);
        process.exit(1);
    }
}

// ---------------------------------------------------------------------------
// Dependency singletons
// ---------------------------------------------------------------------------

const db = new OracleConnector();
let redis = null;
let profileParser = null;

// profileParser is optional — decoded profiles degrade gracefully without it
async function loadProfileParser() {
    try {
        const { BbsProfileBlock } = require('./codec/BbsProfileBlock');
        profileParser = new BbsProfileBlock();
        console.log('[MCP] BbsProfileBlock loaded');
    } catch {
        console.warn('[MCP] BbsProfileBlock not found — decode_profile will be unavailable');
    }
}

async function loadProfileTagMeta() {
    if (!profileParser || typeof profileParser.loadTagMeta !== 'function') return;
    try {
        const tags = await getProfileTags(db, redis);
        profileParser.loadTagMeta(tags.data);
        console.log(`[MCP] Profile tag metadata loaded: ${tags.count} tags`);
    } catch (err) {
        console.warn('[MCP] Failed to load profile tag metadata:', err.message);
    }
}

// ---------------------------------------------------------------------------
// MCP Server + Tool definitions
// ---------------------------------------------------------------------------

function buildMcpServer() {
    const server = new McpServer({ name: SERVER_NAME, version: VERSION });

    // -------------------------------------------------------------------------
    // Tool: get_profile_tags
    // -------------------------------------------------------------------------
    server.tool(
        'get_profile_tags',
        {
            description: [
                'Fetch all OCNCC profile tag definitions from ACS_PROFILE_DETAILS.',
                'Returns a flat list (data[]) and a hierarchical tree (tree[]).',
                'Each tag: tagId (hex), name, type (INT|BOOL|STR|…),',
                'parentTagId, isInputParameter, children[].',
                'Results are Redis-cached for 1 hour.',
                'Use force_refresh=true to bypass cache.',
            ].join(' '),
            inputSchema: z.object({
                force_refresh: z.boolean().optional().default(false)
                    .describe('Bypass Redis cache and re-read from Oracle'),
            }),
        },
        async ({ force_refresh }) => {
            try {
                const result = await getProfileTags(db, redis, { forceRefresh: force_refresh });
                return textResult(result);
            } catch (err) {
                return errorResult('get_profile_tags', err);
            }
        }
    );

    // -------------------------------------------------------------------------
    // Tool: get_subscriber
    // -------------------------------------------------------------------------
    server.tool(
        'get_subscriber',
        {
            description: [
                'Fetch a subscriber from CCS_ACCT_REFERENCE by CLI (phone number).',
                'Returns: id, cli, service_state, wallet_type, wallet_id,',
                'billing_engine_id, account_type, customer_name, profile (base64).',
                'Set decode_profile=true to include decodedProfile with friendly',
                'ESCHER tag names and values (requires BbsProfileBlock).',
                'Results are Redis-cached for 30 seconds.',
            ].join(' '),
            inputSchema: z.object({
                cli: z.string().min(1)
                    .describe('Subscriber CLI (phone number), e.g. "447700900123"'),
                force_refresh: z.boolean().optional().default(false)
                    .describe('Bypass Redis cache and re-read from Oracle'),
                decode_profile: z.boolean().optional().default(false)
                    .describe('Decode the ESCHER profile blob into friendly tag names/values'),
            }),
        },
        async ({ cli, force_refresh, decode_profile }) => {
            try {
                const result = await getSubscriberByCli(db, redis, cli, {
                    forceRefresh: force_refresh,
                    decodeProfile: decode_profile,
                    profileParser,
                });
                return textResult(result);
            } catch (err) {
                return errorResult('get_subscriber', err);
            }
        }
    );

    // -------------------------------------------------------------------------
    // Tool: get_vws_nodes
    // -------------------------------------------------------------------------
    server.tool(
        'get_vws_nodes',
        {
            description: [
                'Fetch all VWS (OCS billing engine) nodes from CCS_DOMAIN_*.',
                'Returns nodes grouped by domain_id, each with: node_number,',
                'name, comm_address (IP), client_port.',
                'Use this to inspect which billing engines are registered and',
                'their ESCHER connection endpoints.',
                'Results are Redis-cached for 5 minutes.',
            ].join(' '),
            inputSchema: z.object({
                force_refresh: z.boolean().optional().default(false)
                    .describe('Bypass Redis cache and re-read from Oracle'),
            }),
        },
        async ({ force_refresh }) => {
            try {
                const result = await getVWSNodes(db, redis, { forceRefresh: force_refresh });
                return textResult(result);
            } catch (err) {
                return errorResult('get_vws_nodes', err);
            }
        }
    );

    // -------------------------------------------------------------------------
    // Tool: invalidate_cache
    // -------------------------------------------------------------------------
    server.tool(
        'invalidate_cache',
        {
            description: [
                'Invalidate Redis cache to force a fresh Oracle read.',
                'target="profile_tags" clears the ACS tag definition cache.',
                'target="subscriber" (+ cli) clears a specific subscriber.',
                'target="all" clears profile_tags and all subscriber entries.',
            ].join(' '),
            inputSchema: z.object({
                target: z.enum(['profile_tags', 'subscriber', 'all'])
                    .describe('Which cache to invalidate'),
                cli: z.string().optional()
                    .describe('Required when target="subscriber"'),
            }),
        },
        async ({ target, cli }) => {
            try {
                const actions = [];

                if (target === 'profile_tags' || target === 'all') {
                    await invalidateProfileTagsCache(redis);
                    actions.push('profile_tags cache cleared');
                }

                if (target === 'subscriber' || target === 'all') {
                    if (target === 'subscriber' && !cli) {
                        return errorResult('invalidate_cache',
                            new Error('cli is required when target="subscriber"'));
                    }
                    if (cli) {
                        await invalidateSubscriberCache(redis, cli);
                        actions.push(`subscriber cache cleared for CLI ${cli}`);
                    }
                }

                return textResult({ success: true, actions });
            } catch (err) {
                return errorResult('invalidate_cache', err);
            }
        }
    );

    return server;
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function textResult(data) {
    return {
        content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
    };
}

function errorResult(toolName, err) {
    console.error(`[MCP] Tool error [${toolName}]:`, err.message);
    return {
        content: [{
            type: 'text',
            text: JSON.stringify({
                error: err.message,
                tool: toolName,
                oraCode: err.message.match(/ORA-\d+/)?.[0] ?? null,
            }),
        }],
        isError: true,
    };
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

function bearerAuth(req, res, next) {
    // Health probe — no auth required
    if (req.path === '/health') return next();

    const authHeader = req.headers['authorization'] ?? '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

    // Constant-time comparison to prevent timing attacks
    const expected = Buffer.from(API_KEY);
    const received = Buffer.from(token);

    if (
        received.length !== expected.length ||
        !crypto.timingSafeEqual(expected, received)
    ) {
        console.warn(`[MCP] Unauthorised request from ${req.ip} — ${req.method} ${req.path}`);
        return res.status(401).json({ error: 'Unauthorised' });
    }

    next();
}

// ---------------------------------------------------------------------------
// Request logging middleware
// ---------------------------------------------------------------------------

function requestLogger(req, res, next) {
    const start = Date.now();
    res.on('finish', () => {
        const ms = Date.now() - start;
        console.log(`[MCP] ${req.method} ${req.path} ${res.statusCode} ${ms}ms — ${req.ip}`);
    });
    next();
}

// ---------------------------------------------------------------------------
// Express app + MCP routes
// ---------------------------------------------------------------------------

function buildApp(mcpServer) {
    const app = express();

    app.disable('x-powered-by');
    app.use(express.json({ limit: '1mb' }));
    app.use(requestLogger);
    app.use(bearerAuth);

    // Health endpoint — used by PM2, load balancers, monitoring
    app.get('/health', (_req, res) => {
        res.json({
            status: 'ok',
            service: SERVER_NAME,
            version: VERSION,
            uptime: Math.floor(process.uptime()),
        });
    });

    // MCP POST — client-to-server messages (tool calls, initialise, etc.)
    app.post('/mcp', async (req, res) => {
        try {
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => crypto.randomUUID(),
            });
            await mcpServer.connect(transport);
            await transport.handleRequest(req, res, req.body);
        } catch (err) {
            console.error('[MCP] POST handler error:', err.message);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Internal server error' });
            }
        }
    });

    // MCP GET — server-to-client SSE stream (server-initiated notifications)
    app.get('/mcp', async (req, res) => {
        try {
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => crypto.randomUUID(),
            });
            await mcpServer.connect(transport);
            await transport.handleRequest(req, res);
        } catch (err) {
            console.error('[MCP] SSE handler error:', err.message);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Internal server error' });
            }
        }
    });

    // 404 catch-all
    app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

    return app;
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

let httpServer = null;

async function shutdown(signal) {
    console.log(`\n[MCP] ${signal} received — shutting down gracefully`);

    // Stop accepting new connections
    if (httpServer) {
        httpServer.close(() => console.log('[MCP] HTTP server closed'));
    }

    // Drain Oracle pool
    try {
        await db.close(POOL_DRAIN_TIMEOUT);
    } catch (err) {
        console.error('[MCP] Error during pool close:', err.message);
    }

    console.log('[MCP] Shutdown complete');
    process.exit(0);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main() {
    validateEnv();

    console.log(`[MCP] Starting ${SERVER_NAME} v${VERSION}`);

    // Initialise Oracle connection pool
    await db.initialise();
    await db.testConnection();

    // Initialise Redis (optional — queries degrade gracefully)
    try {
        redis = await getRedisClient();
        console.log('[MCP] Redis connected');
    } catch {
        console.warn('[MCP] Redis unavailable — query caching disabled');
        redis = null;
    }

    // Load profile parser and tag metadata
    await loadProfileParser();
    await loadProfileTagMeta();

    // Build MCP server and Express app
    const mcpServer = buildMcpServer();
    const app = buildApp(mcpServer);

    // Start HTTP server
    httpServer = http.createServer(app);

    httpServer.listen(PORT, () => {
        console.log(`[MCP] ${SERVER_NAME} listening on port ${PORT}`);
        console.log(`[MCP] Health: http://localhost:${PORT}/health`);
        console.log(`[MCP] MCP endpoint: http://localhost:${PORT}/mcp`);
    });

    httpServer.on('error', err => {
        console.error('[MCP] HTTP server error:', err.message);
        process.exit(1);
    });

    // Graceful shutdown handlers
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('uncaughtException', err => {
        console.error('[MCP] Uncaught exception:', err);
        shutdown('uncaughtException');
    });
    process.on('unhandledRejection', (reason) => {
        console.error('[MCP] Unhandled rejection:', reason);
        shutdown('unhandledRejection');
    });
}

main().catch(err => {
    console.error('[MCP] Fatal startup error:', err);
    process.exit(1);
});