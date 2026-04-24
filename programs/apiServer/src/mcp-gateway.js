/**
 * MCP Gateway
 *
 * Single ingress point for all external AI agent traffic.
 * Responsibilities:
 *   1. Validate JWT (or mTLS for machine agents)
 *   2. Extract role from token claims
 *   3. Check role is allowed to reach the requested MCP server (from platform.config.yaml)
 *   4. Proxy the MCP HTTP/SSE request to the target MCP server, injecting caller identity
 *   5. Write a gateway audit record for every proxied request
 *
 * All MCP servers bind to 127.0.0.1 only — this gateway is the sole
 * external-facing process.
 *
 * Port: GATEWAY_PORT env var (default 4001, or platform.config.yaml gateway.port)
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const httpProxy = require('http-proxy');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { loadConfig } = require('./mcp/shared/config-loader');

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

const config = loadConfig();
const GW = config.gateway;
const PORT = parseInt(process.env.GATEWAY_PORT || GW.port, 10);

// ---------------------------------------------------------------------------
// Proxy pool — one proxy instance per upstream MCP server
// ---------------------------------------------------------------------------

const proxies = {};  // mcpServerId → httpProxy instance

function getProxy(mcpServerId) {
    if (!proxies[mcpServerId]) {
        const mcpCfg = config._mcpServerById[mcpServerId];
        proxies[mcpServerId] = httpProxy.createProxyServer({
            target: `http://127.0.0.1:${mcpCfg.port}`,
            ws: true,
            changeOrigin: true,
            timeout: 120_000,
            proxyTimeout: 120_000,
        });
        proxies[mcpServerId].on('error', (err, req, res) => {
            console.error(`[Gateway] Proxy error → ${mcpServerId}:`, err.message);
            if (res && !res.headersSent) {
                res.writeHead(502, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Upstream MCP server unavailable', server: mcpServerId }));
            }
        });
    }
    return proxies[mcpServerId];
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

function issueToken(payload) {
    return jwt.sign(payload, GW.jwt_secret, {
        expiresIn: GW.token_expiry || '8h',
        issuer: 'ocncc-gateway',
        algorithm: 'HS256',
    });
}

function verifyToken(token) {
    return jwt.verify(token, GW.jwt_secret, {
        issuer: 'ocncc-gateway',
        algorithms: ['HS256'],
    });
}

// ---------------------------------------------------------------------------
// mTLS validation helper (OSS_MACHINE role)
// ---------------------------------------------------------------------------

function validateMtlsCert(req) {
    // When terminating TLS at this process (not nginx), the peer cert is available:
    const cert = req.socket?.getPeerCertificate?.();
    if (!cert || !cert.subject) return null;
    // Return a synthetic identity from the cert CN
    return { sub: cert.subject.CN, role: 'OSS_MACHINE', auth_method: 'mtls' };
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

function authenticate(req, res, next) {
    // Skip auth for gateway-internal endpoints
    if (req.path === '/health' || req.path === '/gateway/token') return next();

    // 1. Try mTLS (machine agents)
    const mtlsIdentity = validateMtlsCert(req);
    if (mtlsIdentity) {
        req.identity = mtlsIdentity;
        return next();
    }

    // 2. Try Bearer JWT (human agents via Open WebUI)
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.slice(7);
    try {
        const claims = verifyToken(token);
        if (!claims.role) {
            return res.status(403).json({ error: 'JWT missing role claim' });
        }
        req.identity = {
            sub: claims.sub,
            role: claims.role,
            agent_id: claims.agent_id || claims.sub,
            auth_method: 'jwt',
        };
        next();
    } catch (err) {
        const msg = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
        return res.status(401).json({ error: msg });
    }
}

// ---------------------------------------------------------------------------
// Authorisation middleware
// Checks the role is allowed to reach the target MCP server
// ---------------------------------------------------------------------------

function authorize(req, res, next) {
    if (req.path === '/health' || req.path === '/gateway/token') return next();

    const { role } = req.identity;
    const roleCfg = config._roleById[role];

    if (!roleCfg) {
        console.warn(`[Gateway] Unknown role '${role}' from ${req.identity.sub}`);
        return res.status(403).json({ error: `Unknown role: ${role}` });
    }

    // Target MCP server is encoded in the URL: /mcp/{serverId}/...
    const match = req.path.match(/^\/mcp\/([^/]+)(\/.*)?$/);
    if (!match) {
        return res.status(404).json({ error: 'Invalid MCP path. Expected: /mcp/{serverId}/mcp' });
    }

    const targetServerId = match[1];
    if (!config._mcpServerById[targetServerId]) {
        return res.status(404).json({ error: `Unknown MCP server: ${targetServerId}` });
    }

    if (!roleCfg.allowed_mcp_servers.includes(targetServerId)) {
        console.warn(`[Gateway] Access denied: role=${role} → server=${targetServerId} (sub=${req.identity.sub})`);
        return res.status(403).json({
            error: `Role '${role}' is not authorised to access MCP server '${targetServerId}'`,
        });
    }

    req.targetServerId = targetServerId;
    req.targetPath = match[2] || '/mcp';
    req.roleCfg = roleCfg;
    next();
}

// ---------------------------------------------------------------------------
// Gateway audit
// ---------------------------------------------------------------------------

async function gatewayAudit(req, statusCode) {
    // Lightweight structured log — swap for DB write if required
    console.log(JSON.stringify({
        ts: new Date().toISOString(),
        type: 'gateway_request',
        sub: req.identity?.sub,
        role: req.identity?.role,
        method: req.method,
        target: req.targetServerId,
        path: req.path,
        status: statusCode,
        ip: req.ip,
    }));
}

// ---------------------------------------------------------------------------
// Rate limiter (per gateway key / IP)
// ---------------------------------------------------------------------------

const limiter = rateLimit({
    windowMs: GW.rate_limit?.window_ms || 60_000,
    max: GW.rate_limit?.max_requests || 300,
    keyGenerator: req => req.identity?.sub || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Rate limit exceeded' },
});

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(limiter);

// Request logger
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        if (req.identity) gatewayAudit(req, res.statusCode);
        console.log(`[Gateway] ${req.method} ${req.path} ${res.statusCode} ${Date.now() - start}ms`);
    });
    next();
});

app.use(authenticate);
app.use(authorize);

// ---------------------------------------------------------------------------
// Gateway health
// ---------------------------------------------------------------------------

app.get('/health', (_req, res) => {
    const serverStatuses = Object.keys(config._mcpServerById).map(id => ({
        id, port: config._mcpServerById[id].port, status: 'unknown',
    }));
    res.json({
        status: 'ok', service: 'mcp-gateway', uptime: Math.floor(process.uptime()),
        servers: serverStatuses,
    });
});

// ---------------------------------------------------------------------------
// Token issuance endpoint
// Issues a short-lived JWT for a human agent (internal use / LiteLLM integration)
// In production, replace with your SSO/OIDC provider's token endpoint
// ---------------------------------------------------------------------------

app.post('/gateway/token', express.json(), (req, res) => {
    const { client_id, client_secret, role, agent_id } = req.body || {};

    // Validate client credentials against env-configured secrets
    const expectedSecret = process.env[`CLIENT_SECRET_${(client_id || '').toUpperCase()}`];
    if (!expectedSecret || client_secret !== expectedSecret) {
        return res.status(401).json({ error: 'Invalid client credentials' });
    }

    if (!config._roleById[role]) {
        return res.status(400).json({ error: `Unknown role: ${role}` });
    }

    const token = issueToken({ sub: client_id, role, agent_id: agent_id || client_id });
    res.json({ access_token: token, token_type: 'Bearer', expires_in: 28800 });
});

// ---------------------------------------------------------------------------
// MCP proxy routes — /mcp/{serverId}/mcp (POST + GET)
// ---------------------------------------------------------------------------

app.all('/mcp/:serverId/mcp', (req, res) => {
    const { targetServerId } = req;
    const mcpCfg = config._mcpServerById[targetServerId];

    // Inject caller identity into the proxied request headers
    // MCP servers can read these to populate audit logs without re-validating auth
    req.headers['x-gateway-agent-id'] = req.identity.agent_id || req.identity.sub;
    req.headers['x-gateway-role'] = req.identity.role;
    req.headers['x-gateway-sub'] = req.identity.sub;

    // Replace the incoming gateway Bearer token with the MCP server's own key
    // so the upstream server's auth middleware passes
    req.headers['authorization'] = `Bearer ${mcpCfg.api_key}`;

    // Rewrite path: /mcp/{serverId}/mcp → /mcp
    req.url = '/mcp';

    getProxy(targetServerId).web(req, res);
});

// Catch-all for /mcp/* with wrong suffix
app.use('/mcp', (req, res) => {
    res.status(404).json({ error: 'Expected path: /mcp/{serverId}/mcp' });
});

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const httpServer = http.createServer(app);

httpServer.listen(PORT, () => {
    console.log(`[Gateway] MCP Gateway listening on port ${PORT}`);
    console.log(`[Gateway] Routing to MCP servers: ${Object.keys(config._mcpServerById).join(', ')}`);
    console.log(`[Gateway] Roles defined: ${Object.keys(config._roleById).join(', ')}`);
    console.log(`[Gateway] Token endpoint: POST http://localhost:${PORT}/gateway/token`);
});

httpServer.on('error', err => { console.error('[Gateway] Server error:', err); process.exit(1); });

// Graceful shutdown
async function shutdown(signal) {
    console.log(`\n[Gateway] ${signal} — shutting down`);
    httpServer.close();
    process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', err => { console.error('[Gateway] Uncaught:', err); shutdown('uncaughtException'); });
process.on('unhandledRejection', r => { console.error('[Gateway] Rejection:', r); shutdown('unhandledRejection'); });