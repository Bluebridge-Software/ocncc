/**
 * PM2 Ecosystem Configuration — OCNCC Telco AI Platform
 *
 * Manages all platform processes:
 *   ocncc-api        — existing REST API (unchanged)
 *   mcp-gateway      — single external-facing MCP ingress (:4001)
 *   mcp-care         — Customer Care MCP server (:3101, localhost only)
 *   mcp-bss          — BSS Analytics MCP server (:3102, localhost only)
 *   mcp-oss          — OSS Operations MCP server (:3103, localhost only)
 *
 * Usage:
 *   pm2 start ecosystem.config.js              # start all
 *   pm2 start ecosystem.config.js --only mcp-gateway
 *   pm2 stop all / pm2 restart all
 *   pm2 logs mcp-care
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const BASE_DIR = '/opt/ocncc/apiServer';   // ← adjust to your deployment path

const COMMON = {
    cwd: BASE_DIR,
    watch: false,
    autorestart: true,
    restart_delay: 3000,
    env: {
        NODE_ENV: 'production',
    },
};

module.exports = {
    apps: [

        // -----------------------------------------------------------------------
        // Existing REST API — unchanged
        // -----------------------------------------------------------------------
        {
            ...COMMON,
            name: 'ocncc-api',
            script: 'src/server.js',
            max_memory_restart: '512M',
        },

        // -----------------------------------------------------------------------
        // MCP Gateway — single external-facing process
        // Binds to 0.0.0.0:4001 (or GATEWAY_PORT)
        // -----------------------------------------------------------------------
        {
            ...COMMON,
            name: 'mcp-gateway',
            script: 'src/mcp-gateway.js',
            max_memory_restart: '256M',
            // Gateway must start after MCP servers are up
            // PM2 does not natively support start ordering — use wait_ready + listen_timeout
            wait_ready: true,
            listen_timeout: 15000,
        },

        // -----------------------------------------------------------------------
        // MCP Servers — bind to 127.0.0.1 only (not accessible externally)
        // -----------------------------------------------------------------------
        {
            ...COMMON,
            name: 'mcp-care',
            script: 'src/mcp/servers/care-mcp-server.js',
            max_memory_restart: '256M',
        },
        {
            ...COMMON,
            name: 'mcp-bss',
            script: 'src/mcp/servers/bss-mcp-server.js',
            max_memory_restart: '256M',
        },
        {
            ...COMMON,
            name: 'mcp-oss',
            script: 'src/mcp/servers/oss-mcp-server.js',
            max_memory_restart: '256M',
        },

    ],
};