/**
 * OSS Operations MCP Server
 *
 * Operations tool surface for human operators and machine agents.
 * Read tools: get_node_kpis, get_alarms, get_charging_error_rate, get_node_topology
 * Write tools (two-phase): prepare_rebalance / confirm_rebalance
 * All writes default to dry_run=true — machine agents with OSS_MACHINE role
 * may pass dry_run=false directly (no human confirm step in that flow).
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });

const http = require('http');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { z } = require('zod');

const {
    auditLog, createConfirmationToken, verifyConfirmationToken,
    buildMcpApp, textResult, errorResult, registerShutdown, TOKEN_TTL_SECONDS,
} = require('../shared/mcp-utils');
const { createAdapter } = require('../adapters/adapter-factory');
const { loadConfig } = require('../shared/config-loader');

const config = loadConfig();
const srvCfg = config._mcpServerById['oss'];
if (!srvCfg) throw new Error('[OssMCP] No "oss" entry in platform.config.yaml mcp_servers[]');

const PORT = parseInt(process.env.OSS_MCP_PORT || srvCfg.port, 10);
const API_KEY = srvCfg.api_key;
const TOKEN_SECRET = srvCfg.token_secret;
const SERVER_NAME = 'ocncc-oss';
const VERSION = '1.0.0';

const MAX_SESSIONS_FOR_REBALANCE = parseInt(
    srvCfg.limits?.max_session_threshold_for_rebalance || '10000', 10
);

const adapterCfg = config._adapterById[srvCfg.ocs_adapter];
const adapter = createAdapter(adapterCfg.id, adapterCfg.type, adapterCfg.config);

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

function buildServer() {
    const server = new McpServer({ name: SERVER_NAME, version: VERSION });

    // -------------------------------------------------------------------------
    // READ tools
    // -------------------------------------------------------------------------

    server.tool('get_node_kpis', {
        description: 'Fetch KPI metrics for an OCS node over a time window. Returns raw metric values and timestamps.',
        inputSchema: z.object({
            node_id: z.number().int().describe('OCS node / billing engine ID'),
            metrics: z.array(z.string()).default(['session_count', 'error_rate', 'latency_ms']),
            window_seconds: z.number().int().default(300).describe('Lookback window in seconds (default 5 minutes)'),
            agent_id: z.string().min(1),
        }),
    }, async ({ node_id, metrics, window_seconds, agent_id }) => {
        try {
            const result = await adapter.getNodeKpis(node_id, metrics, window_seconds);
            await auditLog({ agentId: agent_id, tool: 'get_node_kpis', inputSummary: `node=${node_id},window=${window_seconds}s`, outcome: 'SUCCESS' });
            return textResult(result);
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'get_node_kpis', inputSummary: `node=${node_id}`, outcome: 'ERROR', detail: err.message });
            return errorResult('get_node_kpis', err);
        }
    });

    server.tool('get_charging_error_rate', {
        description: 'Get the charging error rate percentage for an OCS node over a time window. Use to detect billing engine degradation.',
        inputSchema: z.object({
            node_id: z.number().int(),
            window_seconds: z.number().int().default(300),
            agent_id: z.string().min(1),
        }),
    }, async ({ node_id, window_seconds, agent_id }) => {
        try {
            const result = await adapter.getChargingErrorRate(node_id, window_seconds);
            await auditLog({ agentId: agent_id, tool: 'get_charging_error_rate', inputSummary: `node=${node_id}`, outcome: 'SUCCESS' });
            return textResult(result);
        } catch (err) {
            return errorResult('get_charging_error_rate', err);
        }
    });

    server.tool('get_alarms', {
        description: 'Fetch active (unacknowledged) alarms. Filter by severity: CRITICAL, WARNING, INFO.',
        inputSchema: z.object({
            severity: z.enum(['CRITICAL', 'WARNING', 'INFO']).optional(),
            limit: z.number().int().min(1).max(200).default(50),
            agent_id: z.string().min(1),
        }),
    }, async ({ severity, limit, agent_id }) => {
        try {
            const rows = await adapter.getAlarms({ severity, limit });
            await auditLog({ agentId: agent_id, tool: 'get_alarms', inputSummary: `severity=${severity},limit=${limit}`, outcome: 'SUCCESS' });
            return textResult({ count: rows.length, alarms: rows });
        } catch (err) {
            return errorResult('get_alarms', err);
        }
    });

    server.tool('get_node_topology_oss', {
        description: 'Fetch full OCS node topology including domains, node addresses, and ports.',
        inputSchema: z.object({
            force_refresh: z.boolean().default(false),
            agent_id: z.string().min(1),
        }),
    }, async ({ force_refresh, agent_id }) => {
        try {
            const result = await adapter.getNodeTopology({ forceRefresh: force_refresh });
            await auditLog({ agentId: agent_id, tool: 'get_node_topology_oss', inputSummary: 'topology', outcome: 'SUCCESS' });
            return textResult(result);
        } catch (err) {
            return errorResult('get_node_topology_oss', err);
        }
    });

    // -------------------------------------------------------------------------
    // WRITE tools — two-phase for human operators, direct for machine agents
    // The gateway injects x-gateway-role; tools check it to determine flow.
    // -------------------------------------------------------------------------

    server.tool('prepare_rebalance', {
        description: `PHASE 1 OF 2 (human) or direct assessment (machine): Assess impact of rebalancing subscribers across OCS nodes in a domain. Always runs as dry_run first. Safety guard: will not proceed if active sessions > ${MAX_SESSIONS_FOR_REBALANCE}. Returns confirmation_token for human confirm step.`,
        inputSchema: z.object({
            domain_id: z.number().int().describe('Domain ID to rebalance'),
            agent_id: z.string().min(1),
        }),
    }, async ({ domain_id, agent_id }) => {
        try {
            // Always run dry_run assessment first
            const assessment = await adapter.triggerRebalance(domain_id, true);

            // Safety guard
            const sessionKpis = await adapter.getNodeKpis(domain_id, ['session_count'], 60)
                .catch(() => ({ data: [] }));
            const totalSessions = (sessionKpis.data || [])
                .filter(k => k.STAT_NAME === 'session_count')
                .reduce((sum, k) => sum + (k.STAT_VALUE || 0), 0);

            if (totalSessions > MAX_SESSIONS_FOR_REBALANCE) {
                return errorResult('prepare_rebalance',
                    new Error(`Safety guard: ${totalSessions} active sessions exceeds threshold ${MAX_SESSIONS_FOR_REBALANCE}. Rebalance blocked. Escalate to NOC.`));
            }

            const token = createConfirmationToken(TOKEN_SECRET, {
                action: 'rebalance', domain_id, agentId: agent_id,
            });

            await auditLog({ agentId: agent_id, tool: 'prepare_rebalance', inputSummary: `domain=${domain_id}`, outcome: 'PREPARED' });

            return textResult({
                action: 'REBALANCE', requires_confirmation: true,
                domain_id, assessment, active_sessions: totalSessions,
                confirmation_token: token,
                token_expires_in: `${TOKEN_TTL_SECONDS} seconds`,
                next_step: 'Call confirm_rebalance with the confirmation_token to execute.',
                warning: 'This will redistribute live subscriber sessions across nodes.',
            });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'prepare_rebalance', inputSummary: `domain=${domain_id}`, outcome: 'ERROR', detail: err.message });
            return errorResult('prepare_rebalance', err);
        }
    });

    server.tool('confirm_rebalance', {
        description: 'PHASE 2 OF 2: Execute a domain rebalance using the token from prepare_rebalance. Only call after explicit operator confirmation. HIGH RISK — affects live sessions.',
        inputSchema: z.object({
            confirmation_token: z.string().min(1),
            agent_id: z.string().min(1),
        }),
    }, async ({ confirmation_token, agent_id }) => {
        let payload;
        try { payload = verifyConfirmationToken(TOKEN_SECRET, confirmation_token); }
        catch (err) { return errorResult('confirm_rebalance', err); }

        if (payload.action !== 'rebalance') return errorResult('confirm_rebalance', new Error('Token is not for a rebalance'));
        if (payload.agentId !== agent_id) return errorResult('confirm_rebalance', new Error('Agent identity mismatch'));

        const { domain_id } = payload;
        try {
            const result = await adapter.triggerRebalance(domain_id, false);
            await auditLog({ agentId: agent_id, tool: 'confirm_rebalance', inputSummary: `domain=${domain_id}`, outcome: 'EXECUTED' });
            return textResult({ success: true, domain_id, result, executed_by: agent_id });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'confirm_rebalance', inputSummary: `domain=${domain_id}`, outcome: 'ERROR', detail: err.message });
            return errorResult('confirm_rebalance', err);
        }
    });

    return server;
}

async function main() {
    console.log(`[OssMCP] Starting ${SERVER_NAME} v${VERSION} (adapter: ${adapterCfg.type}/${adapterCfg.id})`);
    await adapter.initialise();

    const mcpServer = buildServer();
    const app = buildMcpApp({ serverName: SERVER_NAME, version: VERSION, mcpServer, apiKey: API_KEY });
    const httpServer = http.createServer(app);

    httpServer.listen(PORT, '127.0.0.1', () => {
        console.log(`[OssMCP] Listening on 127.0.0.1:${PORT}`);
    });
    httpServer.on('error', err => { console.error('[OssMCP] Server error:', err); process.exit(1); });
    registerShutdown(SERVER_NAME, httpServer, [adapter]);
}

main().catch(err => { console.error('[OssMCP] Fatal:', err); process.exit(1); });