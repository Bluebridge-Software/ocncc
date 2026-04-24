/**
 * BSS Analytics MCP Server
 *
 * Read-only analytics tool surface for BSS analysts.
 * Tools: revenue_query, product_performance, arpu_query,
 *        get_subscriber (read-only), get_node_topology, invalidate_cache
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });

const http = require('http');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { z } = require('zod');

const { auditLog, buildMcpApp, textResult, errorResult, registerShutdown } = require('../shared/mcp-utils');
const { createAdapter } = require('../adapters/adapter-factory');
const { loadConfig } = require('../shared/config-loader');

const config = loadConfig();
const srvCfg = config._mcpServerById['bss'];
if (!srvCfg) throw new Error('[BssMCP] No "bss" entry in platform.config.yaml mcp_servers[]');

const PORT = parseInt(process.env.BSS_MCP_PORT || srvCfg.port, 10);
const API_KEY = srvCfg.api_key;
const SERVER_NAME = 'ocncc-bss';
const VERSION = '1.0.0';

const adapterCfg = config._adapterById[srvCfg.ocs_adapter];
const adapter = createAdapter(adapterCfg.id, adapterCfg.type, adapterCfg.config);

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

function buildServer() {
    const server = new McpServer({ name: SERVER_NAME, version: VERSION });

    server.tool('revenue_query', {
        description: 'Query total revenue for a product in a region over a date range. Returns total, event count, and monthly breakdown. All amounts in pence.',
        inputSchema: z.object({
            product: z.string().min(1).describe('Product name, e.g. "Bronze"'),
            region: z.string().min(1).describe('Region name, e.g. "North West"'),
            period_start: z.string().describe('Start date YYYY-MM-DD (inclusive)'),
            period_end: z.string().describe('End date YYYY-MM-DD (exclusive)'),
            agent_id: z.string().min(1),
        }),
    }, async ({ product, region, period_start, period_end, agent_id }) => {
        try {
            const result = await adapter.queryRevenue({ product, region, periodStart: period_start, periodEnd: period_end });
            await auditLog({ agentId: agent_id, tool: 'revenue_query', inputSummary: `product=${product},region=${region},period=${period_start}→${period_end}`, outcome: 'SUCCESS' });
            return textResult(result);
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'revenue_query', inputSummary: `product=${product}`, outcome: 'ERROR', detail: err.message });
            return errorResult('revenue_query', err);
        }
    });

    server.tool('product_performance', {
        description: 'Query performance metrics for a product: unique subscribers, total revenue, event count over a date range.',
        inputSchema: z.object({
            product_id: z.number().int().describe('Product ID'),
            metrics: z.array(z.string()).default(['unique_subscribers', 'total_revenue', 'total_events']),
            period_start: z.string().describe('Start date YYYY-MM-DD'),
            period_end: z.string().describe('End date YYYY-MM-DD'),
            agent_id: z.string().min(1),
        }),
    }, async ({ product_id, metrics, period_start, period_end, agent_id }) => {
        try {
            const result = await adapter.queryProductPerformance({ productId: product_id, metrics, periodStart: period_start, periodEnd: period_end });
            await auditLog({ agentId: agent_id, tool: 'product_performance', inputSummary: `productId=${product_id}`, outcome: 'SUCCESS' });
            return textResult(result);
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'product_performance', inputSummary: `productId=${product_id}`, outcome: 'ERROR', detail: err.message });
            return errorResult('product_performance', err);
        }
    });

    server.tool('arpu_query', {
        description: 'Compute Average Revenue Per User (ARPU) for a subscriber segment over a date range. Returns ARPU in pence and subscriber count.',
        inputSchema: z.object({
            segment: z.string().min(1).describe('Subscriber segment / account type, e.g. "PAYG Standard"'),
            period_start: z.string(),
            period_end: z.string(),
            agent_id: z.string().min(1),
        }),
    }, async ({ segment, period_start, period_end, agent_id }) => {
        try {
            const result = await adapter.queryArpu({ segment, periodStart: period_start, periodEnd: period_end });
            await auditLog({ agentId: agent_id, tool: 'arpu_query', inputSummary: `segment=${segment}`, outcome: 'SUCCESS' });
            return textResult(result);
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'arpu_query', inputSummary: `segment=${segment}`, outcome: 'ERROR', detail: err.message });
            return errorResult('arpu_query', err);
        }
    });

    server.tool('get_subscriber_bss', {
        description: 'Fetch subscriber account details for analytics context (read-only). Returns account type, service state, wallet type.',
        inputSchema: z.object({
            cli: z.string().min(1),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, agent_id }) => {
        try {
            const result = await adapter.getSubscriber(cli, { decodeProfile: false });
            await auditLog({ agentId: agent_id, tool: 'get_subscriber_bss', cli, inputSummary: `cli=${cli}`, outcome: result ? 'SUCCESS' : 'NOT_FOUND' });
            return textResult(result ?? { found: false, cli });
        } catch (err) {
            return errorResult('get_subscriber_bss', err);
        }
    });

    server.tool('get_node_topology_bss', {
        description: 'Fetch OCS node topology for analytics context — domain structure, node addresses.',
        inputSchema: z.object({ agent_id: z.string().min(1) }),
    }, async ({ agent_id }) => {
        try {
            const result = await adapter.getNodeTopology();
            await auditLog({ agentId: agent_id, tool: 'get_node_topology_bss', inputSummary: 'topology', outcome: 'SUCCESS' });
            return textResult(result);
        } catch (err) {
            return errorResult('get_node_topology_bss', err);
        }
    });

    return server;
}

async function main() {
    console.log(`[BssMCP] Starting ${SERVER_NAME} v${VERSION} (adapter: ${adapterCfg.type}/${adapterCfg.id})`);
    await adapter.initialise();

    const mcpServer = buildServer();
    const app = buildMcpApp({ serverName: SERVER_NAME, version: VERSION, mcpServer, apiKey: API_KEY });
    const httpServer = http.createServer(app);

    httpServer.listen(PORT, '127.0.0.1', () => {
        console.log(`[BssMCP] Listening on 127.0.0.1:${PORT}`);
    });
    httpServer.on('error', err => { console.error('[BssMCP] Server error:', err); process.exit(1); });
    registerShutdown(SERVER_NAME, httpServer, [adapter]);
}

main().catch(err => { console.error('[BssMCP] Fatal:', err); process.exit(1); });