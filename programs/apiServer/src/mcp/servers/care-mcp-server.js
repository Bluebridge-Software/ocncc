/**
 * Customer Care MCP Server
 *
 * OCS-agnostic care tool surface — all OCS operations delegated to the
 * injected adapter (OcnccAdapter, MatrixxAdapter, BrmAdapter, MockAdapter).
 * Adapter is resolved from platform.config.yaml at startup.
 *
 * Tools: get_subscriber, get_balance, get_transaction_history, get_topup_history,
 *        get_active_services, get_billing_engine,
 *        prepare_balance_adjustment / confirm_balance_adjustment,
 *        prepare_service_state_change / confirm_service_state_change,
 *        raise_ticket, invalidate_cache
 *
 * Started by platform-runner.js — not directly.
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

// ---------------------------------------------------------------------------
// Resolve config for this MCP server (id: 'care')
// ---------------------------------------------------------------------------

const config = loadConfig();
const srvCfg = config._mcpServerById['care'];
if (!srvCfg) throw new Error('[CareMCP] No "care" entry found in platform.config.yaml mcp_servers[]');

const PORT = parseInt(process.env.CARE_MCP_PORT || srvCfg.port, 10);
const API_KEY = srvCfg.api_key;
const TOKEN_SECRET = srvCfg.token_secret;
const MAX_CREDIT = parseFloat(srvCfg.limits?.max_credit_gbp || 50);
const MAX_DEBIT = parseFloat(srvCfg.limits?.max_debit_gbp || 50);
const SERVER_NAME = 'ocncc-care';
const VERSION = '1.0.0';

if (!API_KEY || !TOKEN_SECRET) {
    console.error('[CareMCP] FATAL: api_key and token_secret must be set in platform.config.yaml / env');
    process.exit(1);
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

const adapterCfg = config._adapterById[srvCfg.ocs_adapter];
if (!adapterCfg) throw new Error(`[CareMCP] OCS adapter '${srvCfg.ocs_adapter}' not found in config`);
const adapter = createAdapter(adapterCfg.id, adapterCfg.type, adapterCfg.config);

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

function buildServer() {
    const server = new McpServer({ name: SERVER_NAME, version: VERSION });

    // -------------------------------------------------------------------------
    // READ tools
    // -------------------------------------------------------------------------

    server.tool('get_subscriber', {
        description: 'Fetch full subscriber record by CLI including decoded service profile. Use as the first step for any customer enquiry.',
        inputSchema: z.object({
            cli: z.string().min(1).describe('Phone number e.g. "447700900123"'),
            agent_id: z.string().min(1).describe('Care agent SSO identity'),
        }),
    }, async ({ cli, agent_id }) => {
        try {
            const result = await adapter.getSubscriber(cli, { decodeProfile: true });
            await auditLog({ agentId: agent_id, tool: 'get_subscriber', cli, inputSummary: `cli=${cli}`, outcome: result ? 'SUCCESS' : 'NOT_FOUND' });
            return textResult(result ?? { found: false, cli });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'get_subscriber', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('get_subscriber', err);
        }
    });

    server.tool('get_balance', {
        description: 'Fetch current balance, credit limit, currency, expiry, and last top-up. Use when a customer queries their balance or a recent top-up.',
        inputSchema: z.object({
            cli: z.string().min(1),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, agent_id }) => {
        try {
            const result = await adapter.getBalance(cli);
            await auditLog({ agentId: agent_id, tool: 'get_balance', cli, inputSummary: `cli=${cli}`, outcome: result ? 'SUCCESS' : 'NOT_FOUND' });
            return textResult(result ?? { found: false, cli });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'get_balance', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('get_balance', err);
        }
    });

    server.tool('get_transaction_history', {
        description: 'Fetch charges, credits, and events within the last N days (max 90). Use to investigate billing disputes or unexpected charges. Returns up to 100 events.',
        inputSchema: z.object({
            cli: z.string().min(1),
            days: z.number().int().min(1).max(90).default(7),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, days, agent_id }) => {
        try {
            const rows = await adapter.getTransactionHistory(cli, days);
            await auditLog({ agentId: agent_id, tool: 'get_transaction_history', cli, inputSummary: `cli=${cli},days=${days}`, outcome: 'SUCCESS' });
            return textResult({ cli, days, count: rows.length, transactions: rows });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'get_transaction_history', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('get_transaction_history', err);
        }
    });

    server.tool('get_topup_history', {
        description: 'Fetch top-up records within the last N days (max 90). Use specifically when a customer reports a top-up not credited.',
        inputSchema: z.object({
            cli: z.string().min(1),
            days: z.number().int().min(1).max(90).default(30),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, days, agent_id }) => {
        try {
            const rows = await adapter.getTopupHistory(cli, days);
            await auditLog({ agentId: agent_id, tool: 'get_topup_history', cli, inputSummary: `cli=${cli},days=${days}`, outcome: 'SUCCESS' });
            return textResult({ cli, days, count: rows.length, topups: rows });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'get_topup_history', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('get_topup_history', err);
        }
    });

    server.tool('get_active_services', {
        description: 'Fetch decoded service flags, account type, and service state. Use to check which services are enabled or suspended.',
        inputSchema: z.object({
            cli: z.string().min(1),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, agent_id }) => {
        try {
            const result = await adapter.getActiveServices(cli);
            await auditLog({ agentId: agent_id, tool: 'get_active_services', cli, inputSummary: `cli=${cli}`, outcome: result ? 'SUCCESS' : 'NOT_FOUND' });
            return textResult(result ?? { found: false, cli });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'get_active_services', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('get_active_services', err);
        }
    });

    server.tool('get_billing_engine', {
        description: 'Return which OCS node the subscriber is assigned to, with its domain, IP, and port. Use for escalation or to diagnose engine-related faults.',
        inputSchema: z.object({
            cli: z.string().min(1),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, agent_id }) => {
        try {
            const sub = await adapter.getSubscriber(cli, {});
            if (!sub) return textResult({ found: false, cli });
            const topology = await adapter.getNodeTopology();
            let assignedNode = null, assignedDomain = null;
            for (const [domainId, nodes] of Object.entries(topology)) {
                const match = nodes.find(n => n.nodeNumber === sub.billing_engine_id);
                if (match) { assignedNode = match; assignedDomain = domainId; break; }
            }
            await auditLog({ agentId: agent_id, tool: 'get_billing_engine', cli, inputSummary: `cli=${cli}`, outcome: 'SUCCESS' });
            return textResult({ cli, billing_engine_id: sub.billing_engine_id, domain_id: assignedDomain, node: assignedNode });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'get_billing_engine', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('get_billing_engine', err);
        }
    });

    // -------------------------------------------------------------------------
    // WRITE tools — two-phase
    // -------------------------------------------------------------------------

    server.tool('prepare_balance_adjustment', {
        description: `PHASE 1 OF 2: Validate a proposed balance adjustment and return a confirmation token. Present the summary to the agent for approval. Max credit: £${MAX_CREDIT}. Max debit: £${MAX_DEBIT}. Token valid for ${TOKEN_TTL_SECONDS}s.`,
        inputSchema: z.object({
            cli: z.string().min(1),
            amount_gbp: z.number().describe('Positive = credit, negative = debit'),
            reason: z.string().min(5).max(200),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, amount_gbp, reason, agent_id }) => {
        try {
            if (amount_gbp > MAX_CREDIT) return errorResult('prepare_balance_adjustment', new Error(`Credit £${amount_gbp} exceeds maximum £${MAX_CREDIT}. Escalate to supervisor.`));
            if (amount_gbp < -MAX_DEBIT) return errorResult('prepare_balance_adjustment', new Error(`Debit £${Math.abs(amount_gbp)} exceeds maximum £${MAX_DEBIT}. Escalate to supervisor.`));

            const sub = await adapter.getSubscriber(cli, {});
            if (!sub) return errorResult('prepare_balance_adjustment', new Error(`Subscriber not found: ${cli}`));
            const balance = await adapter.getBalance(cli);

            const amountPence = Math.round(amount_gbp * 100);
            const currentBalGbp = balance ? (balance.BALANCE / 100).toFixed(2) : 'unknown';
            const projectedGbp = balance ? ((balance.BALANCE + amountPence) / 100).toFixed(2) : 'unknown';

            const token = createConfirmationToken(TOKEN_SECRET, {
                action: 'balance_adjustment', cli, amountPence, reason, agentId: agent_id,
            });

            await auditLog({ agentId: agent_id, tool: 'prepare_balance_adjustment', cli, inputSummary: `cli=${cli},amount=${amount_gbp},reason=${reason}`, outcome: 'PREPARED' });

            return textResult({
                action: 'BALANCE_ADJUSTMENT', requires_confirmation: true,
                cli, customer_name: sub.customer_name,
                direction: amount_gbp >= 0 ? 'CREDIT' : 'DEBIT',
                amount_gbp: Math.abs(amount_gbp).toFixed(2),
                reason, current_balance_gbp: currentBalGbp, projected_balance_gbp: projectedGbp,
                agent_id, token_expires_in: `${TOKEN_TTL_SECONDS} seconds`,
                confirmation_token: token,
                next_step: 'Call confirm_balance_adjustment with the confirmation_token to execute.',
            });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'prepare_balance_adjustment', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('prepare_balance_adjustment', err);
        }
    });

    server.tool('confirm_balance_adjustment', {
        description: 'PHASE 2 OF 2: Execute a balance adjustment using the token from prepare_balance_adjustment. Only call after the agent has explicitly confirmed.',
        inputSchema: z.object({
            confirmation_token: z.string().min(1),
            agent_id: z.string().min(1),
        }),
    }, async ({ confirmation_token, agent_id }) => {
        let payload;
        try { payload = verifyConfirmationToken(TOKEN_SECRET, confirmation_token); }
        catch (err) { return errorResult('confirm_balance_adjustment', err); }

        if (payload.action !== 'balance_adjustment') return errorResult('confirm_balance_adjustment', new Error('Token is not for a balance adjustment'));
        if (payload.agentId !== agent_id) return errorResult('confirm_balance_adjustment', new Error('Agent identity mismatch'));

        const { cli, amountPence, reason } = payload;
        try {
            await adapter.applyBalanceAdjustment(cli, amountPence, reason, agent_id);
            await auditLog({ agentId: agent_id, tool: 'confirm_balance_adjustment', cli, inputSummary: `cli=${cli},pence=${amountPence}`, outcome: 'EXECUTED' });
            return textResult({ success: true, cli, amount_pence_applied: amountPence, reason, applied_by: agent_id, message: `Balance adjustment of ${amountPence > 0 ? '+' : ''}${(amountPence / 100).toFixed(2)} GBP applied to ${cli}.` });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'confirm_balance_adjustment', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('confirm_balance_adjustment', err);
        }
    });

    server.tool('prepare_service_state_change', {
        description: 'PHASE 1 OF 2: Validate a service state change and return a confirmation token. States: A=Active, S=Suspended, B=Barred, T=Terminated.',
        inputSchema: z.object({
            cli: z.string().min(1),
            new_state: z.enum(['A', 'S', 'B', 'T']),
            reason: z.string().min(5).max(200),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, new_state, reason, agent_id }) => {
        const STATE_LABELS = { A: 'Active', S: 'Suspended', B: 'Barred', T: 'Terminated' };
        try {
            const sub = await adapter.getSubscriber(cli, {});
            if (!sub) return errorResult('prepare_service_state_change', new Error(`Subscriber not found: ${cli}`));
            if (sub.service_state === new_state) return errorResult('prepare_service_state_change', new Error(`Already in state ${new_state}`));

            const token = createConfirmationToken(TOKEN_SECRET, {
                action: 'service_state_change', cli, new_state, reason, agentId: agent_id,
            });

            await auditLog({ agentId: agent_id, tool: 'prepare_service_state_change', cli, inputSummary: `cli=${cli},state=${sub.service_state}->${new_state}`, outcome: 'PREPARED' });

            return textResult({
                action: 'SERVICE_STATE_CHANGE', requires_confirmation: true,
                cli, customer_name: sub.customer_name,
                current_state: `${sub.service_state} (${STATE_LABELS[sub.service_state] ?? sub.service_state})`,
                new_state: `${new_state} (${STATE_LABELS[new_state]})`,
                reason, agent_id, token_expires_in: `${TOKEN_TTL_SECONDS} seconds`,
                confirmation_token: token,
                next_step: 'Call confirm_service_state_change with the confirmation_token to execute.',
            });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'prepare_service_state_change', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('prepare_service_state_change', err);
        }
    });

    server.tool('confirm_service_state_change', {
        description: 'PHASE 2 OF 2: Execute a service state change using the token from prepare_service_state_change. Only call after agent confirmation.',
        inputSchema: z.object({
            confirmation_token: z.string().min(1),
            agent_id: z.string().min(1),
        }),
    }, async ({ confirmation_token, agent_id }) => {
        let payload;
        try { payload = verifyConfirmationToken(TOKEN_SECRET, confirmation_token); }
        catch (err) { return errorResult('confirm_service_state_change', err); }

        if (payload.action !== 'service_state_change') return errorResult('confirm_service_state_change', new Error('Token is not for a service state change'));
        if (payload.agentId !== agent_id) return errorResult('confirm_service_state_change', new Error('Agent identity mismatch'));

        const { cli, new_state, reason } = payload;
        try {
            await adapter.applyServiceStateChange(cli, new_state, reason, agent_id);
            await auditLog({ agentId: agent_id, tool: 'confirm_service_state_change', cli, inputSummary: `cli=${cli},state=${new_state}`, outcome: 'EXECUTED' });
            return textResult({ success: true, cli, new_state, reason, applied_by: agent_id, message: `Service state for ${cli} changed to ${new_state}.` });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'confirm_service_state_change', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('confirm_service_state_change', err);
        }
    });

    server.tool('raise_ticket', {
        description: 'Raise a customer care ticket. Categories: BILLING, TECHNICAL, ACCOUNT, COMPLAINT, TOPUP, OTHER.',
        inputSchema: z.object({
            cli: z.string().min(1),
            category: z.enum(['BILLING', 'TECHNICAL', 'ACCOUNT', 'COMPLAINT', 'TOPUP', 'OTHER']),
            priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
            notes: z.string().min(10).max(2000),
            agent_id: z.string().min(1),
        }),
    }, async ({ cli, category, priority, notes, agent_id }) => {
        try {
            const { ticketId } = await adapter.raiseTicket(cli, category, priority, notes, agent_id);
            await auditLog({ agentId: agent_id, tool: 'raise_ticket', cli, inputSummary: `cli=${cli},cat=${category},pri=${priority}`, outcome: 'EXECUTED', detail: `ticket_id=${ticketId}` });
            return textResult({ success: true, ticket_id: ticketId, cli, category, priority, status: 'OPEN' });
        } catch (err) {
            await auditLog({ agentId: agent_id, tool: 'raise_ticket', cli, inputSummary: `cli=${cli}`, outcome: 'ERROR', detail: err.message });
            return errorResult('raise_ticket', err);
        }
    });

    server.tool('invalidate_cache', {
        description: 'Invalidate cached subscriber or reference data to force a fresh OCS read.',
        inputSchema: z.object({
            target: z.enum(['subscriber', 'reference', 'all']),
            cli: z.string().optional().describe('Required when target=subscriber'),
            agent_id: z.string().min(1),
        }),
    }, async ({ target, cli, agent_id }) => {
        try {
            const actions = [];
            if ((target === 'subscriber' || target === 'all') && cli) {
                await adapter.invalidateSubscriberCache(cli);
                actions.push(`subscriber cache cleared for ${cli}`);
            }
            if (target === 'reference' || target === 'all') {
                await adapter.invalidateReferenceCache();
                actions.push('reference data cache cleared');
            }
            await auditLog({ agentId: agent_id, tool: 'invalidate_cache', cli: cli || null, inputSummary: `target=${target}`, outcome: 'SUCCESS' });
            return textResult({ success: true, actions });
        } catch (err) {
            return errorResult('invalidate_cache', err);
        }
    });

    return server;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
    console.log(`[CareMCP] Starting ${SERVER_NAME} v${VERSION} (adapter: ${adapterCfg.type}/${adapterCfg.id})`);
    await adapter.initialise();

    const mcpServer = buildServer();
    const app = buildMcpApp({ serverName: SERVER_NAME, version: VERSION, mcpServer, apiKey: API_KEY });
    const httpServer = http.createServer(app);

    httpServer.listen(PORT, '127.0.0.1', () => {
        console.log(`[CareMCP] Listening on 127.0.0.1:${PORT} (gateway-accessible only)`);
    });

    httpServer.on('error', err => { console.error('[CareMCP] Server error:', err); process.exit(1); });
    registerShutdown(SERVER_NAME, httpServer, [adapter]);
}

main().catch(err => { console.error('[CareMCP] Fatal:', err); process.exit(1); });