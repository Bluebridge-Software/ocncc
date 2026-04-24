/**
 * Matrixx OCS Adapter
 *
 * Implements OcsAdapterInterface for Matrixx Digital Commerce.
 * Matrixx exposes a REST/JSON API — all operations are HTTP calls
 * against the Matrixx Operations API (MAPI).
 *
 * Implementation status: STUB — interface-compliant skeleton.
 * Replace TODO blocks with real Matrixx MAPI calls.
 * Matrixx MAPI reference: https://docs.matrixx.com/mapi
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const { OcsAdapterInterface } = require('./ocs-adapter-interface');

class MatrixxAdapter extends OcsAdapterInterface {

    constructor(id, config) {
        super();
        this._id = id;
        this._config = config;
        this._client = null;   // will hold an axios instance or fetch wrapper
        this._initialised = false;
    }

    get type() { return 'matrixx'; }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    async initialise() {
        if (this._initialised) return;

        const { base_url, api_key, timeout_ms = 10000 } = this._config;
        if (!base_url || !api_key) {
            throw new Error(`[MatrixxAdapter:${this._id}] base_url and api_key are required`);
        }

        // TODO: initialise axios/fetch client with base_url + auth header
        // this._client = axios.create({
        //     baseURL: base_url,
        //     timeout: timeout_ms,
        //     headers: { 'X-API-Key': api_key, 'Content-Type': 'application/json' },
        // });

        this._baseUrl = base_url;
        this._apiKey = api_key;
        this._timeout = timeout_ms;

        // Probe connectivity
        const health = await this.healthCheck();
        if (!health.ok) {
            throw new Error(`[MatrixxAdapter:${this._id}] Health check failed: ${health.detail}`);
        }

        this._initialised = true;
        console.log(`[MatrixxAdapter:${this._id}] Initialised — ${base_url}`);
    }

    async shutdown() {
        this._initialised = false;
        console.log(`[MatrixxAdapter:${this._id}] Shutdown`);
    }

    async healthCheck() {
        const start = Date.now();
        try {
            // TODO: GET /health or equivalent Matrixx probe endpoint
            // await this._client.get('/api/1.0/health');
            throw new Error('MatrixxAdapter health check not yet implemented');
        } catch (err) {
            return { ok: false, latencyMs: Date.now() - start, detail: err.message };
        }
    }

    // -------------------------------------------------------------------------
    // Internal HTTP helper (replace with real implementation)
    // -------------------------------------------------------------------------

    async _mapiGet(path, params = {}) {
        // TODO: implement real MAPI GET
        // const res = await this._client.get(path, { params });
        // return res.data;
        throw new Error(`MatrixxAdapter._mapiGet not implemented — path: ${path}`);
    }

    async _mapiPost(path, body = {}) {
        // TODO: implement real MAPI POST
        throw new Error(`MatrixxAdapter._mapiPost not implemented — path: ${path}`);
    }

    // -------------------------------------------------------------------------
    // Subscriber
    // -------------------------------------------------------------------------

    async getSubscriber(cli, opts = {}) {
        // TODO: GET /api/1.0/subscriber?msisdn={cli}
        // Matrixx returns subscriber object with session_info, balance, policy
        // Map Matrixx fields to the standard SubscriberRecord shape
        const raw = await this._mapiGet(`/api/1.0/subscriber`, { msisdn: cli });
        return this._mapSubscriber(raw);
    }

    async getBalance(cli) {
        // TODO: GET /api/1.0/subscriber/{msisdn}/balance
        const raw = await this._mapiGet(`/api/1.0/subscriber/${cli}/balance`);
        return this._mapBalance(raw);
    }

    async getTransactionHistory(cli, days) {
        // TODO: GET /api/1.0/subscriber/{msisdn}/events?days={days}
        const raw = await this._mapiGet(`/api/1.0/subscriber/${cli}/events`, { days });
        return (raw.events || []).map(e => this._mapTransaction(e));
    }

    async getTopupHistory(cli, days) {
        // TODO: GET /api/1.0/subscriber/{msisdn}/topups?days={days}
        const raw = await this._mapiGet(`/api/1.0/subscriber/${cli}/topups`, { days });
        return (raw.topups || []).map(t => this._mapTopup(t));
    }

    async getActiveServices(cli) {
        // TODO: GET /api/1.0/subscriber/{msisdn}/services
        const raw = await this._mapiGet(`/api/1.0/subscriber/${cli}/services`);
        return this._mapServices(raw);
    }

    async applyBalanceAdjustment(cli, amountPence, reason, agentId) {
        // TODO: POST /api/1.0/subscriber/{msisdn}/balance/adjust
        await this._mapiPost(`/api/1.0/subscriber/${cli}/balance/adjust`, {
            amount: amountPence,
            currency: 'GBP_PENCE',
            reason,
            agent_id: agentId,
        });
    }

    async applyServiceStateChange(cli, newState, reason, agentId) {
        // TODO: POST /api/1.0/subscriber/{msisdn}/state
        // Matrixx state names may differ — map A/S/B/T to Matrixx equivalents
        const STATE_MAP = { A: 'ACTIVE', S: 'SUSPENDED', B: 'BARRED', T: 'TERMINATED' };
        await this._mapiPost(`/api/1.0/subscriber/${cli}/state`, {
            state: STATE_MAP[newState] ?? newState,
            reason,
            agent_id: agentId,
        });
    }

    // -------------------------------------------------------------------------
    // Network
    // -------------------------------------------------------------------------

    async getNodeTopology(opts = {}) {
        // TODO: GET /api/1.0/topology/nodes
        const raw = await this._mapiGet('/api/1.0/topology/nodes');
        // Map to the standard { domainId: [{ nodeNumber, name, commAddress, clientPort }] } shape
        return this._mapNodeTopology(raw);
    }

    // -------------------------------------------------------------------------
    // OSS
    // -------------------------------------------------------------------------

    async getNodeKpis(nodeId, metrics, windowSeconds) {
        // TODO: GET /api/1.0/nodes/{nodeId}/kpis
        const raw = await this._mapiGet(`/api/1.0/nodes/${nodeId}/kpis`, {
            metrics: metrics.join(','),
            window: windowSeconds,
        });
        return { nodeId, metrics, windowSeconds, data: raw.kpis || [] };
    }

    async getAlarms(filter = {}) {
        // TODO: GET /api/1.0/alarms
        const raw = await this._mapiGet('/api/1.0/alarms', filter);
        return raw.alarms || [];
    }

    async getChargingErrorRate(nodeId, windowSeconds) {
        // TODO: GET /api/1.0/nodes/{nodeId}/charging/error-rate
        const raw = await this._mapiGet(`/api/1.0/nodes/${nodeId}/charging/error-rate`, {
            window: windowSeconds,
        });
        return { nodeId, windowSeconds, ...raw };
    }

    async triggerRebalance(domainId, dryRun = true) {
        if (dryRun) {
            return {
                dryRun: true, domainId,
                warning: 'Set dryRun=false to trigger Matrixx rebalance. Affects live sessions.',
            };
        }
        // TODO: POST /api/1.0/domains/{domainId}/rebalance
        await this._mapiPost(`/api/1.0/domains/${domainId}/rebalance`);
        return { dryRun: false, domainId, status: 'REBALANCE_TRIGGERED' };
    }

    // -------------------------------------------------------------------------
    // Field mappers — translate Matrixx API shapes to the standard interface shape
    // Replace field names to match actual Matrixx MAPI response structure
    // -------------------------------------------------------------------------

    _mapSubscriber(raw) {
        if (!raw) return null;
        return {
            id: raw.subscriber_id,
            cli: raw.msisdn,
            service_state: this._mapStateFromMatrixx(raw.state),
            wallet_type: raw.account_type === 'PREPAID' ? 'PRE' : 'POST',
            wallet_id: raw.balance_id,
            billing_engine_id: raw.rating_node_id,
            account_type_name: raw.product_offering,
            customer_name: raw.name,
            profile: null,   // Matrixx has no ESCHER profile blob
        };
    }

    _mapBalance(raw) {
        if (!raw) return null;
        return {
            CLI: raw.msisdn,
            BALANCE: raw.balance_amount,
            CREDIT_LIMIT: raw.credit_limit,
            CURRENCY_ID: raw.currency,
            EXPIRY_DATE: raw.expiry_date,
            LAST_TOPUP_AMOUNT: raw.last_topup?.amount,
            LAST_TOPUP_DATE: raw.last_topup?.date,
        };
    }

    _mapTransaction(raw) {
        return {
            EVENT_TYPE: raw.event_type,
            AMOUNT: raw.amount,
            BALANCE_BEFORE: raw.balance_before,
            BALANCE_AFTER: raw.balance_after,
            EVENT_DATE: raw.timestamp,
            DESCRIPTION: raw.description,
            REFERENCE: raw.transaction_id,
        };
    }

    _mapTopup(raw) {
        return {
            TOPUP_AMOUNT: raw.amount,
            TOPUP_DATE: raw.timestamp,
            TOPUP_TYPE: raw.type,
            CHANNEL: raw.channel,
            REFERENCE: raw.reference,
            STATUS: raw.status,
        };
    }

    _mapServices(raw) {
        return {
            cli: raw.msisdn,
            service_state: this._mapStateFromMatrixx(raw.state),
            account_type: raw.product_offering,
            wallet_type: 'PRE',
            serviceFlags: (raw.services || []).map(s => ({
                name: s.service_name,
                type: 'BOOL',
                value: s.enabled,
            })),
        };
    }

    _mapNodeTopology(raw) {
        const topology = {};
        for (const node of (raw.nodes || [])) {
            const domainId = String(node.domain_id);
            if (!topology[domainId]) topology[domainId] = [];
            topology[domainId].push({
                nodeNumber: node.node_id,
                name: node.name,
                commAddress: node.ip_address,
                clientPort: node.port,
            });
        }
        return topology;
    }

    _mapStateFromMatrixx(state) {
        const MAP = { ACTIVE: 'A', SUSPENDED: 'S', BARRED: 'B', TERMINATED: 'T' };
        return MAP[state] ?? state;
    }
}

module.exports = MatrixxAdapter;