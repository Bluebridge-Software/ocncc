/**
 * Oracle BRM OCS Adapter
 *
 * Implements OcsAdapterInterface for Oracle BRM (Billing & Revenue Management).
 * BRM exposes operations via PCM (Portal Communication Module) client libraries,
 * BRM Webservices (SOAP), or the newer REST Billing Care APIs.
 *
 * Implementation status: STUB — interface-compliant skeleton.
 * Replace TODO blocks with real BRM client calls.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const { OcsAdapterInterface } = require('./ocs-adapter-interface');

class BrmAdapter extends OcsAdapterInterface {

    constructor(id, config) {
        super();
        this._id = id;
        this._config = config;
        this._initialised = false;
    }

    get type() { return 'brm'; }

    async initialise() {
        if (this._initialised) return;
        const { wsdl_url, username, password } = this._config;
        if (!wsdl_url || !username || !password) {
            throw new Error(`[BrmAdapter:${this._id}] wsdl_url, username, password are required`);
        }
        // TODO: initialise SOAP client or BRM REST client
        // Option A (SOAP): const soap = require('soap'); this._client = await soap.createClientAsync(wsdl_url, ...);
        // Option B (REST): initialise axios with BRM Billing Care API base URL + OAuth token
        this._initialised = true;
        console.log(`[BrmAdapter:${this._id}] Initialised (stub) — ${wsdl_url}`);
    }

    async shutdown() {
        this._initialised = false;
    }

    async healthCheck() {
        const start = Date.now();
        try {
            // TODO: call BRM /health or PCM_OP_TEST_LOOPBACK
            throw new Error('BrmAdapter health check not yet implemented');
        } catch (err) {
            return { ok: false, latencyMs: Date.now() - start, detail: err.message };
        }
    }

    // -------------------------------------------------------------------------
    // Subscriber — map BRM account/service objects to standard shape
    // BRM models: /account, /service/telco/gsm, /balance_group, /event
    // -------------------------------------------------------------------------

    async getSubscriber(cli, opts = {}) {
        // TODO: PCM_OP_SEARCH or BRM REST GET /accounts?msisdn={cli}
        // Map BRM account + service/telco/gsm to SubscriberRecord
        throw new Error(`[BrmAdapter:${this._id}] getSubscriber not yet implemented`);
    }

    async getBalance(cli) {
        // TODO: PCM_OP_BAL_GET_BALANCES or REST GET /accounts/{id}/balances
        throw new Error(`[BrmAdapter:${this._id}] getBalance not yet implemented`);
    }

    async getTransactionHistory(cli, days) {
        // TODO: PCM_OP_SEARCH on /event/* with time window
        throw new Error(`[BrmAdapter:${this._id}] getTransactionHistory not yet implemented`);
    }

    async getTopupHistory(cli, days) {
        // TODO: PCM_OP_SEARCH on /event/billing/payment
        throw new Error(`[BrmAdapter:${this._id}] getTopupHistory not yet implemented`);
    }

    async getActiveServices(cli) {
        // TODO: PCM_OP_READ /service/telco/gsm for account
        throw new Error(`[BrmAdapter:${this._id}] getActiveServices not yet implemented`);
    }

    async applyBalanceAdjustment(cli, amountPence, reason, agentId) {
        // TODO: PCM_OP_BAL_TRANSFER or REST POST /accounts/{id}/adjustments
        throw new Error(`[BrmAdapter:${this._id}] applyBalanceAdjustment not yet implemented`);
    }

    async applyServiceStateChange(cli, newState, reason, agentId) {
        // TODO: PCM_OP_CUST_SET_STATUS
        throw new Error(`[BrmAdapter:${this._id}] applyServiceStateChange not yet implemented`);
    }

    async getNodeTopology(opts = {}) {
        // TODO: BRM CM (Connection Manager) node list
        throw new Error(`[BrmAdapter:${this._id}] getNodeTopology not yet implemented`);
    }

    async raiseTicket(cli, category, priority, notes, agentId) {
        // TODO: PCM_OP_PROBLEM_CREATE or CRM integration
        throw new Error(`[BrmAdapter:${this._id}] raiseTicket not yet implemented`);
    }
}

module.exports = BrmAdapter;