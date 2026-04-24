/**
 * Mock OCS Adapter
 *
 * In-memory fixture data implementing OcsAdapterInterface.
 * Use for local development, unit tests, and CI pipelines
 * where no real OCS backend is available.
 *
 * Seed data can be overridden by passing fixtures to the constructor.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const { OcsAdapterInterface } = require('./ocs-adapter-interface');

const DEFAULT_SUBSCRIBERS = {
    '447700900001': {
        id: 1001, cli: '447700900001', service_state: 'A',
        wallet_type: 'PRE', wallet_id: 20001, billing_engine_id: 351,
        account_type_id: 3, account_type_name: 'PAYG Standard',
        customer_name: 'ALICE TEST', profile: null,
    },
    '447700900002': {
        id: 1002, cli: '447700900002', service_state: 'S',
        wallet_type: 'PRE', wallet_id: 20002, billing_engine_id: 351,
        account_type_id: 3, account_type_name: 'PAYG Standard',
        customer_name: 'BOB TEST', profile: null,
    },
    '447700900003': {
        id: 1003, cli: '447700900003', service_state: 'A',
        wallet_type: 'POST', wallet_id: 20003, billing_engine_id: 352,
        account_type_id: 5, account_type_name: 'Business 50',
        customer_name: 'CAROL TEST', profile: null,
    },
};

const DEFAULT_BALANCES = {
    '447700900001': { CLI: '447700900001', BALANCE: 1250, CREDIT_LIMIT: 0, CURRENCY_ID: 'GBP', EXPIRY_DATE: '2026-12-31', LAST_TOPUP_AMOUNT: 1000, LAST_TOPUP_DATE: '2026-04-01' },
    '447700900002': { CLI: '447700900002', BALANCE: 0, CREDIT_LIMIT: 0, CURRENCY_ID: 'GBP', EXPIRY_DATE: '2026-06-30', LAST_TOPUP_AMOUNT: 500, LAST_TOPUP_DATE: '2026-03-15' },
    '447700900003': { CLI: '447700900003', BALANCE: -2500, CREDIT_LIMIT: 5000, CURRENCY_ID: 'GBP', EXPIRY_DATE: null, LAST_TOPUP_AMOUNT: null, LAST_TOPUP_DATE: null },
};

const DEFAULT_TOPOLOGY = {
    '12': [
        { nodeNumber: 351, name: 'VWS01', commAddress: '192.168.127.42', clientPort: 1500 },
        { nodeNumber: 352, name: 'VWS02', commAddress: '192.168.127.47', clientPort: 1500 },
    ],
};

let _ticketSequence = 9000;

class MockAdapter extends OcsAdapterInterface {

    constructor(id, config = {}) {
        super();
        this._id = id;
        this._config = config;
        this._subscribers = { ...DEFAULT_SUBSCRIBERS, ...(config.fixtures?.subscribers || {}) };
        this._balances = { ...DEFAULT_BALANCES, ...(config.fixtures?.balances || {}) };
        this._topology = config.fixtures?.topology || DEFAULT_TOPOLOGY;
        this._transactions = {};
        this._topups = {};
        this._tickets = [];
        this._adjustments = [];
        this._initialised = false;
    }

    get type() { return 'mock'; }

    async initialise() {
        this._initialised = true;
        console.log(`[MockAdapter:${this._id}] Initialised with ${Object.keys(this._subscribers).length} fixture subscribers`);
    }

    async shutdown() {
        this._initialised = false;
    }

    async healthCheck() {
        return { ok: true, latencyMs: 0, detail: 'mock' };
    }

    async getSubscriber(cli, opts = {}) {
        const sub = this._subscribers[cli] ?? null;
        if (!sub) return null;
        return {
            ...sub,
            decodedProfile: opts.decodeProfile ? {
                tags: [
                    { tagId: '0000001A', name: 'BALANCE', type: 'INT', value: this._balances[cli]?.BALANCE ?? 0 },
                    { tagId: '0000002B', name: 'DATA_ENABLED', type: 'BOOL', value: true },
                    { tagId: '0000003C', name: 'ROAMING_ENABLED', type: 'BOOL', value: false },
                    { tagId: '0000004D', name: 'VOICEMAIL_ACTIVE', type: 'BOOL', value: true },
                ],
            } : undefined,
        };
    }

    async getBalance(cli) {
        return this._balances[cli] ?? null;
    }

    async getTransactionHistory(cli, days) {
        return (this._transactions[cli] || []).slice(0, 20).map(t => ({
            EVENT_TYPE: t.type,
            AMOUNT: t.amount,
            BALANCE_BEFORE: t.balanceBefore,
            BALANCE_AFTER: t.balanceAfter,
            EVENT_DATE: t.date,
            DESCRIPTION: t.description,
            REFERENCE: t.ref,
        }));
    }

    async getTopupHistory(cli, days) {
        return (this._topups[cli] || []).slice(0, 10).map(t => ({
            TOPUP_AMOUNT: t.amount,
            TOPUP_DATE: t.date,
            TOPUP_TYPE: 'VOUCHER',
            CHANNEL: 'ONLINE',
            REFERENCE: t.ref,
            STATUS: t.status || 'COMPLETE',
        }));
    }

    async getActiveServices(cli) {
        const sub = this._subscribers[cli];
        if (!sub) return null;
        return {
            cli,
            service_state: sub.service_state,
            account_type: sub.account_type_name,
            wallet_type: sub.wallet_type,
            serviceFlags: [
                { name: 'DATA_ENABLED', type: 'BOOL', value: true },
                { name: 'ROAMING_ENABLED', type: 'BOOL', value: false },
                { name: 'VOICEMAIL', type: 'BOOL', value: true },
            ],
        };
    }

    async applyBalanceAdjustment(cli, amountPence, reason, agentId) {
        if (!this._balances[cli]) {
            this._balances[cli] = { CLI: cli, BALANCE: 0, CURRENCY_ID: 'GBP' };
        }
        const before = this._balances[cli].BALANCE;
        this._balances[cli].BALANCE += amountPence;
        this._adjustments.push({ cli, amountPence, reason, agentId, at: new Date().toISOString() });

        if (!this._transactions[cli]) this._transactions[cli] = [];
        this._transactions[cli].unshift({
            type: amountPence >= 0 ? 'CREDIT' : 'DEBIT',
            amount: amountPence,
            balanceBefore: before,
            balanceAfter: before + amountPence,
            date: new Date().toISOString(),
            description: reason,
            ref: `ADJ-${Date.now()}`,
        });
    }

    async applyServiceStateChange(cli, newState, reason, agentId) {
        if (!this._subscribers[cli]) throw new Error(`Subscriber ${cli} not found`);
        this._subscribers[cli].service_state = newState;
    }

    async getNodeTopology(opts = {}) {
        return this._topology;
    }

    async queryRevenue({ product, region, periodStart, periodEnd }) {
        return {
            product, region, periodStart, periodEnd,
            totalRevenuePence: 12_345_678,
            breakdown: [
                { PERIOD_MONTH: periodStart, TOTAL_REVENUE: 4_115_226, EVENT_COUNT: 1420 },
                { PERIOD_MONTH: periodEnd, TOTAL_REVENUE: 8_230_452, EVENT_COUNT: 2840 },
            ],
        };
    }

    async queryProductPerformance({ productId }) {
        return {
            productId,
            data: [{ PRODUCT_NAME: 'PAYG Standard', UNIQUE_SUBSCRIBERS: 14_200, TOTAL_REVENUE: 71_234_500, TOTAL_EVENTS: 284_100 }],
        };
    }

    async queryArpu({ segment }) {
        return { segment, ARPU_PENCE: 502, SUBSCRIBER_COUNT: 14_200 };
    }

    async getNodeKpis(nodeId, metrics) {
        return {
            nodeId, metrics,
            data: metrics.map(m => ({ STAT_NAME: m, STAT_VALUE: Math.floor(Math.random() * 1000) })),
        };
    }

    async getAlarms(filter = {}) {
        return [
            { ALARM_ID: 'ALM001', SEVERITY: 'WARNING', SYSTEM_NAME: 'VWS01', MESSAGE: 'High session count', RAISED_AT: new Date().toISOString(), ACKNOWLEDGED: 'N' },
        ];
    }

    async getChargingErrorRate(nodeId) {
        return { nodeId, ERROR_COUNT: 12, TOTAL_COUNT: 10000, ERROR_RATE_PCT: 0.12 };
    }

    async triggerRebalance(domainId, dryRun = true) {
        return { dryRun, domainId, status: dryRun ? 'DRY_RUN_OK' : 'REBALANCE_TRIGGERED' };
    }

    async raiseTicket(cli, category, priority, notes, agentId) {
        const ticketId = ++_ticketSequence;
        this._tickets.push({ ticketId, cli, category, priority, notes, agentId, status: 'OPEN', createdAt: new Date().toISOString() });
        return { ticketId };
    }

    async invalidateSubscriberCache(cli) { /* no-op */ }
    async invalidateReferenceCache() { /* no-op */ }

    // Test helper — inspect mock state
    getState() {
        return { subscribers: this._subscribers, balances: this._balances, tickets: this._tickets, adjustments: this._adjustments };
    }
}

module.exports = MockAdapter;