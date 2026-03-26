// routes/api.js
// API route handlers

'use strict';

const express = require('express');

/**
 * Create the API router.
 * @param {BeClient} beClient - The billing engine client instance
 * @param {StatsTracker} [statsTracker] - Optional statistics tracker
 * @returns {express.Router}
 */
function createRouter(beClient, statsTracker) {
  const router = express.Router();

  // ---------------------------------------------------------------------------
  // Endpoint-to-message-type mapping
  // ---------------------------------------------------------------------------
  const ENDPOINT_TYPES = {
    '/wallet-info': { type: 'WI  ', action: 'REQ ', isNew: true },
    '/wallet-state-info': { type: 'WSI ', action: 'REQ ', isNew: true },
    '/initial-reservation': { type: 'IR  ', action: 'REQ ', isNew: true },
    '/subsequent-reservation': { type: 'SR  ', action: 'REQ ', isNew: false },
    '/commit-reservation': { type: 'CR  ', action: 'REQ ', isNew: false },
    '/revoke-reservation': { type: 'RR  ', action: 'REQ ', isNew: false },
    '/named-event': { type: 'NE  ', action: 'REQ ', isNew: true },
    '/initial-named-event-reservation': { type: 'INER', action: 'REQ ', isNew: true },
    '/subsequent-named-event-reservation': { type: 'SNER', action: 'REQ ', isNew: false },
    '/confirm-named-event-reservation': { type: 'CNER', action: 'REQ ', isNew: false },
    '/revoke-named-event-reservation': { type: 'RNER', action: 'REQ ', isNew: false },
    '/initial-amount-reservation': { type: 'IARR', action: 'REQ ', isNew: true },
    '/subsequent-amount-reservation': { type: 'SARR', action: 'REQ ', isNew: false },
    '/confirm-amount-reservation': { type: 'CARR', action: 'REQ ', isNew: false },
    '/revoke-amount-reservation': { type: 'RARR', action: 'REQ ', isNew: false },
    '/apply-tariffed-charge': { type: 'ATC ', action: 'REQ ', isNew: true },
    '/direct-amount': { type: 'DA  ', action: 'REQ ', isNew: true },
    '/unit-second-rate': { type: 'USR ', action: 'REQ ', isNew: true },
    '/named-event-rate': { type: 'NER ', action: 'REQ ', isNew: true },
    '/wallet-create': { type: 'WC  ', action: 'REQ ', isNew: true },
    '/wallet-update': { type: 'WU  ', action: 'REQ ', isNew: true },
    '/wallet-delete': { type: 'WD  ', action: 'REQ ', isNew: true },
    '/wallet-general-recharge': { type: 'WGR ', action: 'REQ ', isNew: true },
    '/voucher-info': { type: 'VI  ', action: 'REQ ', isNew: true },
    '/voucher-redeem': { type: 'VR  ', action: 'REQ ', isNew: true },
    '/commit-voucher-redeem': { type: 'CVR ', action: 'REQ ', isNew: false },
    '/revoke-voucher-redeem': { type: 'RVR ', action: 'REQ ', isNew: false },
    '/voucher-redeem-wallet': { type: 'VRW ', action: 'REQ ', isNew: true },
    '/voucher-update': { type: 'VU  ', action: 'REQ ', isNew: true },
    '/voucher-type-recharge': { type: 'VTR ', action: 'REQ ', isNew: true },
    '/voucher-type-recharge-confirm': { type: 'VTRC', action: 'REQ ', isNew: false },
    '/bad-pin': { type: 'BPIN', action: 'REQ ', isNew: true },
    '/reload-mfile': { type: 'LDMF', action: 'REQ ', isNew: true },
    '/wallet-reservations-info': { type: 'WRI ', action: 'REQ ', isNew: true },
    '/wallet-reservation-end': { type: 'WRE ', action: 'REQ ', isNew: true },
    '/merge-wallets': { type: 'MGW ', action: 'REQ ', isNew: true }
  };

  // ---------------------------------------------------------------------------
  // Generic send endpoint
  // ---------------------------------------------------------------------------
  router.post('/send', async (req, res) => {
    try {
      const message = req.body;
      if (!message || typeof message !== 'object') {
        return res.status(400).json({ error: 'Request body must be a JSON object' });
      }

      const codec = require('../escher-codec');
      const isFriendly = codec.isFriendlyFormat(message);

      const options = {
        billingEngineId: req.query.billingEngineId ? parseInt(req.query.billingEngineId, 10) : undefined,
        responseFormat: req.query.format || (isFriendly ? 'friendly' : 'raw'),
        isNewDialog: req.query.isNewDialog !== 'false',
        preferredEngine: req.query.preferredEngine || 'primary'
      };

      if (statsTracker) {
        const beId = options.billingEngineId || (message['HEAD'] && message['HEAD']['SVID']) || (message['Header'] && message['Header']['BE Server ID']);
        const endpoint = message['TYPE'] || message['FOX Type'] || '/send';
        statsTracker.recordCall('/send (' + endpoint.trim() + ')', beId, req.headers['x-client-id'] || req.ip);
      }

      const result = await beClient.sendMessage(message, options);
      res.json(result);
    } catch (err) {
      if (statsTracker) {
        const beId = options?.billingEngineId || (req.body?.['HEAD']?.['SVID']);
        statsTracker.recordCall('/send', beId, req.headers['x-client-id'] || req.ip, 'error');
      }
      handleError(res, err);
    }
  });

  // ---------------------------------------------------------------------------
  // Typed endpoints (one per message type)
  // ---------------------------------------------------------------------------
  for (const [path, info] of Object.entries(ENDPOINT_TYPES)) {
    router.post(path, async (req, res) => {
      try {
        const message = req.body;
        if (!message || typeof message !== 'object') {
          return res.status(400).json({ error: 'Request body must be a JSON object' });
        }

        // Auto-fill message type and action if not provided
        const codec = require('../escher-codec');
        const isFriendly = codec.isFriendlyFormat(message);

        if (isFriendly) {
          if (!message['FOX Type']) message['FOX Type'] = info.type;
          if (!message['FOX Action']) message['FOX Action'] = info.action;
        } else {
          if (!message['TYPE']) message['TYPE'] = info.type;
          if (!message['ACTN']) message['ACTN'] = info.action;
        }

        const options = {
          billingEngineId: req.query.billingEngineId ? parseInt(req.query.billingEngineId, 10) : undefined,
          responseFormat: req.query.format || (isFriendly ? 'friendly' : 'raw'),
          isNewDialog: req.query.isNewDialog !== undefined ? req.query.isNewDialog !== 'false' : info.isNew,
          preferredEngine: req.query.preferredEngine || 'primary'
        };

        if (statsTracker) {
          const beId = options.billingEngineId || (message['HEAD'] && message['HEAD']['SVID']) || (message['Header'] && message['Header']['BE Server ID']);
          statsTracker.recordCall(path, beId, req.headers['x-client-id'] || req.ip);
        }

        const result = await beClient.sendMessage(message, options);
        res.json(result);
      } catch (err) {
        if (statsTracker) {
          const beId = options?.billingEngineId || (req.body?.['HEAD']?.['SVID']);
          statsTracker.recordCall(path, beId, req.headers['x-client-id'] || req.ip, 'error');
        }
        handleError(res, err);
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Status & Stats endpoints
  // ---------------------------------------------------------------------------
  router.get('/stats', async (req, res) => {
    if (!statsTracker) {
      return res.status(501).json({ error: 'Stats tracking not configured' });
    }
    const hours = parseInt(req.query.hours, 10) || 24;
    try {
      res.json(await statsTracker.getStats(hours));
    } catch (err) {
      handleError(res, err);
    }
  });

  router.get('/status', (req, res) => {
    res.json(beClient.getStatus());
  });

  router.get('/status/:engineId', (req, res) => {
    const engineId = parseInt(req.params.engineId, 10);
    const engine = beClient.getBillingEngine(engineId);
    if (!engine) {
      return res.status(404).json({ error: `Billing engine ${engineId} not found` });
    }
    res.json(engine.getStatus());
  });

  // ---------------------------------------------------------------------------
  // Configuration endpoints
  // ---------------------------------------------------------------------------
  router.get('/config', (req, res) => {
    res.json(beClient.config.toJSON());
  });

  router.post('/config/engines', (req, res) => {
    try {
      const config = req.body;
      if (!config || !config.id || !config.primary || !config.primary.ip || !config.primary.port) {
        return res.status(400).json({ error: 'Required: id, primary.ip, primary.port' });
      }
      beClient.addBillingEngine(config);
      res.json({ message: `Billing engine ${config.id} added/updated`, status: beClient.getBillingEngine(config.id).getStatus() });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  router.delete('/config/engines', (req, res) => {
    const id = parseInt(req.query.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: 'Billing engine ID required' });
    }
    if (!beClient.getBillingEngine(id)) {
      return res.status(404).json({ error: `Billing engine ${id} not found` });
    }
    beClient.removeBillingEngine(id);
    res.json({ message: `Billing engine ${id} removed` });
  });

  // ---------------------------------------------------------------------------
  // Health check
  // ---------------------------------------------------------------------------
  router.get('/health', (req, res) => {
    const engines = beClient.getStatus();
    const anyAvailable = Object.values(engines).some(e =>
      e.primary.available || (e.secondary && e.secondary.available)
    );
    res.status(anyAvailable || Object.keys(engines).length === 0 ? 200 : 503).json({
      status: anyAvailable || Object.keys(engines).length === 0 ? 'ok' : 'degraded',
      engines: Object.keys(engines).length,
      timestamp: new Date().toISOString()
    });
  });

  return router;
}

function handleError(res, err) {
  const msg = err.message || 'Unknown error';
  if (msg.includes('timed out')) {
    return res.status(504).json({ error: msg });
  }
  if (msg.includes('no connection') || msg.includes('connection failed') || msg.includes('both connections')) {
    return res.status(502).json({ error: msg });
  }
  if (msg.includes('Unknown billing engine') || msg.includes('required')) {
    return res.status(400).json({ error: msg });
  }
  console.error('[API Error]', err);
  res.status(500).json({ error: msg });
}

module.exports = createRouter;
