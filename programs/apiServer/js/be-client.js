/**
 * OCNCC Billing Engine Client Interface.
 * Main client interface - routes requests to billing engines
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const BillingEngine = require('./billing-engine');
const codec = require('./escher-codec');

class BeClient {
  /**
   * @param {Config} config - Configuration object
   */
  constructor(config) {
    this.config = config;
    this.engines = new Map(); // engineID -> BillingEngine
    this._cmidCounter = 1;

    // Initialise billing engines from config
    /*
    console.log('[BeClient] Using config file for billing engine initialisation');
    const engineConfigs = config.getBillingEngines();
    for (const engineConfig of engineConfigs) {
      this.addBillingEngine(engineConfig);
    }
    */
  }

  /**
   * Add or update a billing engine configuration at runtime.
   */
  addBillingEngine(engineConfig) {
    const { id, primary, secondary } = engineConfig;

    // Remove existing engine if present
    if (this.engines.has(id)) {
      this.engines.get(id).destroy();
    }

    const options = {
      messageTimeoutMs: this.config.get('messageTimeoutMs'),
      primaryFailbackIntervalMs: this.config.get('primaryFailbackIntervalMs'),
      maxOutstandingMessages: this.config.get('maxOutstandingMessages'),
      clientName: this.config.get('clientName'),
      connectionRetryMs: this.config.get('connectionRetryMs'),
      heartbeatIntervalMs: this.config.get('heartbeatIntervalMs'),
      logTraffic: this.config.get('logTraffic') || false
    };

    const engine = new BillingEngine(id, { primary, secondary }, options);
    this.engines.set(id, engine);
    console.log(`[BeClient] Added billing engine ${id}: primary=${primary.ip}:${primary.port}` +
      (secondary ? `, secondary=${secondary.ip}:${secondary.port}` : ''));

    // Also update the config
    this.config.addBillingEngine(engineConfig);

    return engine;
  }

  /**
   * Remove a billing engine.
   */
  removeBillingEngine(id) {
    const engine = this.engines.get(id);
    if (engine) {
      engine.destroy();
      this.engines.delete(id);
      this.config.removeBillingEngine(id);
    }
  }

  /**
   * Get a billing engine by ID, creating it on-demand if configured.
   */
  getBillingEngine(billingEngineID) {
    return this.engines.get(billingEngineID) || null;
  }

  /**
   * Generate a unique CMID (Client Message ID).
   * Thread-safe since Node.js is single-threaded.
   */
  nextCMID() {
    return this._cmidCounter++;
  }

  /**
   * Send a JSON message to a billing engine.
   * Accepts both raw and friendly JSON formats.
   * Returns the response in the requested format.
   * 
   * @param {object} message - JSON message (raw or friendly format)
   * @param {object} options - { billingEngineId, responseFormat: 'raw'|'friendly'|'both', isNewDialog }
   * @returns {Promise<object>} - Decoded response
   */
  async sendMessage(message, options = {}) {
    // Detect input format and normalise to raw
    const inputIsFriendly = codec.isFriendlyFormat(message);
    const rawMessage = inputIsFriendly ? codec.normaliseToRaw(message) : { ...message };

    // Determine BE ID from message or options
    let beId = options.billingEngineId;
    if (beId === undefined || beId === null) {
      // Try to extract from message header
      const head = rawMessage['HEAD'] || rawMessage['Header'] || {};
      beId = head['SVID'] || head['BE Server ID'];
    }

    if (beId === undefined || beId === null) {
      throw new Error('Billing Engine ID is required. Provide via options.billingEngineId or SVID in the message header.');
    }

    const engine = this.getBillingEngine(beId);
    if (!engine) {
      throw new Error(`Unknown billing engine ID: ${beId}. Configure it first via POST /api/config/engines.`);
    }

    // Auto-generate CMID if not provided
    let cmid;
    if (rawMessage['HEAD'] && rawMessage['HEAD']['CMID'] !== undefined) {
      cmid = rawMessage['HEAD']['CMID'];
    } else {
      cmid = this.nextCMID();
      if (!rawMessage['HEAD']) rawMessage['HEAD'] = {};
      rawMessage['HEAD']['CMID'] = cmid;
    }

    // Ensure SVID is set
    if (!rawMessage['HEAD']['SVID']) {
      rawMessage['HEAD']['SVID'] = beId;
    }

    // Auto-fill DATE if not set
    if (!rawMessage['HEAD']['DATE']) {
      rawMessage['HEAD']['DATE'] = `~date:${Math.floor(Date.now() / 1000)}`;
    }

    // Auto-fill VER if not set
    if (!rawMessage['HEAD']['VER ']) {
      rawMessage['HEAD']['VER '] = 100;
    }

    // Auto-fill USEC if not set
    if (rawMessage['HEAD']['USEC'] === undefined) {
      rawMessage['HEAD']['USEC'] = (Date.now() % 1000) * 1000;
    }

    // Auto-fill DUP if not set
    if (rawMessage['HEAD']['DUP '] === undefined) {
      rawMessage['HEAD']['DUP '] = 0;
    }

    const isNewDialog = options.isNewDialog !== undefined ? options.isNewDialog : true;

    // Encode the message
    const encoded = codec.encodeMap(rawMessage);

    // Send and wait for response
    const requestOptions = {
      isNewDialog: isNewDialog,
      preferredEngine: options.preferredEngine
    };
    const responseBuf = await engine.sendRequest(encoded, cmid, requestOptions);

    // Decode response
    const responseFormat = options.responseFormat || 'both';
    const rawDecoded = codec.decodeMap(responseBuf, false);

    if (responseFormat === 'raw') {
      return { format: 'raw', message: rawDecoded };
    } else if (responseFormat === 'friendly') {
      return { format: 'friendly', message: codec.convertToFriendly(rawDecoded) };
    } else {
      return {
        format: 'both',
        raw: rawDecoded,
        friendly: codec.convertToFriendly(rawDecoded)
      };
    }
  }

  /**
   * Get status of all billing engines.
   */
  getStatus() {
    const status = {};
    for (const [id, engine] of this.engines) {
      status[id] = engine.getStatus();
    }
    return status;
  }

  /**
   * Get list of all billing engine IDs.
   */
  getBillingEngineIds() {
    return [...this.engines.keys()];
  }

  /**
   * Destroy all billing engines and clean up.
   */
  destroy() {
    for (const [id, engine] of this.engines) {
      engine.destroy();
    }
    this.engines.clear();
  }
}

module.exports = BeClient;
