/**
 * OCNCC Billing Engine Connection.
 * Manages a primary/secondary billing engine pair
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const EventEmitter = require('events');
const BeConnection = require('./be-connection');
const codec = require('../codec/escher-codec');

class BillingEngine extends EventEmitter {
  /**
   * @param {number} engineID
   * @param {object} config - { primary: {ip, port}, secondary: {ip, port}, ... }
   * @param {object} options - { messageTimeoutMs, primaryFailbackIntervalMs, clientName, ... }
   */
  constructor(engineID, config, options = {}) {
    super();
    this.engineID = engineID;
    this.messageTimeoutMs = options.messageTimeoutMs || 2000;
    this.primaryFailbackIntervalMs = options.primaryFailbackIntervalMs || -1;
    this.maxOutstandingMessages = options.maxOutstandingMessages || 0xFFFFFFFF;
    this.logTraffic = options.logTraffic || false;

    // Outstanding requests map: CMID -> { resolve, reject, timer, usingPrimary, sentTime }
    this._requests = new Map();

    // Statistics
    this.stats = {
      timeouts: 0,
      orphans: 0,
      sent: 0,
      received: 0,
      failovers: 0
    };

    // Setup primary connection
    const connOpts = {
      clientName: options.clientName || 'bbs-ocncc-be-client',
      connectionRetryMs: options.connectionRetryMs || 5000,
      heartbeatIntervalMs: options.heartbeatIntervalMs || 3000
    };

    this.primary = new BeConnection(engineID, config.primary.ip, config.primary.port, connOpts);
    this.primary.on('message', (msg) => this._onMessage(msg, 'primary'));
    this.primary.on('error_disconnect', () => this._onHalfError('primary'));

    // Setup secondary connection (optional)
    if (config.secondary && config.secondary.ip) {
      this.secondary = new BeConnection(engineID, config.secondary.ip, config.secondary.port, connOpts);
      this.secondary.on('message', (msg) => this._onMessage(msg, 'secondary'));
      this.secondary.on('error_disconnect', () => this._onHalfError('secondary'));
    } else {
      this.secondary = null;
    }

    // Heartbeat timer
    this._heartbeatTimer = setInterval(() => {
      this.primary.doHeartbeat();
      if (this.secondary) this.secondary.doHeartbeat();
    }, connOpts.heartbeatIntervalMs);
  }

  /** Check if the billing engine is congested. */
  isCongested() {
    return this._requests.size > this.maxOutstandingMessages;
  }

  /** Check if primary is available. */
  isPrimaryAvailable() {
    return this.primary.isAvailable();
  }

  /** Check if secondary is available. */
  isSecondaryAvailable() {
    return this.secondary ? this.secondary.isAvailable() : false;
  }

  /** Check if either half is available. */
  isAvailable() {
    return this.isPrimaryAvailable() || this.isSecondaryAvailable();
  }

  /**
   * Send a request to the billing engine.
   * Returns a Promise that resolves with the decoded response.
   * 
   * @param {Buffer} encodedMsg - Binary Escher message
   * @param {number} cmid - Client message ID for tracking
   * @param {object|boolean} options - Options object { isNewDialog, preferredEngine }, or legacy boolean for isNewDialog
   * @returns {Promise<Buffer>} - Raw response buffer
   */
  sendRequest(encodedMsg, cmid, options = {}) {
    // Handle legacy boolean for backward compatibility
    const isNewDialog = typeof options === 'boolean' ? options : (options.isNewDialog !== false);
    const preferredEngine = (typeof options === 'object' && options.preferredEngine === 'secondary') ? 'secondary' : 'primary';
    const fallbackEngine = preferredEngine === 'primary' ? 'secondary' : 'primary';

    return new Promise((resolve, reject) => {
      // Congestion check for new dialogs
      if (isNewDialog && this.isCongested()) {
        reject(new Error(`BE ${this.engineID} is congested`));
        return;
      }

      const request = {
        resolve,
        reject,
        cmid,
        encodedMsg,
        usingPrimary: preferredEngine === 'primary',
        numAttempts: 0,
        sentTime: Date.now(),
        timer: null
      };

      // Set timeout
      if (this.messageTimeoutMs > 0) {
        request.timer = setTimeout(() => {
          this._requests.delete(cmid);
          this.stats.timeouts++;
          reject(new Error(`Request ${cmid} timed out after ${this.messageTimeoutMs}ms on BE ${this.engineID}`));
        }, this.messageTimeoutMs);
      }

      this._requests.set(cmid, request);

      if (isNewDialog) {
        // New dialog: try preferred first, fallback to secondary
        if (!this._attemptSend(request, preferredEngine)) {
          request.usingPrimary = fallbackEngine === 'primary';
          if (!this._attemptSend(request, fallbackEngine)) {
            this._cleanupRequest(cmid);
            reject(new Error(`BE ${this.engineID}: no connection available (tried ${preferredEngine} and ${fallbackEngine})`));
          }
        }
      } else {
        // Existing dialog: check for failback to primary
        if (!request.usingPrimary && this._canFailbackToPrimary(request)) {
          request.usingPrimary = true;
          this.stats.failovers++;
        }

        const half = request.usingPrimary ? 'primary' : 'secondary';
        if (!this._attemptSend(request, half)) {
          // Failover
          const otherHalf = request.usingPrimary ? 'secondary' : 'primary';
          request.usingPrimary = !request.usingPrimary;
          this.stats.failovers++;
          if (!this._attemptSend(request, otherHalf)) {
            this._cleanupRequest(cmid);
            reject(new Error(`BE ${this.engineID}: both connections failed`));
          }
        }
      }
    });
  }

  /** Destroy this billing engine and all connections. */
  destroy() {
    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
    this.primary.destroy();
    if (this.secondary) this.secondary.destroy();

    // Reject all outstanding requests
    for (const [cmid, req] of this._requests) {
      this._cleanupRequest(cmid);
      req.reject(new Error('BillingEngine destroyed'));
    }
    this._requests.clear();
  }

  getStatus() {
    return {
      engineID: this.engineID,
      primary: {
        connected: this.primary.isConnected(),
        available: this.primary.isAvailable(),
        identifier: this.primary.getIdentifier()
      },
      secondary: this.secondary ? {
        connected: this.secondary.isConnected(),
        available: this.secondary.isAvailable(),
        identifier: this.secondary.getIdentifier()
      } : null,
      outstandingRequests: this._requests.size,
      stats: { ...this.stats }
    };
  }

  // ---- Private methods ----

  _attemptSend(request, half) {
    const conn = half === 'primary' ? this.primary : this.secondary;
    if (!conn || !conn.isAvailable()) return false;

    request.numAttempts++;
    const success = conn.write(request.encodedMsg);
    if (success) {
      request.sentTime = Date.now();
      this.stats.sent++;

      if (this.logTraffic) {
        console.log(`[BE ${this.engineID}] Sent to ${half} (CMID=${request.cmid}, attempt=${request.numAttempts})`);
      }
    }
    return success;
  }

  _canFailbackToPrimary(request) {
    if (this.primaryFailbackIntervalMs < 0) return false;
    if (!this.primary.isAvailable()) return false;

    const now = Date.now();
    if (now < request.sentTime + this.primaryFailbackIntervalMs) return false;
    if (now < this.primary.getConnectTime() + this.primaryFailbackIntervalMs) return false;

    return true;
  }

  _onMessage(msgBuf, half) {
    this.stats.received++;

    // Extract CMID from the response
    try {
      const decoded = codec.decodeMap(msgBuf, false);
      const head = decoded['HEAD'];
      const cmid = head ? head['CMID'] : undefined;

      if (cmid === undefined || cmid === null) {
        console.error(`[BE ${this.engineID}] Received message without CMID from ${half}`);
        return;
      }

      const request = this._requests.get(cmid);
      if (!request) {
        this.stats.orphans++;
        if (this.logTraffic) {
          console.log(`[BE ${this.engineID}] Orphan response for CMID=${cmid} from ${half}`);
        }
        return;
      }

      if (this.logTraffic) {
        console.log(`[BE ${this.engineID}] Received response for CMID=${cmid} from ${half}`);
      }

      this._cleanupRequest(cmid);
      request.resolve(msgBuf);
    } catch (err) {
      console.error(`[BE ${this.engineID}] Error processing response from ${half}:`, err.message);
    }
  }

  _onHalfError(failedHalf) {
    console.error(`[BE ${this.engineID}] ${failedHalf} connection lost`);
    const otherHalf = failedHalf === 'primary' ? 'secondary' : 'primary';
    const otherConn = failedHalf === 'primary' ? this.secondary : this.primary;

    if (!otherConn || !otherConn.isAvailable()) {
      // Both halves down - fail all outstanding requests
      console.error(`[BE ${this.engineID}] Both halves down, failing ${this._requests.size} requests`);
      for (const [cmid, req] of this._requests) {
        if ((failedHalf === 'primary' && req.usingPrimary) ||
          (failedHalf === 'secondary' && !req.usingPrimary)) {
          this._cleanupRequest(cmid);
          req.reject(new Error(`BE ${this.engineID}: dual connection failure`));
        }
      }
      return;
    }

    // Re-queue requests from failed half to other half
    for (const [cmid, req] of this._requests) {
      const reqOnFailedHalf = (failedHalf === 'primary' && req.usingPrimary) ||
        (failedHalf === 'secondary' && !req.usingPrimary);
      if (!reqOnFailedHalf) continue;

      if (req.numAttempts >= 2) {
        this._cleanupRequest(cmid);
        req.reject(new Error(`BE ${this.engineID}: request failed after failover`));
      } else {
        req.usingPrimary = !req.usingPrimary;
        this.stats.failovers++;
        if (!this._attemptSend(req, otherHalf)) {
          this._cleanupRequest(cmid);
          req.reject(new Error(`BE ${this.engineID}: failover send failed`));
        }
      }
    }
  }

  _cleanupRequest(cmid) {
    const req = this._requests.get(cmid);
    if (req && req.timer) {
      clearTimeout(req.timer);
      req.timer = null;
    }
    this._requests.delete(cmid);
  }
}

module.exports = BillingEngine;
