/**
 * OCNCC Billing Engine Connection.
 * TCP connection to a single billing engine half (primary or secondary)
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const net = require('net');
const EventEmitter = require('events');
const codec = require('./escher-codec');

class BeConnection extends EventEmitter {
  /**
   * @param {number} engineID - Billing engine ID
   * @param {string} ip - IP address of the server
   * @param {number} port - Port number
   * @param {object} options - { clientName, connectionRetryMs, heartbeatIntervalMs }
   */
  constructor(engineID, ip, port, options = {}) {
    super();
    this.engineID = engineID;
    this.ip = ip;
    this.port = port;
    this.clientName = options.clientName || 'js-be-client';
    this.connectionRetryMs = options.connectionRetryMs || 5000;
    this.heartbeatIntervalMs = options.heartbeatIntervalMs || 3000;

    this.identifier = `${engineID}:${ip}-${port}`;
    this.socket = null;
    this.available = false;  // true after handshake complete
    this.connected = false;
    this.connectTime = 0;
    this.lastConnectAttempt = 0;
    this._receiveBuffer = Buffer.alloc(0);
    this._destroyed = false;
    this._reconnectTimer = null;

    // Connect immediately
    this._ensureConnection();
  }

  isConnected() {
    return this.connected && this.socket !== null && !this.socket.destroyed;
  }

  isAvailable() {
    return this.available && this.isConnected();
  }

  getIdentifier() {
    return this.identifier;
  }

  getConnectTime() {
    return this.connectTime;
  }

  /**
   * Write raw binary data to the socket.
   * @param {Buffer} data - Binary Escher message
   * @returns {boolean} true if written successfully
   */
  write(data) {
    if (!this.isAvailable()) {
      return false;
    }
    try {
      this.socket.write(data);
      return true;
    } catch (err) {
      console.error(`[BeConnection ${this.identifier}] Write error:`, err.message);
      this._handleError();
      return false;
    }
  }

  /**
   * Close the connection and optionally reconnect.
   */
  close(reconnect = true) {
    this.available = false;
    this.connected = false;
    if (this.socket) {
      try {
        this.socket.removeAllListeners();
        this.socket.destroy();
      } catch (e) { /* ignore */ }
      this.socket = null;
    }
    if (reconnect && !this._destroyed) {
      this._scheduleReconnect();
    }
  }

  /**
   * Permanently destroy this connection (no reconnect).
   */
  destroy() {
    this._destroyed = true;
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    this.close(false);
  }

  /**
   * Send a heartbeat if connected and available.
   */
  doHeartbeat() {
    if (!this.isConnected()) {
      this._ensureConnection();
      return;
    }
    if (this.isAvailable()) {
      // Send HTBT message
      const htbtMsg = { 'TYPE': 'HTBT', 'HEAD': {}, 'BODY': {} };
      try {
        const encoded = codec.encodeMap(htbtMsg);
        this.socket.write(encoded);
      } catch (err) {
        console.error(`[BeConnection ${this.identifier}] Heartbeat error:`, err.message);
      }
    }
  }

  // ---- Private methods ----

  _ensureConnection() {
    if (this._destroyed) return;
    if (this.isConnected()) return;

    this.lastConnectAttempt = Date.now();

    console.log(`[BeConnection ${this.identifier}] Connecting...`);

    this.socket = new net.Socket();
    this.socket.setNoDelay(true);

    this.socket.on('connect', () => this._onConnect());
    this.socket.on('data', (data) => this._onData(data));
    this.socket.on('error', (err) => {
      console.error(`[BeConnection ${this.identifier}] Socket error:`, err.message);
      this._handleError();
    });
    this.socket.on('close', () => {
      console.log(`[BeConnection ${this.identifier}] Connection closed`);
      this._handleError();
    });

    this.socket.connect(this.port, this.ip);
  }

  _onConnect() {
    console.log(`[BeConnection ${this.identifier}] Connected, sending BEG handshake`);
    this.connected = true;
    this.connectTime = Date.now();

    // Send BEG (Begin) handshake message - matches C++ BeConnection::connected()
    const now = new Date();
    const unixSec = Math.floor(now.getTime() / 1000);
    const usec = (now.getTime() % 1000) * 1000;

    const begMsg = {
      'TYPE': 'BEG ',
      'ACTN': 'REQ ',
      'HEAD': {
        'SVID': this.engineID,
        'CMID': 0,
        'DATE': `~date:${unixSec}`,
        'USEC': usec,
        'VER ': 1
      },
      'BODY': {
        'NAME': this.clientName
      }
    };

    try {
      const encoded = codec.encodeMap(begMsg);
      this.socket.write(encoded);
    } catch (err) {
      console.error(`[BeConnection ${this.identifier}] BEG handshake write failed:`, err.message);
      this.close();
    }
  }

  _onData(data) {
    // Accumulate data in buffer
    this._receiveBuffer = Buffer.concat([this._receiveBuffer, data]);

    // Process complete messages
    while (this._receiveBuffer.length >= 2) {
      const msgLen = this._receiveBuffer.readUInt16BE(0);
      if (msgLen === 0) {
        // Invalid map length, drop it or handle error
        break;
      }

      // Check for extended map format (0xFFFE)
      if (msgLen === 0xFFFE) {
        if (this._receiveBuffer.length < 8) break; // Need extended header
        
        const extLen = this._receiveBuffer.readUInt32BE(4);
        if (this._receiveBuffer.length < extLen) break; // wait for more data
        
        const msgBuf = this._receiveBuffer.subarray(0, extLen);
        this._receiveBuffer = this._receiveBuffer.subarray(extLen);
        this._processMessage(msgBuf);
        continue;
      }

      // Standard map length
      if (this._receiveBuffer.length < msgLen) break; // wait for more data

      const msgBuf = this._receiveBuffer.subarray(0, msgLen);
      this._receiveBuffer = this._receiveBuffer.subarray(msgLen);
      this._processMessage(msgBuf);
    }
  }

  _processMessage(msgBuf) {
    if (!this.available) {
      // First message after connect should be BEG_ACK
      console.log(`[BeConnection ${this.identifier}] Received BEG_ACK, connection available`);
      this.available = true;
      this.emit('available');
      return;
    }

    // Check for heartbeat response
    try {
      const decoded = codec.decodeMap(msgBuf, false);
      if (decoded['TYPE'] === 'HTBT') {
        // Heartbeat response - ignore
        return;
      }
    } catch (e) {
      // Not a valid decode, pass through anyway
    }

    // Emit the raw message for the billing engine to process
    this.emit('message', msgBuf);
  }

  _handleError() {
    const wasAvailable = this.available;
    this.close(true); // will schedule reconnect
    if (wasAvailable) {
      this.emit('error_disconnect');
    }
  }

  _scheduleReconnect() {
    if (this._reconnectTimer) return;
    if (this._destroyed) return;
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      this._ensureConnection();
    }, this.connectionRetryMs);
  }
}

module.exports = BeConnection;
