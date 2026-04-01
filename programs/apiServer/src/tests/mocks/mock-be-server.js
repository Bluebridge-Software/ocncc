/**
 * OCNCC Mock Billing Engine Server (Escher Protocol)
 * For integration testing of the BBS OCNCC BE Client.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

const net = require('net');
const codec = require('../../codecs/escher-codec');

class MockBeServer {
  constructor(port = 1500, options = {}) {
    this.port = port;
    this.options = options;
    this.server = null;
    this.clients = new Set();
    this.responses = new Map(); // CMID -> Response JSON
    this.typeResponses = new Map(); // TYPE -> Response JSON (Default)
  }

  /**
   * Start the mock server.
   */
  start() {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => {
        console.log(`[MockServer] New connection from ${socket.remoteAddress}:${socket.remotePort}`);
        this.clients.add(socket);

        let buffer = Buffer.alloc(0);

        socket.on('data', (data) => {
          buffer = Buffer.concat([buffer, data]);

          while (buffer.length >= 4) {
            const length = buffer.readUInt32BE(0);
            if (buffer.length < length) break; // Incomplete message

            const messageBuffer = buffer.slice(0, length);
            buffer = buffer.slice(length);

            this._handleMessage(socket, messageBuffer);
          }
        });

        socket.on('close', () => {
          console.log('[MockServer] Connection closed');
          this.clients.delete(socket);
        });

        socket.on('error', (err) => {
          console.error('[MockServer] Socket error:', err.message);
        });
      });

      this.server.listen(this.port, 'localhost', () => {
        console.log(`[MockServer] Listening on localhost:${this.port}`);
        resolve();
      });

      this.server.on('error', (err) => {
        console.error('[MockServer] Server error:', err);
        reject(err);
      });
    });
  }

  /**
   * Stop the mock server.
   */
  stop() {
    return new Promise((resolve) => {
      for (const client of this.clients) {
        client.destroy();
      }
      this.server.close(() => {
        console.log('[MockServer] Server stopped');
        resolve();
      });
    });
  }

  /**
   * Set a specific response for a specific CMID.
   */
  setResponse(cmid, response) {
    this.responses.set(cmid, response);
  }

  /**
   * Set a default response for a message type.
   */
  setDefaultResponse(type, response) {
    this.typeResponses.set(type, response);
  }

  /**
   * Local handler for incoming messages.
   */
  _handleMessage(socket, buffer) {
    try {
      const decoded = codec.decodeMap(buffer);
      const action = decoded['ACTN'];
      const type = decoded['TYPE'];
      const head = decoded['HEAD'] || {};
      const cmid = head['CMID'];

      console.log(`[MockServer] Received ${action} ${type} (CMID: ${cmid})`);

      // 1. BEG Handshake handling
      if (type === 'BEG ') {
        this._sendResponse(socket, {
          'ACTN': 'ACK ',
          'TYPE': 'BEG ',
          'HEAD': { 'CMID': cmid, 'SVID': 1 }
        });
        return;
      }

      // 2. HTBT Heartbeat handling
      if (type === 'HTBT') {
        this._sendResponse(socket, {
          'ACTN': 'ACK ',
          'TYPE': 'HTBT',
          'HEAD': { 'CMID': cmid, 'SVID': 1 }
        });
        return;
      }

      // 3. Custom responses
      let response = this.responses.get(cmid);
      if (!response) {
        response = this.typeResponses.get(type);
      }

      // 4. Fallback default ACK
      if (!response) {
        response = {
          'ACTN': 'ACK ',
          'TYPE': type,
          'HEAD': { 'CMID': cmid, 'SVID': 1 },
          'BODY': { 'STAT': 'ACTV' }
        };
      }

      // Ensure response has the correct CMID
      if (response && response['HEAD']) {
        response['HEAD']['CMID'] = cmid;
      }

      this._sendResponse(socket, response);

    } catch (err) {
      console.error('[MockServer] Decoding error:', err.message);
    }
  }

  _sendResponse(socket, json) {
    try {
      const encoded = codec.encodeMap(json);
      socket.write(encoded);
      console.log(`[MockServer] Sent ACK ${json['TYPE']} (CMID: ${json['HEAD']['CMID']})`);
    } catch (err) {
      console.error('[MockServer] Encoding error:', err.message);
    }
  }
}

module.exports = MockBeServer;
