/**
 * OCNCC Billing Engine Alert Manager.
 * Handles triggering alerts via Syslog and SNMP when anomalies occur.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const syslog = require('syslog-client');
const snmp = require('net-snmp');

class AlertManager {
  constructor(config) {
    this.config = config;
    this.syslogClient = null;
    this.snmpSession = null;

    if (config.get('syslogEnabled')) {
      const options = {
        syslogHostname: 'bbs-ocncc-be',
        port: config.get('syslogPort') || 514
      };
      this.syslogClient = syslog.createClient(config.get('syslogHost'), options);
      console.log(`[AlertManager] Syslog enabled: ${config.get('syslogHost')}:${options.port}`);
    }

    if (config.get('snmpEnabled')) {
      const options = {
        port: config.get('snmpPort') || 162,
        community: config.get('snmpCommunity') || 'public',
        version: snmp.Version2c
      };
      // SNMP Traps usually don't need a persistent session in simple cases, 
      // but net-snmp library uses sessions for targets.
      this.snmpTarget = config.get('snmpHost');
      this.snmpOptions = options;
      console.log(`[AlertManager] SNMP alerts enabled: ${this.snmpTarget}:${options.port}`);
    }
  }

  /**
   * Trigger a security alert (Fraud / Cyber Attack detection)
   */
  async triggerSecurityAlert(type, details) {
    const message = `[SECURITY_ALERT] Type: ${type} | Client: ${details.clientId || 'unknown'} | IP: ${details.ip || 'unknown'} | Reason: ${details.reason || 'Unauthorised'}`;

    console.warn(`\x1b[31m${message}\x1b[0m`);

    // 1. Syslog Alert
    if (this.syslogClient) {
      this.syslogClient.log(message, {
        severity: syslog.Severity.Critical,
        facility: syslog.Facility.Local0
      }, (error) => {
        if (error) console.error('[AlertManager] Syslog error:', error.message);
      });
    }

    // 2. SNMP Trap Alert
    if (this.config.get('snmpEnabled')) {
      this._sendSnmpTrap(type, message, details);
    }
  }

  _sendSnmpTrap(type, message, details) {
    // Simple V2 Trap
    // Enterprise OID for BBS OCNCC (Example OID)
    const enterpriseOid = "1.3.6.1.4.1.99999.1";

    // Varbinds for the trap
    const varbinds = [
      {
        oid: "1.3.6.1.4.1.99999.1.1", // Alert Type
        type: snmp.ObjectType.OctetString,
        value: type
      },
      {
        oid: "1.3.6.1.4.1.99999.1.2", // Alert Description
        type: snmp.ObjectType.OctetString,
        value: message
      },
      {
        oid: "1.3.6.1.4.1.99999.1.3", // Client ID
        type: snmp.ObjectType.OctetString,
        value: details.clientId || 'unknown'
      }
    ];

    const session = snmp.createSession(this.snmpTarget, this.snmpOptions.community, { port: this.snmpOptions.port });

    session.trap(enterpriseOid, varbinds, (error) => {
      if (error) {
        console.error('[AlertManager] SNMP Trap error:', error.message);
      }
      session.close();
    });
  }

  destroy() {
    if (this.syslogClient) {
      this.syslogClient.close();
    }
  }
}

module.exports = AlertManager;
