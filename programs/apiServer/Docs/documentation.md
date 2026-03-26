# BBS OCNCC Billing Engine Client Documentation

## Overview
The BBS OCNCC Billing Engine Client is a high-performance, concurrent Node.js service designed to interface with the Oracle OCNCC Billing Engine using the **Escher binary protocol**. It exposes a modern RESTful API that abstracts the complexities of the binary protocol, providing primary/secondary failover, congestion control, and robust security.

---

## 🏗️ Architecture

The service is built on a modular architecture that mirrors the core logic of the OCNCC C++ interfaces:

- **REST API Gateway (Express):** Exposes JSON endpoints for all OCNCC message types.
- **`BeClient`:** Orchestrates routing across multiple billing engine clusters.
- **`BillingEngine`:** Manages primary and secondary connection pairs with automatic failover and priority routing.
- **`BeConnection`:** Handles low-level TCP socket state, including the `BEG` handshake and `HTBT` heartbeats.
- **`EscherCodec`:** A high-speed binary encoder/decoder that handles the Escher Tag-Length-Value (TLV) format.
- **`StatsTracker`:** Aggregates real-time metrics (success, failure, unauthorised) with optional Redis persistence.
- **`AlertManager`:** Triggers instantaneous security alerts via Syslog and SNMP.

---

## ⚙️ Configuration

Configuration is managed via environment variables (typically in a `.env` file) and `config.js`.

### Key Environment Variables
| Variable | Description | Default |
| :--- | :--- | :--- |
| `BE_PORT` | Port for the REST API | `3010` |
| `BE_HOST` | Host to bind the API to | `localhost` |
| `BE_ENGINES` | Comma-separated engine definitions: `ID:P_IP:P_PORT:S_IP:S_PORT` | - |
| `BE_JWT_ENABLED` | Toggle JWT authentication | `true` |
| `BE_JWT_SECRET` | Secret key for signing tokens | (Set in .env) |
| `BE_REDIS_ENABLED` | Enable Redis for stats persistence | `false` |
| `BE_SYSLOG_ENABLED` | Enable Syslog alerting | `false` |
| `BE_SNMP_ENABLED` | Enable SNMP trap alerting | `false` |

### Billing Engine Format
Engines are defined as: `ID:PrimaryIP:PrimaryPort[:SecondaryIP:SecondaryPort]`
Example: `1:10.0.0.1:1500:10.0.0.2:1500,2:10.0.0.3:1500`

---

## 🔐 Security & Authentication

The API is protected by **scoped JWT tokens**. Each client is issued a token containing a `clientId` and an `allowedEndpoints` array.

### Token Scoping
- `*`: Access to all endpoints.
- `['/wallet-info', '/stats']`: Restricted to specific calls.

### Fraud Detection
The system automatically monitors for:
- **Unauthorised API access attempts** (missing or invalid tokens).
- **Endpoint limit violations** (valid tokens trying to hit restricted routes).
- Alerts are dispatched to **Syslog** and **SNMP** upon detection.

### Generating Tokens
Use the included CLI tool:
```bash
node generate-token.js client-definition.json
```
Client definitions update the `auth-tokens.json` master database automatically.

---

## 📊 Monitoring & Alerts

### Statistics API
Endpoint: `GET /api/stats?hours=24`
Returns a JSON breakdown of:
- Total call volume.
- Failures and timeout counts.
- Unauthorised access attempts by IP/Client.
- Usage per endpoint and per Billing Engine ID.

### Alerting Channels
1. **Syslog:** Critical security events are logged to the configured Syslog host (Local0).
2. **SNMP:** V2 Traps are sent using BBS Enterprise OIDs:
   - `1.3.6.1.4.1.99999.1.1`: Alert Type
   - `1.3.6.1.4.1.99999.1.2`: Description
   - `1.3.6.1.4.1.99999.1.3`: Client ID

---

## 🚀 API Integration

### Swagger Documentation
Interactive documentation is available at `/api-docs`. You can test endpoints directly from the browser using "Try it out".

### Data Formats
The API supports two JSON representations:
1. **Raw Format:** Uses protocol-level symbols (e.g., `SVID`, `CMID`).
2. **Friendly Format:** Uses human-readable labels (e.g., `BE Server ID`, `Client Message ID`).

### Request Parameters
| Parameter | Default | Description |
| :--- | :--- | :--- |
| `billingEngineId` | - | Target a specific engine ID. |
| `preferredEngine` | `primary` | Choose `primary` or `secondary` (falls back if one is down). |
| `format` | `raw` | Response output format: `raw` or `friendly`. |

---

## 🛠️ Developer Guide

### Prerequisites
- Node.js 18+
- (Optional) Redis server for distributed statistics.

### Setup
1. `npm install`
2. Create `.env` based on `.env.example`.
3. Start the server: `node server.js`

### Running Tests
- **Codec Roundtrip:** `node test-codec.js`
- **Security Check:** `node test-security.js`
- **Frontend/Integration Example:** `node example-integration.js`
