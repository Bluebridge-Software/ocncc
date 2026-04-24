# OCNCC Telco AI Platform

**Version:** 1.0.0  
**© COPYRIGHT:** Blue Bridge Software Ltd - 2026  
**Author:** Tony Craven

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Directory Structure](#directory-structure)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Environment Variables](#environment-variables)
7. [Platform Configuration (platform.config.yaml)](#platform-configuration)
8. [Starting and Stopping](#starting-and-stopping)
9. [Gateway: Auth, Routing, and Security](#gateway-auth-routing-and-security)
10. [MCP Servers](#mcp-servers)
11. [OCS Adapters](#ocs-adapters)
12. [Role-Based Access Control](#role-based-access-control)
13. [External Agent Integration](#external-agent-integration)
14. [LiteLLM + Open WebUI Setup](#litellm--open-webui-setup)
15. [Extension Guide](#extension-guide)
    - [Adding a New OCS (e.g. Matrixx)](#adding-a-new-ocs)
    - [Adding a New Role](#adding-a-new-role)
    - [Adding a New MCP Server Type](#adding-a-new-mcp-server-type)
16. [Database Schema](#database-schema)
17. [Security Reference](#security-reference)
18. [Troubleshooting](#troubleshooting)

---

## Overview

The OCNCC Telco AI Platform is a pluggable, production-ready MCP (Model Context Protocol) platform that exposes telecom OCS (Online Charging System) capabilities to AI agents via a secure, role-governed gateway.

Three distinct domains are served:

| Domain | Audience | Interaction | Write ops |
|---|---|---|---|
| **Customer Care** | Human care agents | Natural language chat | Two-phase confirm |
| **BSS Analytics** | Human BSS analysts | Query + analysis | Read-only |
| **OSS Operations** | Human operators + machine agents | Chat + automation | Two-phase / direct |

The OCS layer is fully pluggable — swapping from OCNCC to Matrixx or BRM is a one-line config change with no code modifications.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  CONSUMER LAYER                                                      │
│  Open WebUI (Care)    Open WebUI (BSS)    Machine Agent (OSS)       │
└──────────┬──────────────────┬────────────────────┬───────────────────┘
           │ Bearer JWT        │ Bearer JWT          │ mTLS cert
           │ role=CARE         │ role=BSS            │ role=OSS_MACHINE
           ▼                  ▼                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│  MCP GATEWAY  (mcp-gateway.js)  :4001  — single external ingress    │
│  • JWT / mTLS validation                                            │
│  • Role → allowed MCP servers lookup (platform.config.yaml)        │
│  • Token swap: consumer JWT → MCP server API key                   │
│  • Identity header injection: x-gateway-agent-id, x-gateway-role  │
│  • Rate limiting, structured audit log                             │
└──────┬────────────────────┬──────────────────────┬──────────────────┘
       │ 127.0.0.1:3101     │ 127.0.0.1:3102       │ 127.0.0.1:3103
       ▼                    ▼                      ▼
┌───────────────┐  ┌────────────────┐  ┌───────────────────┐
│  care-mcp     │  │  bss-mcp       │  │  oss-mcp          │
│  Care tools   │  │  Analytics     │  │  Operations       │
│  + two-phase  │  │  read-only     │  │  + two-phase      │
└──────┬────────┘  └───────┬────────┘  └─────────┬─────────┘
       └──────────────────┬┘────────────────────┘
                          ▼
              ┌─────────────────────────┐
              │   OCS ADAPTER LAYER     │
              │  OcnccAdapter           │
              │  MatrixxAdapter (stub)  │
              │  BrmAdapter (stub)      │
              │  MockAdapter            │
              └─────────────┬───────────┘
                            ▼
              Oracle OCNCC / Matrixx / BRM
```

**Security property:** All MCP servers bind to `127.0.0.1` only. They are unreachable without going through the gateway. The gateway is the sole external-facing process.

---

## Directory Structure

```
./apiServer/src/
├── server.js                              ← existing REST API (unchanged)
├── mcp-gateway.js                         ← gateway: auth, routing, proxy
│
├── mcp/
│   ├── servers/
│   │   ├── care-mcp-server.js             ← Customer Care tools
│   │   ├── bss-mcp-server.js              ← BSS Analytics tools
│   │   └── oss-mcp-server.js              ← OSS Operations tools
│   │
│   ├── adapters/
│   │   ├── ocs-adapter-interface.js       ← abstract contract
│   │   ├── adapter-factory.js             ← resolves type → class
│   │   ├── ocncc-adapter.js               ← Oracle OCNCC implementation
│   │   ├── matrixx-adapter.js             ← Matrixx stub
│   │   ├── brm-adapter.js                 ← BRM stub
│   │   └── mock-adapter.js                ← in-memory fixtures
│   │
│   └── shared/
│       ├── mcp-utils.js                   ← audit, tokens, Express bootstrap
│       └── config-loader.js               ← YAML loader + env resolution
│
├── config/
│   └── platform.config.yaml              ← declarative platform wiring
│
├── database/                             ← existing (unchanged)
├── services/                             ← existing (unchanged)
└── ecosystem.config.js                   ← PM2 process definitions
```

---

## Prerequisites

- Node.js 20+
- Oracle Instant Client (shared with existing server.js)
- PM2: `npm install -g pm2`
- Python 3.9+ (for LiteLLM)
- Docker (optional, for Open WebUI)
- Redis (optional, recommended for caching)

---

## Installation

### 1. Install new Node dependencies

```bash
cd apiServer
npm install @modelcontextprotocol/sdk zod express \
            jsonwebtoken http-proxy express-rate-limit js-yaml
```

### 2. Place files

Copy all platform files into `apiServer/src/` following the directory structure above.

### 3. Create `.env` additions

Add the new variables (see [Environment Variables](#environment-variables)).

### 4. Create audit tables in Oracle

Run the DDL in [Database Schema](#database-schema).

### 5. Verify config loads

```bash
cd apiServer
node -e "require('./src/mcp/shared/config-loader').loadConfig(); console.log('Config OK')"
```

---

## Environment Variables

Add to `apiServer/.env`:

```env
# ── Gateway ────────────────────────────────────────────────────────
GATEWAY_JWT_SECRET=<node -e "console.log(require('crypto').randomBytes(48).toString('hex'))">
GATEWAY_PORT=4001

# ── MCP Server keys ────────────────────────────────────────────────
CARE_MCP_API_KEY=<generate>
CARE_MCP_TOKEN_SECRET=<generate — min 32 chars>
BSS_MCP_API_KEY=<generate>
OSS_MCP_API_KEY=<generate>
OSS_MCP_TOKEN_SECRET=<generate>

# ── Oracle (existing) ──────────────────────────────────────────────
ORACLE_USER=your_user
ORACLE_PASSWORD=your_password
ORACLE_SMF_SERVICE=(DESCRIPTION=...)

# ── Oracle staging (optional) ──────────────────────────────────────
ORACLE_STAGING_USER=
ORACLE_STAGING_PASSWORD=
ORACLE_STAGING_SERVICE=

# ── Redis ──────────────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379

# ── Client credentials (for /gateway/token endpoint) ──────────────
# Format: CLIENT_SECRET_{CLIENT_ID_UPPERCASE}
CLIENT_SECRET_CARE_WEBUI=<secret for Open WebUI care instance>
CLIENT_SECRET_BSS_WEBUI=<secret for Open WebUI BSS instance>
CLIENT_SECRET_OSS_AUTOMATION=<secret for machine agent>

# ── LiteLLM ────────────────────────────────────────────────────────
ANTHROPIC_API_KEY=sk-ant-...
LITELLM_MASTER_KEY=<generate>

# ── Optional ───────────────────────────────────────────────────────
PLATFORM_CONFIG=/opt/ocncc/apiServer/src/config/platform.config.yaml
CONFIRM_TOKEN_TTL=120
```

**Generating secrets:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

## Platform Configuration

`src/config/platform.config.yaml` is the single source of truth for the platform topology. All `${VAR}` placeholders are resolved from environment variables at startup. The server **fails fast** if any referenced variable is unset.

### Sections

**`gateway`** — port, JWT secret, token expiry, rate limits.

**`ocs_adapters`** — one entry per OCS backend. Multiple adapters of the same type are supported (e.g. OCNCC prod + staging). Each has an `id`, `type`, and `config` block specific to that adapter type.

**`mcp_servers`** — one entry per MCP server. `ocs_adapter` references an adapter `id`. Each server gets its own `api_key` (used by the gateway to authenticate proxied requests). `limits` block configures safety guards (credit limits, session thresholds).

**`roles`** — one entry per access role. `allowed_mcp_servers` is the authorisation list — the gateway rejects any request where the role's list does not include the target server.

### Changing the OCS for a domain

To switch the Care MCP to use Matrixx instead of OCNCC:

```yaml
mcp_servers:
  - id: care
    type: care
    port: 3101
    api_key: ${CARE_MCP_API_KEY}
    token_secret: ${CARE_MCP_TOKEN_SECRET}
    ocs_adapter: matrixx_prod          # ← one line change
```

Restart `mcp-care`. No code changes. The Matrixx adapter must be fully implemented first (see [Adding a New OCS](#adding-a-new-ocs)).

---

## Starting and Stopping

### Start all processes

```bash
cd apiServer
pm2 start ecosystem.config.js
```

**Recommended startup order** (PM2 starts them in parallel — the gateway will retry proxy connections automatically):

1. `mcp-care`, `mcp-bss`, `mcp-oss` bind to localhost and start quickly
2. `mcp-gateway` starts and begins routing (MCP servers may not be ready for the first few seconds — the proxy retries)
3. `ocncc-api` starts independently

### Start individual processes

```bash
pm2 start ecosystem.config.js --only mcp-gateway
pm2 start ecosystem.config.js --only mcp-care
```

### Stop, restart, reload

```bash
pm2 stop mcp-care
pm2 restart mcp-care
pm2 reload mcp-gateway          # zero-downtime reload (single instance)
pm2 stop all
pm2 restart all
```

### Logs

```bash
pm2 logs mcp-care               # tail care MCP logs
pm2 logs mcp-gateway            # tail gateway logs (audit records here)
pm2 logs --lines 100            # last 100 lines from all processes
```

### Status

```bash
pm2 list
```

```
┌─────┬──────────────┬─────────┬──────┬───────────┬──────────┬────────┐
│ id  │ name         │ mode    │ ↺    │ status    │ cpu      │ mem    │
├─────┼──────────────┼─────────┼──────┼───────────┼──────────┼────────┤
│ 0   │ ocncc-api    │ fork    │ 0    │ online    │ 0%       │ 85mb   │
│ 1   │ mcp-gateway  │ fork    │ 0    │ online    │ 0%       │ 48mb   │
│ 2   │ mcp-care     │ fork    │ 0    │ online    │ 0%       │ 62mb   │
│ 3   │ mcp-bss      │ fork    │ 0    │ online    │ 0%       │ 58mb   │
│ 4   │ mcp-oss      │ fork    │ 0    │ online    │ 0%       │ 55mb   │
└─────┴──────────────┴─────────┴──────┴───────────┴──────────┴────────┘
```

### Persist across reboots

```bash
pm2 save
pm2 startup    # follow printed instructions
```

---

## Gateway: Auth, Routing, and Security

### URL structure

All external agent traffic goes to the gateway on a single port:

```
POST/GET http://gateway-host:4001/mcp/{serverId}/mcp
```

| serverId | Routes to |
|---|---|
| `care` | care-mcp-server :3101 |
| `bss`  | bss-mcp-server  :3102 |
| `oss`  | oss-mcp-server  :3103 |

### How routing works

1. Agent sends `Authorization: Bearer <JWT>` with request to `/mcp/care/mcp`
2. Gateway validates the JWT (HMAC-SHA256, issued by `/gateway/token`)
3. Gateway extracts the `role` claim from the token
4. Gateway looks up the role in `platform.config.yaml` roles[]
5. Gateway checks that `care` is in `role.allowed_mcp_servers[]`
6. Gateway **swaps the Authorization header**: replaces the consumer's JWT with the care MCP server's own `api_key`
7. Gateway injects identity headers: `x-gateway-agent-id`, `x-gateway-role`, `x-gateway-sub`
8. Gateway proxies the request to `http://127.0.0.1:3101/mcp`
9. Care MCP server validates its own API key (set by gateway) and processes the tool call
10. Gateway writes a structured audit log entry

### What each role can reach

| Role | MCP Servers | Write ops |
|---|---|---|
| CARE | care only | Two-phase confirm |
| CARE_SUPERVISOR | care only | Two-phase confirm (higher limits) |
| BSS | bss only | None (read-only) |
| OSS_HUMAN | oss only | Two-phase confirm |
| OSS_MACHINE | oss only | Full (no confirm step) |
| ADMIN | care, bss, oss | Full |

A CARE agent **cannot** reach `/mcp/bss/mcp` or `/mcp/oss/mcp` — the gateway returns 403 before the request touches those servers.

### Token issuance

For internal integrations (LiteLLM, scripts), the gateway issues JWTs:

```bash
curl -X POST http://gateway-host:4001/gateway/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id":     "care_webui",
    "client_secret": "your-care-webui-client-secret",
    "role":          "CARE",
    "agent_id":      "care.smith"
  }'
```

```json
{
  "access_token": "eyJ...",
  "token_type":   "Bearer",
  "expires_in":   28800
}
```

In production, replace `/gateway/token` with your SSO/OIDC provider's token endpoint. The gateway validates any JWT signed with `GATEWAY_JWT_SECRET` containing a `role` claim — the issuer is interchangeable.

### mTLS for machine agents

Machine agents (OSS_MACHINE) authenticate via client certificate. The gateway reads the peer certificate's CN as the agent identity, bypassing JWT entirely. Configure your TLS termination (nginx or Node.js `https.createServer`) to require and forward client certs.

---

## MCP Servers

Each MCP server is independent — it binds to `127.0.0.1` only and is unreachable except through the gateway.

### Health checks

```bash
# Internal health (no auth — direct to MCP server)
curl http://localhost:3101/health   # care
curl http://localhost:3102/health   # bss
curl http://localhost:3103/health   # oss

# Gateway health (no auth — checks all upstream servers)
curl http://localhost:4001/health
```

### Care MCP tools

| Tool | Type | Description |
|---|---|---|
| `get_subscriber` | Read | Full account + decoded profile |
| `get_balance` | Read | Balance, credit limit, last top-up |
| `get_transaction_history` | Read | Events last N days (max 90) |
| `get_topup_history` | Read | Top-up records last N days |
| `get_active_services` | Read | Decoded service flags |
| `get_billing_engine` | Read | OCS node assignment |
| `prepare_balance_adjustment` | Write Phase 1 | Validate, return token + summary |
| `confirm_balance_adjustment` | Write Phase 2 | Execute on agent confirmation |
| `prepare_service_state_change` | Write Phase 1 | Validate, return token + summary |
| `confirm_service_state_change` | Write Phase 2 | Execute on agent confirmation |
| `raise_ticket` | Write | Create care ticket |
| `invalidate_cache` | Util | Clear Redis cache |

### BSS MCP tools

| Tool | Type | Description |
|---|---|---|
| `revenue_query` | Read | Revenue by product/region/period |
| `product_performance` | Read | Subscribers, revenue, events by product |
| `arpu_query` | Read | ARPU by segment and period |
| `get_subscriber_bss` | Read | Account context (no profile decode) |
| `get_node_topology_bss` | Read | OCS topology for context |

### OSS MCP tools

| Tool | Type | Description |
|---|---|---|
| `get_node_kpis` | Read | KPI metrics for a node |
| `get_charging_error_rate` | Read | Error rate % for a node |
| `get_alarms` | Read | Active unacknowledged alarms |
| `get_node_topology_oss` | Read | Full node topology |
| `prepare_rebalance` | Write Phase 1 | Dry-run assessment + token |
| `confirm_rebalance` | Write Phase 2 | Execute with safety guard check |

---

## OCS Adapters

### Interface

All adapters implement `OcsAdapterInterface` (`mcp/adapters/ocs-adapter-interface.js`). The interface defines methods across four categories:

- **Lifecycle:** `initialise()`, `shutdown()`, `healthCheck()`
- **Subscriber:** `getSubscriber()`, `getBalance()`, `getTransactionHistory()`, `getTopupHistory()`, `getActiveServices()`, `applyBalanceAdjustment()`, `applyServiceStateChange()`
- **Network:** `getNodeTopology()`
- **Analytics:** `queryRevenue()`, `queryProductPerformance()`, `queryArpu()`
- **OSS:** `getNodeKpis()`, `getAlarms()`, `getChargingErrorRate()`, `triggerRebalance()`
- **Ticketing:** `raiseTicket()`
- **Cache:** `invalidateSubscriberCache()`, `invalidateReferenceCache()`

Methods that a given OCS does not support throw `NotImplementedError` (not a generic `Error`), allowing callers to detect capability gaps cleanly.

### Adapter status

| Adapter | Status | Notes |
|---|---|---|
| `OcnccAdapter` | Production | Full implementation using existing Oracle/BbsProfileBlock code |
| `MatrixxAdapter` | Stub | Interface-compliant; all methods throw until implemented |
| `BrmAdapter` | Stub | Interface-compliant; all methods throw until implemented |
| `MockAdapter` | Complete | In-memory fixtures; use for dev/test |

---

## Role-Based Access Control

Roles are defined in `platform.config.yaml`. The gateway enforces them — MCP servers themselves are not role-aware.

### Adding a role

```yaml
roles:
  - id: CARE_READONLY
    label: "Care QA / Auditor"
    allowed_mcp_servers: [care]
    auth_method: jwt
    write_operations: none
```

Restart `mcp-gateway`. No other changes needed.

### Issuing a token for the new role

```bash
# Add to .env:
CLIENT_SECRET_CARE_QA=<secret>

# Request token:
curl -X POST http://gateway-host:4001/gateway/token \
  -d '{ "client_id": "care_qa", "client_secret": "...", "role": "CARE_READONLY", "agent_id": "qa.jones" }'
```

---

## External Agent Integration

### Claude Code (local developer)

```json
// .claude/mcp.json
{
  "mcpServers": {
    "ocncc-care": {
      "type": "http",
      "url": "http://gateway-host:4001/mcp/care/mcp",
      "headers": { "Authorization": "Bearer <care-jwt>" }
    }
  }
}
```

### Open WebUI + LiteLLM (human agents)

LiteLLM sits between Open WebUI and the gateway:

```yaml
# litellm-config.yaml
model_list:
  - model_name: care-assistant
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/ANTHROPIC_API_KEY

mcp_servers:
  ocncc-care:
    url: http://localhost:4001/mcp/care/mcp
    headers:
      Authorization: "Bearer ${CARE_GATEWAY_TOKEN}"
```

Obtain `CARE_GATEWAY_TOKEN` via `/gateway/token` at LiteLLM startup.

### Machine agent (OSS automation)

```js
// Node.js agent example
const MCP_URL = 'http://gateway-host:4001/mcp/oss/mcp';
const TOKEN   = process.env.OSS_GATEWAY_TOKEN;  // role=OSS_MACHINE

async function callTool(name, args) {
    const res = await fetch(MCP_URL, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
        body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method: 'tools/call', params: { name, arguments: args } }),
    });
    const data = await res.json();
    return JSON.parse(data.result.content[0].text);
}

// Automated KPI check
const kpis = await callTool('get_node_kpis', { node_id: 351, metrics: ['session_count', 'error_rate'], window_seconds: 300, agent_id: 'oss-automation' });
if (kpis.data.find(k => k.STAT_NAME === 'error_rate' && k.STAT_VALUE > 5)) {
    const prep = await callTool('prepare_rebalance', { domain_id: 12, agent_id: 'oss-automation' });
    // post prep.confirmation_token to Slack/Teams for human approval
    // on approval webhook: await callTool('confirm_rebalance', { confirmation_token: ..., agent_id: 'oss-automation' })
}
```

---

## LiteLLM + Open WebUI Setup

### Install

```bash
pip install litellm[proxy]
docker run -d --name open-webui -p 3000:8080 \
  -e OPENAI_API_BASE_URL=http://host.docker.internal:4000/v1 \
  -e OPENAI_API_KEY=your-litellm-virtual-key \
  ghcr.io/open-webui/open-webui:main
```

### Start LiteLLM

```bash
litellm --config src/config/litellm-config.yaml --port 4000
```

### Create virtual keys per team

```bash
# Care team key
curl -X POST http://localhost:4000/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -d '{"models": ["care-assistant"], "metadata": {"team": "care"}}'

# BSS team key
curl -X POST http://localhost:4000/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -d '{"models": ["bss-assistant"], "metadata": {"team": "bss"}}'
```

Set each team's Open WebUI to use its respective virtual key — a BSS analyst's Open WebUI instance only sees `bss-assistant` and cannot reach care or OSS tools.

---

## Extension Guide

### Adding a New OCS

Example: making Matrixx production-ready.

**Step 1:** Implement `matrixx-adapter.js`

Replace every `throw new Error(...)` in `_mapiGet` / `_mapiPost` with real Matrixx API calls. Implement the field mappers (`_mapSubscriber`, `_mapBalance`, etc.) to translate Matrixx response shapes to the standard interface shape.

Run against MockAdapter first to validate your tool implementations, then swap to MatrixxAdapter and run integration tests.

**Step 2:** No changes to `adapter-factory.js` — Matrixx is already registered.

**Step 3:** Add to `platform.config.yaml`:

```yaml
ocs_adapters:
  - id: matrixx_prod
    type: matrixx
    config:
      base_url: ${MATRIXX_URL}
      api_key:  ${MATRIXX_API_KEY}
```

**Step 4:** Point an MCP server at it:

```yaml
mcp_servers:
  - id: care
    ocs_adapter: matrixx_prod    # ← changed from ocncc_prod
```

**Step 5:** Restart `mcp-care`. Done.

---

### Adding a New Role

1. Add the role to `platform.config.yaml`:

```yaml
roles:
  - id: CARE_SUPERVISOR
    label: "Care Supervisor"
    allowed_mcp_servers: [care]
    auth_method: jwt
    write_operations: two_phase
    limits:
      max_credit_gbp: 500.00
```

2. Add client credentials to `.env`:

```env
CLIENT_SECRET_CARE_SUPERVISOR_WEBUI=<secret>
```

3. Restart `mcp-gateway`.

4. Issue tokens for this role via `/gateway/token`.

No code changes.

---

### Adding a New MCP Server Type

Example: a Fraud Detection MCP server.

**Step 1:** Create `src/mcp/servers/fraud-mcp-server.js`

Use `care-mcp-server.js` as a template. Pick up config via:

```js
const srvCfg = config._mcpServerById['fraud'];
```

Implement your tools, delegating to the adapter.

**Step 2:** Add to `platform.config.yaml`:

```yaml
mcp_servers:
  - id: fraud
    type: fraud
    port: 3104
    api_key: ${FRAUD_MCP_API_KEY}
    ocs_adapter: ocncc_prod
```

**Step 3:** Add a role:

```yaml
roles:
  - id: FRAUD
    allowed_mcp_servers: [fraud]
    auth_method: jwt
    write_operations: two_phase
```

**Step 4:** Add to `ecosystem.config.js`:

```js
{
  ...COMMON,
  name:   'mcp-fraud',
  script: 'src/mcp/servers/fraud-mcp-server.js',
}
```

**Step 5:** `pm2 start ecosystem.config.js --only mcp-fraud && pm2 restart mcp-gateway`

---

## Database Schema

```sql
-- Care tool call audit (used by all care write tools)
CREATE TABLE care_audit_log (
    log_id        NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id      VARCHAR2(100)  NOT NULL,
    tool_name     VARCHAR2(100)  NOT NULL,
    cli           VARCHAR2(20),
    input_summary VARCHAR2(500),
    outcome       VARCHAR2(20)   NOT NULL,
    detail        VARCHAR2(1000),
    created_at    DATE           NOT NULL
);
CREATE INDEX ix_care_audit_cli     ON care_audit_log (cli);
CREATE INDEX ix_care_audit_agent   ON care_audit_log (agent_id);
CREATE INDEX ix_care_audit_created ON care_audit_log (created_at);

-- Balance adjustment execution log
CREATE TABLE care_balance_adjustments (
    adj_id       NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cli          VARCHAR2(20)  NOT NULL,
    amount_pence NUMBER        NOT NULL,
    reason       VARCHAR2(200) NOT NULL,
    agent_id     VARCHAR2(100) NOT NULL,
    applied_at   DATE          NOT NULL
);
CREATE INDEX ix_care_bal_cli ON care_balance_adjustments (cli);

-- Care tickets
CREATE TABLE care_tickets (
    ticket_id  NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cli        VARCHAR2(20)   NOT NULL,
    category   VARCHAR2(20)   NOT NULL,
    priority   VARCHAR2(10)   NOT NULL,
    notes      VARCHAR2(2000),
    agent_id   VARCHAR2(100)  NOT NULL,
    status     VARCHAR2(20)   DEFAULT 'OPEN' NOT NULL,
    created_at DATE           NOT NULL,
    updated_at DATE
);
CREATE INDEX ix_care_ticket_cli    ON care_tickets (cli);
CREATE INDEX ix_care_ticket_status ON care_tickets (status);
```

---

## Security Reference

| Concern | Mechanism |
|---|---|
| External exposure | Only gateway (:4001) has a public port. All MCP servers bind to 127.0.0.1 |
| Authentication | HMAC-SHA256 JWT (human) or mTLS client cert (machine) |
| Authorisation | Role → `allowed_mcp_servers[]` enforced at gateway before proxy |
| Token forgery | `timingSafeEqual` for all token comparisons |
| Replay attacks | Confirmation tokens include nonce + 120s expiry |
| Balance limits | Hard limits in adapter + platform.config.yaml `limits` block |
| Write safety | Two-phase confirm for all human write operations |
| Network write risk (OSS) | Session count safety guard; dry_run default |
| Audit | Every tool call logged to `care_audit_log` with agent identity |
| Sensitive params in logs | Input summaries logged, not raw values (no passwords, no balances) |
| TLS | Terminate at nginx in front of gateway; use HTTPS for all external traffic |

### nginx TLS reverse proxy

```nginx
server {
    listen 443 ssl;
    server_name mcp.yourdomain.internal;

    ssl_certificate     /etc/ssl/certs/mcp.crt;
    ssl_certificate_key /etc/ssl/private/mcp.key;

    location / {
        proxy_pass          http://127.0.0.1:4001;
        proxy_http_version  1.1;
        proxy_set_header    Host $host;
        proxy_set_header    X-Real-IP $remote_addr;
        proxy_read_timeout  300s;    # required for SSE streams
    }
}
```

---

## Troubleshooting

### Gateway returns 403 for a valid agent

Check: does the agent's JWT `role` claim match exactly the role `id` in `platform.config.yaml`? Role IDs are case-sensitive. Decode the JWT at jwt.io to inspect claims.

### MCP server not reachable from gateway

```bash
# Verify MCP server is listening on localhost only
lsof -i :3101 | grep LISTEN
# Should show: node  <pid>  <user>  TCP 127.0.0.1:3101 (LISTEN)
curl http://localhost:3101/health
```

If the process is not running: `pm2 logs mcp-care --lines 50`

### Confirmation token expired

Re-run the `prepare_*` step. Increase `CONFIRM_TOKEN_TTL` in `.env` if agents consistently need more than 2 minutes.

### Config validation fails at startup

```
[Config] Invalid platform.config.yaml:
  ocs_adapters[0].type is required
```

Check `platform.config.yaml` for the flagged field. Also verify all `${ENV_VAR}` references have corresponding entries in `.env`.

### Oracle pool conflict between MCP servers

Each adapter instance uses a unique `poolAlias` (`ocncc_<adapterId>`). If two adapters share the same `id`, they will clash. Ensure all adapter `id` values in `platform.config.yaml` are unique.

### `NotImplementedError` from a stub adapter

A stub adapter (Matrixx, BRM) was configured as the OCS for an MCP server, but the corresponding method hasn't been implemented yet. Use `MockAdapter` for development until the stub is production-ready.
