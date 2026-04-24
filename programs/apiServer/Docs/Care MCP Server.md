# OCNCC Customer Care AI Platform

**Service:** `ocncc-care`  
**Version:** 1.0.0  
**Stack:** care-mcp-server.js → LiteLLM → Open WebUI  
**© COPYRIGHT:** Blue Bridge Software Ltd - 2026  
**Author:** Tony Craven

---

## Table of Contents

1. [Overview](#overview)
2. [Full Stack Architecture](#full-stack-architecture)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Environment Variables](#environment-variables)
6. [Database Schema — Audit Tables](#database-schema--audit-tables)
7. [Starting the Stack](#starting-the-stack)
8. [PM2 Process Management](#pm2-process-management)
9. [Available Tools](#available-tools)
10. [Two-Phase Write Pattern](#two-phase-write-pattern)
11. [Example Care Agent Sessions](#example-care-agent-sessions)
12. [Open WebUI Configuration](#open-webui-configuration)
13. [LiteLLM Configuration Notes](#litellm-configuration-notes)
14. [Security](#security)
15. [Extending to BSS and OSS](#extending-to-bss-and-oss)
16. [Troubleshooting](#troubleshooting)

---

## Overview

The OCNCC Customer Care AI Platform allows care agents to interact with live subscriber data using natural language. Instead of navigating multiple systems, an agent types a question into a chat interface and receives a direct, accurate answer pulled from Oracle OCNCC in real time.

Write operations (balance adjustments, service state changes) use a **two-phase confirmation pattern** — the AI presents a human-readable summary of what will happen and waits for explicit agent confirmation before executing.

All tool calls are written to an Oracle audit table for compliance and QA purposes.

---

## Full Stack Architecture

```
Care Agent Browser
        │
        │  HTTPS
        ▼
┌───────────────────┐
│   Open WebUI      │  Chat interface — presents conversation to agent
│   :3000           │  Configured to use LiteLLM as its API backend
└────────┬──────────┘
         │  OpenAI-compatible chat completion API
         │  POST /v1/chat/completions
         ▼
┌───────────────────┐
│   LiteLLM         │  Gateway — routes to LLM, handles MCP tool calls
│   :4000           │  Injects system prompt, enforces rate limits
└────────┬──────────┘
         │                    │
         │ Anthropic API      │ MCP HTTP/SSE
         ▼                    ▼
  Claude Sonnet 4.6    ┌──────────────────┐
                       │  care-mcp-server  │
                       │  :3101            │
                       └────────┬──────────┘
                                │
                     ┌──────────┴──────────┐
                     ▼                     ▼
              Oracle OCNCC DB        Redis Cache
              (read + write)         (30s TTL)
```

---

## Prerequisites

- Node.js 20+
- Python 3.9+ (for LiteLLM)
- Oracle Instant Client (shared with `server.js`)
- Redis (optional but recommended)
- Docker (optional — for Open WebUI)
- PM2: `npm install -g pm2`
- Anthropic API key

---

## Installation

### 1. Place the MCP server

```
./apiServer/src/care-mcp-server.js
```

### 2. Install Node dependencies

```bash
cd apiServer
npm install @modelcontextprotocol/sdk zod express
```

### 3. Install LiteLLM

```bash
pip install litellm[proxy] langfuse   # langfuse optional — remove if not using
```

### 4. Install Open WebUI (Docker — recommended)

```bash
docker run -d \
  --name open-webui \
  -p 3000:8080 \
  -e OPENAI_API_BASE_URL=http://host.docker.internal:4000/v1 \
  -e OPENAI_API_KEY=your-litellm-virtual-key \
  -v open-webui:/app/backend/data \
  ghcr.io/open-webui/open-webui:main
```

Or without Docker:
```bash
pip install open-webui
open-webui serve --port 3000
```

---

## Environment Variables

Add these to `apiServer/.env`:

```env
# --- Existing Oracle vars ---
ORACLE_USER=your_db_user
ORACLE_PASSWORD=your_db_password
ORACLE_SMF_SERVICE=(DESCRIPTION=...)

# --- Care MCP Server ---
CARE_MCP_PORT=3101
CARE_MCP_API_KEY=<generate: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))">
CARE_MCP_TOKEN_SECRET=<generate: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))">

# Hard limits for balance adjustments (GBP)
CARE_MAX_CREDIT_GBP=50.00
CARE_MAX_DEBIT_GBP=50.00

# --- LiteLLM ---
ANTHROPIC_API_KEY=sk-ant-...
LITELLM_MASTER_KEY=<generate a strong secret>
LITELLM_DATABASE_URL=postgresql://user:pass@localhost/litellm   # optional

# MCP URLs (for litellm-config.yaml)
CARE_MCP_URL=http://localhost:3101/mcp
ORACLE_MCP_URL=http://localhost:3100/mcp
ORACLE_MCP_API_KEY=<your ocncc-oracle MCP key>

# Redis
REDIS_HOST=localhost
REDIS_PASSWORD=
```

---

## Database Schema — Audit Tables

Run these DDL statements in Oracle before starting the care MCP server.

```sql
-- Care tool call audit log
CREATE TABLE care_audit_log (
    log_id          NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id        VARCHAR2(100)  NOT NULL,
    tool_name       VARCHAR2(100)  NOT NULL,
    cli             VARCHAR2(20),
    input_summary   VARCHAR2(500),
    outcome         VARCHAR2(20)   NOT NULL,  -- SUCCESS, ERROR, PREPARED, EXECUTED
    detail          VARCHAR2(1000),
    created_at      DATE           NOT NULL
);

CREATE INDEX ix_care_audit_cli      ON care_audit_log (cli);
CREATE INDEX ix_care_audit_agent    ON care_audit_log (agent_id);
CREATE INDEX ix_care_audit_created  ON care_audit_log (created_at);

-- Balance adjustment execution log
CREATE TABLE care_balance_adjustments (
    adj_id          NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cli             VARCHAR2(20)   NOT NULL,
    amount_pence    NUMBER         NOT NULL,
    reason          VARCHAR2(200)  NOT NULL,
    agent_id        VARCHAR2(100)  NOT NULL,
    applied_at      DATE           NOT NULL
);

CREATE INDEX ix_care_bal_cli  ON care_balance_adjustments (cli);

-- Care tickets
CREATE TABLE care_tickets (
    ticket_id       NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cli             VARCHAR2(20)   NOT NULL,
    category        VARCHAR2(20)   NOT NULL,
    priority        VARCHAR2(10)   NOT NULL,
    notes           VARCHAR2(2000),
    agent_id        VARCHAR2(100)  NOT NULL,
    status          VARCHAR2(20)   DEFAULT 'OPEN' NOT NULL,
    created_at      DATE           NOT NULL,
    updated_at      DATE
);

CREATE INDEX ix_care_ticket_cli     ON care_tickets (cli);
CREATE INDEX ix_care_ticket_status  ON care_tickets (status);
```

---

## Starting the Stack

Start the three components in this order:

### 1. care-mcp-server

```bash
cd apiServer
node src/care-mcp-server.js
```

Expected output:
```
[CareMCP] Starting ocncc-care v1.0.0
[OracleConnector] Pool 'default_pool' created (FAN enabled, min=2, max=10)
[OracleConnector] Connection probe successful
[CareMCP] Redis connected
[CareMCP] Profile tag metadata loaded: 142 tags
[CareMCP] Listening on port 3101
[CareMCP] Health: http://localhost:3101/health
[CareMCP] MCP endpoint: http://localhost:3101/mcp
```

### 2. LiteLLM

```bash
litellm --config litellm-config.yaml --port 4000
```

Expected output:
```
LiteLLM: Proxy initialized with config, starting proxy server
INFO:     Uvicorn running on http://0.0.0.0:4000
```

### 3. Open WebUI

```bash
docker start open-webui
# or if running natively:
open-webui serve --port 3000
```

Browse to `http://localhost:3000`.

---

## PM2 Process Management

Add the care MCP to your `ecosystem.config.js`:

```js
module.exports = {
  apps: [
    {
      name:        'ocncc-api',
      script:      'src/server.js',
      cwd:         '/opt/ocncc/apiServer',
      autorestart: true,
    },
    {
      name:        'ocncc-mcp',
      script:      'src/mcp-server.js',
      cwd:         '/opt/ocncc/apiServer',
      autorestart: true,
    },
    {
      name:        'ocncc-care-mcp',
      script:      'src/care-mcp-server.js',
      cwd:         '/opt/ocncc/apiServer',
      autorestart: true,
      max_memory_restart: '256M',
    },
  ],
};
```

```bash
# Start care MCP only
pm2 start ecosystem.config.js --only ocncc-care-mcp

# Start all three
pm2 start ecosystem.config.js

# Logs
pm2 logs ocncc-care-mcp

# Restart after config change
pm2 restart ocncc-care-mcp
```

For LiteLLM under PM2:

```js
{
  name:        'litellm',
  script:      'litellm',
  interpreter: 'python3',
  args:        '--config /opt/ocncc/litellm-config.yaml --port 4000',
  autorestart: true,
}
```

---

## Available Tools

### Read Tools

| Tool | Purpose | Key Inputs |
|---|---|---|
| `get_subscriber` | Full account + decoded profile | `cli`, `agent_id` |
| `get_balance` | Balance, credit limit, last top-up | `cli`, `agent_id` |
| `get_transaction_history` | Charges, credits, events | `cli`, `days` (1–90), `agent_id` |
| `get_topup_history` | Top-up records with status | `cli`, `days` (1–90), `agent_id` |
| `get_active_services` | Service flags from ESCHER profile | `cli`, `agent_id` |
| `get_billing_engine` | VWS node assignment | `cli`, `agent_id` |

### Write Tools (two-phase)

| Phase 1 (prepare) | Phase 2 (confirm) | What it does |
|---|---|---|
| `prepare_balance_adjustment` | `confirm_balance_adjustment` | Credits or debits subscriber balance |
| `prepare_service_state_change` | `confirm_service_state_change` | Changes service state (A/S/B/T) |

### Ticket Tool

| Tool | Purpose |
|---|---|
| `raise_ticket` | Creates a care ticket (categories: BILLING, TECHNICAL, ACCOUNT, COMPLAINT, TOPUP, OTHER) |

---

## Two-Phase Write Pattern

All write operations follow a prepare → confirm pattern. This ensures the AI presents a human-readable summary to the care agent and waits for explicit approval before any data is modified.

### How it works

```
Agent: "Credit £10 to 447700900123 — they reported a failed top-up yesterday"

AI calls: prepare_balance_adjustment({
  cli: "447700900123",
  amount_gbp: 10.00,
  reason: "Failed top-up reported by customer",
  agent_id: "agent.smith"
})

AI presents to agent:
┌─────────────────────────────────────────┐
│ BALANCE ADJUSTMENT — REQUIRES APPROVAL  │
│                                         │
│ Customer:       J SMITH                 │
│ CLI:            447700900123            │
│ Direction:      CREDIT                  │
│ Amount:         £10.00                  │
│ Current balance: £2.50                  │
│ Projected:      £12.50                  │
│ Reason: Failed top-up reported          │
│                                         │
│ Token expires in: 120 seconds           │
│ Type "confirm" to proceed               │
└─────────────────────────────────────────┘

Agent: "confirm"

AI calls: confirm_balance_adjustment({
  confirmation_token: "<token from prepare>",
  agent_id: "agent.smith"
})

AI: "✓ Balance adjustment of +£10.00 applied to 447700900123."
```

### Token security

Confirmation tokens are HMAC-SHA256 signed with `CARE_MCP_TOKEN_SECRET` and expire after 120 seconds. They encode the exact operation parameters — the confirm step cannot be used to execute a different operation than what was prepared. Agent identity is validated at both steps.

---

## Example Care Agent Sessions

### 1. Balance query and top-up investigation

```
Agent: I have a customer on 447700900123 saying their £20 top-up from Tuesday 
       hasn't appeared. Can you check?

AI: [calls get_balance, get_topup_history(days=7)]

    Current balance for J SMITH (447700900123): £5.00

    Top-up history (last 7 days):
    - 22/04/2026 14:32 — £20.00 via VOUCHER — Status: PENDING — Ref: VCH2026042201

    The £20 top-up is present in the log but shows status PENDING rather than
    COMPLETE — it has not yet been credited to the account. This is likely a
    voucher processing delay.

    Would you like me to:
    a) Apply a manual £20 credit while the voucher processes, or
    b) Raise a TOPUP ticket for the processing team?
```

### 2. Service suspension and reactivation

```
Agent: Customer 447700900456 says their service stopped working this morning.
       Agent ID: care.jones

AI: [calls get_subscriber]

    Subscriber: M PATEL (447700900456)
    Service state: S (Suspended)
    Wallet type: PRE
    Account type: PAYG Standard
    Balance: £0.00 — account has zero balance, which triggered automatic suspension.

    The service is suspended due to zero balance. Options:
    a) Apply a goodwill credit to reactivate, or
    b) Advise the customer to top up — service will reactivate automatically.

Agent: Apply £5 goodwill credit and reactivate. Agent ID is care.jones

AI: [calls prepare_balance_adjustment, prepare_service_state_change]

    Two changes require your confirmation:

    1. CREDIT £5.00 to 447700900456
       Current balance: £0.00 → Projected: £5.00
       Reason: Goodwill credit to restore service

    2. STATE CHANGE: S (Suspended) → A (Active)
       Customer: M PATEL

    Type "confirm" to apply both changes.

Agent: confirm

AI: [calls confirm_balance_adjustment, confirm_service_state_change]

    ✓ £5.00 credit applied to 447700900456
    ✓ Service state changed to Active
    
    M PATEL's service should be active immediately.
```

### 3. Billing dispute — transaction history

```
Agent: 447700900789 disputing a charge of £3 on Sunday. Can you pull their 
       transactions for the last 3 days?

AI: [calls get_transaction_history(cli, days=3)]

    Transactions for K BROWN (last 3 days):

    20/04/2026 18:44 — CHARGE £3.00 — "Premium SMS bundle" — Balance: £12.00 → £9.00
    19/04/2026 09:12 — TOPUP £10.00 — Balance: £2.00 → £12.00

    The £3.00 charge on Sunday 20 April is for a Premium SMS bundle activation.
    This would have been triggered by the subscriber sending an opt-in message to 
    a premium service.

    Shall I raise a COMPLAINT ticket, or apply a refund?
```

---

## Open WebUI Configuration

After Open WebUI is running, configure it to use LiteLLM as its backend:

1. **Settings → Connections → OpenAI API**
   - API Base URL: `http://localhost:4000/v1`
   - API Key: your LiteLLM virtual key

2. **Select model:** `care-assistant` (as defined in `litellm-config.yaml`)

3. **Optional — Custom System Prompt in Open WebUI:**
   The system prompt is already injected by LiteLLM's `default_system_prompt`.
   If you want per-agent overrides, set them in Open WebUI's model settings for individual users.

4. **Agent ID:**
   Agents should introduce themselves at the start of a session:
   > "My agent ID is care.smith"
   
   The AI will then pass this to all tool calls automatically.

---

## LiteLLM Configuration Notes

### Virtual keys per agent team

Create virtual keys in the LiteLLM Admin UI (`http://localhost:4000/ui`) so different teams have isolated spend tracking and rate limits:

```bash
# Create a virtual key for the care team
curl -X POST http://localhost:4000/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "models": ["care-assistant", "care-assistant-fast"],
    "max_budget": 50,
    "budget_duration": "30d",
    "metadata": {"team": "customer-care"}
  }'
```

### Adding the BSS model later

When `bss-mcp-server.js` is ready, add it to `litellm-config.yaml`:

```yaml
model_list:
  - model_name: bss-assistant
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/ANTHROPIC_API_KEY

mcp_servers:
  ocncc-bss:
    url: os.environ/BSS_MCP_URL
    headers:
      Authorization: "Bearer ${BSS_MCP_API_KEY}"
```

Point a separate Open WebUI instance (or model selector) at `bss-assistant`. BSS analysts use a different model name and a different system prompt — the same LiteLLM gateway serves all three domains.

---

## Security

### Network

- Expose only Open WebUI (port 3000) externally, via HTTPS with your reverse proxy
- LiteLLM (4000) and all MCP servers (3100, 3101) remain on the internal network only
- Care agents authenticate to Open WebUI — not directly to LiteLLM or MCP

### Write operation limits

Hard limits are enforced in the MCP server regardless of what the LLM requests:

```env
CARE_MAX_CREDIT_GBP=50.00    # Any credit above this is rejected at the tool layer
CARE_MAX_DEBIT_GBP=50.00     # Any debit above this is rejected at the tool layer
```

Adjustments above the limit return an error instructing the agent to escalate to a supervisor. The supervisor would use a separate elevated-privilege key.

### Audit trail

Every tool call — successful or failed — is written to `care_audit_log` with the agent identity, CLI, inputs, and outcome. This table should be included in your regulatory data retention policy.

```sql
-- Example audit query: all write operations by agent in last 24 hours
SELECT agent_id, tool_name, cli, input_summary, outcome, created_at
FROM care_audit_log
WHERE outcome IN ('PREPARED', 'EXECUTED', 'ERROR')
  AND created_at >= SYSDATE - 1
ORDER BY created_at DESC;
```

---

## Extending to BSS and OSS

The pattern established here scales directly to the other two domains.

**BSS Analytics MCP** (`bss-mcp-server.js`, port 3102):
- Read-only Oracle connection to reporting/warehouse schema
- Tools for revenue queries, product performance, cohort analysis
- No two-phase writes (analytics is read-only)
- Separate LiteLLM model name `bss-assistant` with analytics-focused system prompt

**OSS Operations MCP** (`oss-mcp-server.js`, port 3103):
- Connects to PCF, NRF, and Prometheus alongside Oracle
- Write tools (policy push, rebalance) use the same two-phase pattern
- Machine agent runtime replaces Open WebUI for automated workflows
- Separate approval webhook (Slack/Teams) before `confirm_` tools execute on critical operations

All three MCP servers register with the same LiteLLM gateway instance. Role-based virtual keys control which model names (and therefore which MCP tool sets) each team can access.

---

## Troubleshooting

### LiteLLM can't reach the care MCP

```
ConnectionRefusedError: [Errno 111] Connection refused — http://localhost:3101/mcp
```

Verify care-mcp-server is running: `curl http://localhost:3101/health`  
If running in Docker, use `host.docker.internal` instead of `localhost`.

### Confirmation token expired

```json
{ "error": "Confirmation token expired — re-run the prepare step (tokens valid for 120s)" }
```

The agent took more than 2 minutes between the prepare and confirm steps. Re-run `prepare_balance_adjustment` to generate a fresh token. Increase `TOKEN_TTL_SECONDS` in the server if agents consistently need more time.

### Agent identity mismatch on confirm

```json
{ "error": "Agent identity mismatch — token was prepared by a different agent" }
```

The `agent_id` passed to `confirm_` must exactly match what was passed to `prepare_`. Ensure the AI is carrying the agent ID consistently through the session. Prompt the agent to state their ID at session start.

### Oracle audit log write failed (non-blocking)

```
[CareMCP] Audit log write failed: ORA-00942: table or view does not exist
```

The `care_audit_log` table hasn't been created. Run the DDL statements in [Database Schema](#database-schema--audit-tables). Audit failures are non-blocking — tool calls still succeed — but you lose the compliance trail.

### Balance adjustment stub — no actual credit applied

The `dbApplyBalanceAdjustment` function is stubbed — it writes to `care_balance_adjustments` but does not yet call `BeClient` to push the credit to the billing engine via ESCHER. Replace the TODO comment with your actual balance write mechanism before going to production.

```js
// In care-mcp-server.js, function dbApplyBalanceAdjustment:
// TODO: Replace stub with: await beClient.adjustBalance(cli, amountPence)
```
