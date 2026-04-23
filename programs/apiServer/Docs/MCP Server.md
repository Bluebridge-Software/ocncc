# OCNCC MCP Server

**Service:** `ocncc-oracle`  
**Version:** 1.0.0  
**Transport:** HTTP + Server-Sent Events (MCP StreamableHTTP spec)  
**Author:** Tony Craven — Blue Bridge Software Ltd  
**© Copyright:** Blue Bridge Software Ltd 2026

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Starting and Stopping](#starting-and-stopping)
7. [PM2 Process Management](#pm2-process-management)
8. [Health Check](#health-check)
9. [Available Tools](#available-tools)
10. [External Agent Integration](#external-agent-integration)
    - [Claude Code](#claude-code)
    - [Antigravity (Google)](#antigravity-google)
    - [Programmatic / Custom Agent](#programmatic--custom-agent)
11. [Example Agent Queries](#example-agent-queries)
12. [Security](#security)
13. [Troubleshooting](#troubleshooting)

---

## Overview

The OCNCC MCP Server exposes the Oracle OCNCC Master Database as a set of queryable tools consumable by any MCP-compatible AI agent. It runs as a **persistent, standalone HTTP service** alongside the existing REST API server, on a separate port.

External agents connect over HTTP and interact via the MCP protocol — they call named tools with typed inputs and receive structured JSON responses. No agent has direct database access; all queries are mediated through the existing `database-queries.js` and `oracle-connector.js` layers, preserving Redis caching and retry logic.

---

## Architecture

```
External AI Agent
(Claude Code, Antigravity, custom tooling)
        │
        │  HTTP POST /mcp    (tool calls, initialise)
        │  HTTP GET  /mcp    (SSE stream, notifications)
        │  Authorization: Bearer <MCP_API_KEY>
        ▼
┌──────────────────────────────────────────────┐
│  apiServer host                              │
│                                              │
│  ┌─────────────┐     ┌────────────────────┐  │
│  │  server.js  │     │   mcp-server.js    │  │
│  │  REST API   │     │   MCP over HTTP    │  │
│  │  :3000      │     │   :3100            │  │
│  └──────┬──────┘     └────────┬───────────┘  │
│         └───────────┬─────────┘              │
│                     ▼                        │
│           src/database/  src/services/       │
│           OracleConnector  RedisClient       │
│                     │                        │
│                     ▼                        │
│                Oracle OCNCC DB               │
└──────────────────────────────────────────────┘
```

The two processes are independent — each maintains its own Oracle connection pool and Redis client. They share source code on disk only.

---

## Prerequisites

- Node.js 20+
- Oracle Instant Client (already configured for `server.js`)
- PM2 (recommended for production): `npm install -g pm2`
- Redis (optional — queries degrade gracefully without it)
- The existing `apiServer` project dependencies installed

---

## Installation

### 1. Place the file

```
./apiServer/src/mcp-server.js
```

### 2. Install additional dependencies

```bash
cd apiServer
npm install @modelcontextprotocol/sdk zod express
```

`express` may already be present if `server.js` uses it. The MCP SDK and `zod` are new.

### 3. Verify imports resolve

```bash
cd apiServer/src
node -e "require('./database/oracle-connector'); console.log('OK')"
node -e "require('./services/redis-client'); console.log('OK')"
node -e "require('./database/database-queries'); console.log('OK')"
```

Adjust paths if your directory structure differs.

---

## Configuration

All configuration is via environment variables. Add these to your existing `.env` file at `apiServer/.env`:

```env
# --- Existing Oracle vars (already present) ---
ORACLE_USER=your_db_user
ORACLE_PASSWORD=your_db_password
ORACLE_SMF_SERVICE=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=...)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=...)))

# --- MCP Server ---
MCP_PORT=3100
MCP_API_KEY=generate-a-strong-random-secret-here
```

**Generating a secure API key:**

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

The server will **refuse to start** if `ORACLE_USER`, `ORACLE_PASSWORD`, `ORACLE_SMF_SERVICE`, or `MCP_API_KEY` are absent.

---

## Starting and Stopping

### Development (foreground)

```bash
cd apiServer
node src/mcp-server.js
```

Expected startup output on stderr:

```
[MCP] Starting ocncc-oracle v1.0.0
[OracleConnector] Pool 'default_pool' created (FAN enabled, min=2, max=10)
[OracleConnector] Connection probe successful
[MCP] Redis connected
[MCP] BbsProfileBlock loaded
[MCP] Profile tag metadata loaded: 142 tags
[MCP] ocncc-oracle listening on port 3100
[MCP] Health: http://localhost:3100/health
[MCP] MCP endpoint: http://localhost:3100/mcp
```

Stop with `Ctrl+C` — this triggers graceful shutdown (pool drain, connection close).

### Manual background (not recommended for production)

```bash
nohup node src/mcp-server.js > logs/mcp.log 2>&1 &
echo $! > logs/mcp.pid

# Stop
kill $(cat logs/mcp.pid)
```

---

## PM2 Process Management

PM2 is the recommended way to run both processes in production.

### Ecosystem file

Create `apiServer/ecosystem.config.js`:

```js
module.exports = {
  apps: [
    {
      name:         'ocncc-api',
      script:       'src/server.js',
      cwd:          '/opt/ocncc/apiServer',
      instances:    1,
      autorestart:  true,
      watch:        false,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
      },
    },
    {
      name:         'ocncc-mcp',
      script:       'src/mcp-server.js',
      cwd:          '/opt/ocncc/apiServer',
      instances:    1,
      autorestart:  true,
      watch:        false,
      max_memory_restart: '256M',
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};
```

### PM2 commands

```bash
cd apiServer

# Start both processes
pm2 start ecosystem.config.js

# Start MCP only
pm2 start ecosystem.config.js --only ocncc-mcp

# Stop MCP (graceful — sends SIGTERM, pool drains)
pm2 stop ocncc-mcp

# Restart MCP
pm2 restart ocncc-mcp

# Reload with zero downtime (if clustered)
pm2 reload ocncc-mcp

# Delete from PM2 registry
pm2 delete ocncc-mcp

# Live logs
pm2 logs ocncc-mcp

# Monitor CPU/memory
pm2 monit

# Save process list (survives reboot)
pm2 save
pm2 startup   # follow printed instructions to enable on-boot
```

### Checking status

```bash
pm2 list
```

```
┌─────┬─────────────┬─────────┬──────┬───────────┬──────────┬──────────┐
│ id  │ name        │ mode    │ ↺    │ status    │ cpu      │ memory   │
├─────┼─────────────┼─────────┼──────┼───────────┼──────────┼──────────┤
│ 0   │ ocncc-api   │ fork    │ 0    │ online    │ 0%       │ 85.2mb   │
│ 1   │ ocncc-mcp   │ fork    │ 0    │ online    │ 0%       │ 62.1mb   │
└─────┴─────────────┴─────────┴──────┴───────────┴──────────┴──────────┘
```

---

## Health Check

The `/health` endpoint requires **no authentication** and is suitable for load balancer probes and monitoring:

```bash
curl http://localhost:3100/health
```

```json
{
  "status": "ok",
  "service": "ocncc-oracle",
  "version": "1.0.0",
  "uptime": 3742
}
```

---

## Available Tools

All tools return JSON. On error, the response includes `error` (message), `tool` (name), and `oraCode` (ORA-XXXXX code if an Oracle error).

---

### `get_profile_tags`

Fetch all OCNCC profile tag definitions from `ACS_PROFILE_DETAILS`.

| Input | Type | Default | Description |
|---|---|---|---|
| `force_refresh` | boolean | `false` | Bypass Redis cache and re-read from Oracle |

**Response:**

```json
{
  "count": 142,
  "data": [
    {
      "tagId": "0000001A",
      "name": "BALANCE",
      "type": "INT",
      "parentTagId": null,
      "isInputParameter": true,
      "children": []
    }
  ],
  "tree": [...]
}
```

Redis TTL: **1 hour**

---

### `get_subscriber`

Fetch a subscriber record from `CCS_ACCT_REFERENCE` by CLI.

| Input | Type | Default | Description |
|---|---|---|---|
| `cli` | string | required | Phone number, e.g. `"447700900123"` |
| `force_refresh` | boolean | `false` | Bypass Redis cache |
| `decode_profile` | boolean | `false` | Decode ESCHER profile blob (requires BbsProfileBlock) |

**Response (decode_profile=false):**

```json
{
  "count": 1,
  "data": [
    {
      "id": 100042,
      "cli": "447700900123",
      "service_state": "A",
      "wallet_type": "PRE",
      "wallet_id": 20019,
      "billing_engine_id": 351,
      "account_type_id": 3,
      "account_type_name": "PAYG Standard",
      "customer_name": "J SMITH",
      "profile": "AQIDBAUGBwg..."
    }
  ]
}
```

**Response (decode_profile=true):**

```json
{
  "count": 1,
  "data": [
    {
      "id": 100042,
      "cli": "447700900123",
      ...
      "decodedProfile": {
        "tags": [
          { "tagId": "0000001A", "name": "BALANCE", "type": "INT", "value": 2500 },
          { "tagId": "0000002B", "name": "EXPIRY_DATE", "type": "STR", "value": "2026-12-31" }
        ]
      }
    }
  ]
}
```

Redis TTL: **30 seconds**

---

### `get_vws_nodes`

Fetch VWS (OCS billing engine) node topology from `CCS_DOMAIN_*`.

| Input | Type | Default | Description |
|---|---|---|---|
| `force_refresh` | boolean | `false` | Bypass Redis cache |

**Response:**

```json
{
  "12": [
    {
      "nodeNumber": 351,
      "name": "VWS01",
      "commAddress": "192.168.127.42",
      "clientPort": 1500
    },
    {
      "nodeNumber": 352,
      "name": "VWS02",
      "commAddress": "192.168.127.47",
      "clientPort": 1500
    }
  ]
}
```

Redis TTL: **5 minutes**

---

### `invalidate_cache`

Invalidate Redis cache entries to force a fresh Oracle read.

| Input | Type | Required | Description |
|---|---|---|---|
| `target` | `"profile_tags"` \| `"subscriber"` \| `"all"` | yes | Which cache to clear |
| `cli` | string | when target=`"subscriber"` | CLI to clear |

**Response:**

```json
{
  "success": true,
  "actions": ["profile_tags cache cleared"]
}
```

---

## External Agent Integration

### Claude Code

Add to `.claude/mcp.json` in your project root, or `~/.claude/mcp.json` for global access:

```json
{
  "mcpServers": {
    "ocncc-oracle": {
      "type": "http",
      "url": "http://your-server-host:3100/mcp",
      "headers": {
        "Authorization": "Bearer your-mcp-api-key"
      }
    }
  }
}
```

Claude Code will discover the tools automatically on session start. You can then prompt naturally:

```
Look up subscriber 447700900123, decode their profile, and tell me their balance and service state.
```

```
Get all profile tags and list the ones that are input parameters of type INT.
```

```
Show me the VWS node topology — which billing engines are active?
```

---

### Antigravity (Google)

In Antigravity's MCP settings panel, add a new server entry:

```json
{
  "name": "ocncc-oracle",
  "type": "http",
  "url": "http://your-server-host:3100/mcp",
  "headers": {
    "Authorization": "Bearer your-mcp-api-key"
  }
}
```

Antigravity follows the same MCP StreamableHTTP spec, so the connection is identical to Claude Code. Once registered, all four tools appear in the agent's tool list regardless of which model (Gemini, Claude, etc.) is active.

---

### Programmatic / Custom Agent

Any HTTP client can call the MCP endpoint directly. The MCP protocol uses JSON-RPC 2.0 over HTTP POST.

#### 1. Initialise the session

```bash
curl -s -X POST http://localhost:3100/mcp \
  -H "Authorization: Bearer your-mcp-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": { "name": "my-agent", "version": "1.0.0" }
    }
  }'
```

#### 2. List available tools

```bash
curl -s -X POST http://localhost:3100/mcp \
  -H "Authorization: Bearer your-mcp-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }'
```

#### 3. Call a tool

```bash
curl -s -X POST http://localhost:3100/mcp \
  -H "Authorization: Bearer your-mcp-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "get_subscriber",
      "arguments": {
        "cli": "447700900123",
        "decode_profile": true
      }
    }
  }'
```

#### Node.js example

```js
const MCP_URL = 'http://your-server-host:3100/mcp';
const MCP_KEY = process.env.MCP_API_KEY;

async function callTool(name, args) {
    const res = await fetch(MCP_URL, {
        method:  'POST',
        headers: {
            'Content-Type':  'application/json',
            'Authorization': `Bearer ${MCP_KEY}`,
        },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id:      Date.now(),
            method:  'tools/call',
            params:  { name, arguments: args },
        }),
    });

    const data = await res.json();
    if (data.error) throw new Error(data.error.message);
    return JSON.parse(data.result.content[0].text);
}

// Usage
const subscriber = await callTool('get_subscriber', {
    cli:            '447700900123',
    decode_profile: true,
});

console.log(subscriber.data[0].customer_name);
console.log(subscriber.data[0].decodedProfile.tags);
```

#### Python example

```python
import os, json, time, requests

MCP_URL = "http://your-server-host:3100/mcp"
MCP_KEY = os.environ["MCP_API_KEY"]

def call_tool(name: str, args: dict) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id":      int(time.time() * 1000),
        "method":  "tools/call",
        "params":  {"name": name, "arguments": args},
    }
    r = requests.post(
        MCP_URL,
        json=payload,
        headers={"Authorization": f"Bearer {MCP_KEY}"},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"]["message"])
    return json.loads(data["result"]["content"][0]["text"])

# Usage
subscriber = call_tool("get_subscriber", {
    "cli": "447700900123",
    "decode_profile": True,
})
print(subscriber["data"][0]["customer_name"])
```

---

## Example Agent Queries

These are natural-language prompts that work once the MCP is registered with Claude Code or Antigravity.

**Subscriber lookup:**
```
Look up 447700900123. What is their service state, wallet type, and billing engine?
```

**Profile decode:**
```
Fetch subscriber 447700900123 with profile decoding enabled. List all INT-type 
tags and their current values in a table.
```

**Stale data refresh:**
```
The subscriber data for 447700900123 may be cached — invalidate it and re-fetch 
with a fresh read from Oracle.
```

**Node topology:**
```
Get all VWS nodes. Which domain has the most nodes, and what are their IP addresses 
and ports?
```

**Tag exploration:**
```
Get all profile tags. Show me the hierarchy — which tags have children, and what 
are the top-level parent tags?
```

**Cross-query analysis:**
```
Look up subscriber 447700900123 and also get the VWS nodes. The subscriber is on 
billing_engine_id 351 — which domain does that node belong to and what is its 
comm_address?
```

---

## Security

### Network exposure

The MCP port (3100) should **not** be directly internet-facing. Recommended options:

**VPN / private network** — agents connect via WireGuard or OpenVPN. The MCP server binds to `0.0.0.0` but port 3100 is blocked at the firewall for external traffic.

**SSH tunnel** — agent machine opens a tunnel before connecting:
```bash
ssh -L 3100:localhost:3100 user@ocncc-host
# Agent then connects to http://localhost:3100/mcp
```

**Nginx reverse proxy with TLS** — if the MCP must be internet-accessible, terminate TLS at nginx and proxy to port 3100:
```nginx
server {
    listen 443 ssl;
    server_name mcp.yourdomain.com;

    ssl_certificate     /etc/ssl/certs/your.crt;
    ssl_certificate_key /etc/ssl/private/your.key;

    location /mcp {
        proxy_pass         http://127.0.0.1:3100;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_read_timeout 300s;   # SSE streams require long timeout
    }
}
```

### API key rotation

To rotate the `MCP_API_KEY` without downtime:

1. Update the key in `.env`
2. `pm2 restart ocncc-mcp`
3. Update the key in all registered agent configs

### Read-only posture

The four exposed tools are all read-only against Oracle (SELECT only). The `invalidate_cache` tool only writes to Redis. No DML operations are exposed. If future write tools are added, consider a separate write-scoped key with additional logging.

---

## Troubleshooting

### Server won't start — missing env vars

```
[MCP] FATAL: Missing required environment variables: MCP_API_KEY
```

Add the missing variables to `.env` and restart.

---

### 401 Unauthorised from agent

Check that the `Authorization` header is exactly `Bearer <your-key>` with no trailing spaces or newlines. Verify the key in your agent config matches `MCP_API_KEY` in `.env`.

---

### Oracle pool errors on startup

```
[OracleConnector] Pool 'default_pool' created ...
[OracleConnector] Connection probe successful   ← must appear
```

If the probe fails, check `ORACLE_SMF_SERVICE` TNS string and Oracle Instant Client path (`LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH`).

---

### Tool returns stale data

Call `invalidate_cache` with the appropriate target, then re-call the query tool with `force_refresh: true` to confirm a fresh Oracle read.

---

### SSE connection drops immediately

Ensure any proxy (nginx, load balancer) has `proxy_read_timeout` set to at least 300 seconds. Default timeouts (60s) will terminate the SSE stream before the agent finishes its session.

---

### PM2 shows repeated restarts

```bash
pm2 logs ocncc-mcp --lines 50
```

Common causes: missing `.env` file, Oracle Instant Client not on `PATH`, port 3100 already in use (`lsof -i :3100`).