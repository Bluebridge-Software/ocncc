# OCNCC Billing Engine REST API — Integration Guide

> **© 2026 Blue Bridge Software Ltd. All rights reserved.**
> Author: Tony Craven
> Document Version: 1.0 — March 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Authentication](#3-authentication)
4. [Message Format](#4-message-format)
   - 4.1 [Dual-Format Support (Raw vs Friendly)](#41-dual-format-support-raw-vs-friendly)
   - 4.2 [Common Message Structure](#42-common-message-structure)
   - 4.3 [Header Fields](#43-header-fields)
   - 4.4 [Action Types (ACTN)](#44-action-types-actn)
   - 4.5 [Response Format](#45-response-format)
5. [REST API Endpoints](#5-rest-api-endpoints)
   - 5.1 [POST /api/wallet-info](#51-post-apiwallet-info)
   - 5.2 [POST /api/initial-reservation](#52-post-apiinitial-reservation)
   - 5.3 [GET /api/stats](#53-get-apistats)
6. [Message Type Reference](#6-message-type-reference)
   - 6.1 [Wallet Operations](#61-wallet-operations)
   - 6.2 [Call Reservation Flow](#62-call-reservation-flow)
   - 6.3 [Named Event Operations](#63-named-event-operations)
   - 6.4 [Amount Reservation Operations](#64-amount-reservation-operations)
   - 6.5 [Direct Amount Operations](#65-direct-amount-operations)
   - 6.6 [Rate Query Operations](#66-rate-query-operations)
   - 6.7 [Voucher Operations](#67-voucher-operations)
   - 6.8 [Administrative Operations](#68-administrative-operations)
7. [Response Types](#7-response-types)
   - 7.1 [ACK (Positive Acknowledgement)](#71-ack-positive-acknowledgement)
   - 7.2 [NACK (Negative Acknowledgement)](#72-nack-negative-acknowledgement)
   - 7.3 [EXCP (Exception)](#73-excp-exception)
8. [NAck Code Reference](#8-nack-code-reference)
9. [Exception Code Reference](#9-exception-code-reference)
10. [Wallet State Reference](#10-wallet-state-reference)
11. [Balance Limit Type Reference](#11-balance-limit-type-reference)
12. [Error Handling](#12-error-handling)
13. [Integration Examples](#13-integration-examples)
14. [Security Best Practices](#14-security-best-practices)
15. [Field Symbol Reference (Raw Format)](#15-field-symbol-reference-raw-format)
16. [Extended Wallet Features](#16-extended-wallet-features)
    - 16.1 [Future-Dated Buckets (STDT)](#161-future-dated-buckets-stdt)
    - 16.2 [Multi-Bucket Updates in a Single Message](#162-multi-bucket-updates-in-a-single-message)
    - 16.3 [Extended Message Fields](#163-extended-message-fields)

---

## 1. Overview

The OCNCC Billing Engine (BE) REST API provides a JSON-over-HTTP bridge to the underlying BE messaging platform (Oracle Communications Network Charging and Control). It allows third-party systems to perform real-time balance management operations — including wallet queries, call reservations, direct charges, voucher redemptions, and wallet lifecycle management — without needing to implement the native Escher binary messaging protocol.

The REST API accepts JSON payloads in either **Raw** (4-character symbol) format or **Friendly** (human-readable label) format, translates them to native BE Protocol messages, forwards them to the configured BE Server(s), and returns the response in the same format the request was received in.

**Base URL:**
```
http://<host>:3010/api
```

**Transport:** HTTP/1.1 (HTTPS recommended in production)

**Data Format:** `application/json`

---

## 2. Architecture

```
Third-Party Client
      │
      │  HTTP POST (JSON)
      ▼
OCNCC REST API Gateway (Node.js, port 3010)
      │  JWT Authentication & Endpoint ACL
      │  JSON → BE Protocol Message translation
      ▼
BE Client  ──TCP──►  BE Server (Primary)
                └──TCP──►  BE Server (Secondary / Failover)
                               │
                               ▼
                          BE VWARS (Wallet/Account processing)
```

The gateway supports automatic failover between a primary and secondary BE Server. The `preferredEngine` query parameter allows callers to hint which engine to attempt first.

---

## 3. Authentication

All API endpoints (except health checks, if present) require a **JWT Bearer token** in the `Authorization` header.

### 3.1 Token Format

```
Authorization: Bearer <JWT_TOKEN>
```

### 3.2 Token Structure

Tokens must be signed with the shared secret configured via the `BE_JWT_SECRET` environment variable on the server. Tokens are issued and managed by the integrating system; the API gateway validates them on each request.

**JWT Payload fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `clientId` | string | Yes | Unique identifier for the calling system. Recorded in `/api/stats`. |
| `allowedEndpoints` | string[] | Yes | List of API endpoints this token is permitted to call. E.g. `["/wallet-info", "/stats"]` |
| `exp` | number | Yes (standard) | Unix timestamp when the token expires. Tokens with no `exp` will be rejected. |
| `iat` | number | Recommended | Unix timestamp when the token was issued. |

**Example Token Payload:**
```json
{
  "clientId": "MyBillingSystem",
  "allowedEndpoints": ["/wallet-info", "/initial-reservation", "/stats"],
  "iat": 1743000000,
  "exp": 1743003600
}
```

### 3.3 Generating a Token (Node.js Example)

```javascript
const jwt = require('jsonwebtoken');

const token = jwt.sign(
  {
    clientId: 'MyBillingSystem',
    allowedEndpoints: ['/wallet-info', '/initial-reservation', '/stats']
  },
  process.env.BE_JWT_SECRET,
  { expiresIn: '1h' }
);
```

### 3.4 Authentication Errors

| HTTP Status | Condition |
|---|---|
| `401 Unauthorized` | No `Authorization` header provided, or token is missing/malformed. |
| `401 Unauthorized` | Token signature is invalid (wrong secret). |
| `401 Unauthorized` | Token has expired (`exp` is in the past). |
| `403 Forbidden` | Token is valid but the requested endpoint is not in `allowedEndpoints`. |

Unauthorised attempts are counted in the `/api/stats` response under `unauthorisedAttempts`.

### 3.5 Security Restrictions

- Tokens **must** have an expiry (`exp`). Tokens without an expiry claim are rejected.
- The `BE_JWT_SECRET` must be a strong random value. The default value `YOUR_SUPER_SECRET_KEY_CHANGE_IN_PRODUCTION` **must never be used in production**.
- Token scope is enforced per-endpoint. A token granted access to `/wallet-info` cannot call `/initial-reservation` unless that endpoint is also listed in `allowedEndpoints`.
- Tokens should be kept confidential. Do not embed them in client-side JavaScript or public repositories.
- Tokens should have a short expiry (e.g. 1 hour) and be rotated regularly.

---

## 4. Message Format

### 4.1 Dual-Format Support (Raw vs Friendly)

The API accepts messages in two formats and automatically detects which is being used based on the presence of known keys.

**Raw Format** uses terse 4-character symbol codes, identical to the native BE Protocol wire format. This is suitable for legacy systems or direct integrations.

**Friendly Format** uses human-readable field names. The server detects this format and returns responses in the same friendly format.

The server's response will mirror the format of the request — send raw, receive raw; send friendly, receive friendly.

**Example: Wallet Info Request in Raw Format**
```json
{
  "ACTN": "REQ ",
  "TYPE": "WI  ",
  "HEAD": {
    "CMID": 1055,
    "SVID": 1
  },
  "BODY": {
    "WALT": 447700900123,
    "BTYP": 2
  }
}
```

**Example: Wallet Info Request in Friendly Format**
```json
{
  "FOX Action": "REQ ",
  "FOX Type": "WI  ",
  "Header": {
    "Request Number (CMID)": 1055,
    "BE Server ID": 1
  },
  "Body": {
    "Wallet Reference": 447700900123,
    "Balance Type": 2
  }
}
```

> **Note:** All examples in this document use **Raw format** for precision. The 4-character symbols are the authoritative field identifiers. Trailing spaces in symbols (e.g. `"REQ "`, `"WI  "`) are **significant** and must be included.

---

### 4.2 Common Message Structure

Every BE Protocol message has the same top-level structure:

```json
{
  "ACTN": "<action>",
  "TYPE": "<message-type>",
  "HEAD": { ... },
  "BODY": { ... }
}
```

| Field | Symbol | Type | Description |
|---|---|---|---|
| Action | `ACTN` | Symbol (4-char) | The message action. See [Section 4.4](#44-action-types-actn). |
| Type | `TYPE` | Symbol (4-char) | The message type. Identifies the specific operation. |
| Header | `HEAD` | Map | Common routing and correlation fields. |
| Body | `BODY` | Map | Operation-specific fields. |

---

### 4.3 Header Fields

The `HEAD` map is common to all messages and contains routing and correlation information.

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `SVID` | BE Server ID | int | **M** | The target BE Server identifier (`BE_LOCATION.ID`). Typically `1` unless you have multiple BE server pairs. |
| `CMID` | Client Message ID | int | **M** | A unique integer (per client) used to correlate a request with its response. The server echoes this value in the reply. |
| `VER ` | Protocol Version | int | O | Protocol dialect version. Encoded as pairs of digits (e.g. `100` = version 1.0.0). Defaults to `0` if omitted. |
| `DATE` | Call Date | date | O | Date/time of the event in GMT (Unix timestamp). Set automatically by the BE Client if omitted. |
| `USEC` | Microseconds | int | O | Microsecond component of `DATE`. Set automatically if `DATE` is omitted. |
| `DUP ` | Duplicate Flag | int | O | Set to `1` if this message may be a duplicate of a previously sent message (e.g. after a failover retry). `0` normally. |

**Example Header:**
```json
{
  "HEAD": {
    "SVID": 1,
    "CMID": 1001,
    "VER ": 100,
    "DUP ": 0
  }
}
```

---

### 4.4 Action Types (ACTN)

| Symbol | Name | Direction | Description |
|---|---|---|---|
| `REQ ` | Request | Client → Server | A request from the client to perform an operation. |
| `ACK ` | Acknowledgement | Server → Client | A successful response to a Request. |
| `NACK` | Negative Acknowledgement | Server → Client | The system is functioning correctly but the request could not be fulfilled (e.g. insufficient funds). Not a system error. |
| `EXCP` | Exception | Server → Client | A system error. Something unexpected went wrong. Should be logged and investigated. |
| `ABRT` | Abort | Client → Server | Indicates the client has abandoned a pending request. |

---

### 4.5 Response Format

All responses from the API are wrapped in an envelope:

```json
{
  "format": "raw",
  "message": { ... }
}
```

| Field | Type | Description |
|---|---|---|
| `format` | string | Either `"raw"` or `"friendly"`, reflecting the format of the original request. |
| `message` | object | The BE Protocol response message (ACK, NACK, or EXCP). |

---

## 5. REST API Endpoints

### 5.1 POST /api/wallet-info

Retrieves detailed information about a subscriber wallet, including state, balances, and bucket contents.

**Maps to BE message type:** `WI  ` (Wallet Info)

**HTTP Method:** `POST`

**URL:** `/api/wallet-info`

**Query Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `billingEngineId` | int | No | Override the target BE Server ID (overrides `HEAD.SVID`). |
| `preferredEngine` | string | No | Hint which engine to try first. Values: `"primary"`, `"secondary"`. |

**Request Body:**

```json
{
  "ACTN": "REQ ",
  "TYPE": "WI  ",
  "HEAD": {
    "SVID": 1,
    "CMID": 1001,
    "VER ": 100,
    "DUP ": 0
  },
  "BODY": {
    "WALT": 12345,
    "WALR": "ACC001:1",
    "BTYP": 2,
    "BUNT": 1,
    "UCUR": 840,
    "SPID": 101,
    "LOCK": 500,
    "SDNF": null,
    "SPLG": null,
    "SPCP": null,
    "UDWS": null,
    "ACTY": 5,
    "AREF": 999,
    "WTYP": 1,
    "CLI ": "447700900123"
  }
}
```

**Request Body Fields (BODY):**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The numeric wallet identifier. Used for routing to the correct BE VWARS instance. |
| `WALR` | Wallet Reference | string | O | Human-readable wallet reference string (e.g. `"ACC001:1"`). |
| `BTYP` | Balance Type | int | O | The specific balance type to return. If omitted, all balances are returned. |
| `BUNT` | Balance Unit | int | O | The unit of the balance (e.g. seconds, bytes). |
| `UCUR` | User Currency | int | O | ISO 4217 currency code integer for the user's currency (e.g. `840` = USD, `826` = GBP). |
| `SPID` | Service Provider ID | int | O | Service Provider identifier. |
| `LOCK` | Lock Duration (ms) | int | O | Lock the wallet for this many milliseconds during the query to prevent concurrent modifications. |
| `SDNF` | Start Date No Filter | null/date | O | If present, disables date filtering on balance start dates. Send `null` to activate. |
| `SPLG` | Suppress Plugins | null | O | If present (as `null`), suppresses plugin execution during this query. |
| `SPCP` | Suppress Periodic Charge Plugin | null | O | If present (as `null`), suppresses the periodic charge plugin. |
| `UDWS` | Update Wallet Status | null | O | Controls wallet status update behaviour. |
| `ACTY` | Account Type | int | O | Account type identifier (`CCS_ACCT_TYPE.ID`). |
| `AREF` | Account Reference | int | O | Account reference identifier (`CCS_ACCR_REFERENCE.ID`). |
| `WTYP` | Wallet Type | int | O | Wallet type identifier. |
| `CLI ` | Calling Line ID | string | O | The subscriber's MSISDN / calling number. |

**Successful Response (ACK):**

```json
{
  "format": "raw",
  "message": {
    "ACTN": "ACK ",
    "TYPE": "WI  ",
    "HEAD": {
      "SVID": 1,
      "CMID": 1001,
      "VER ": 100,
      "DUP ": 0
    },
    "BODY": {
      "WALT": 12345,
      "STAT": "ACTV",
      "EXPR": 1776627629,
      "MAXC": 3,
      "ACTV": 1766259629,
      "LUSE": 1774032029,
      "SCUR": 840,
      "UCUR": 840,
      "BALS": [
        {
          "BTYP": 1,
          "LIMT": "DEBT",
          "STOT": 50000,
          "BUNT": 1,
          "BKTS": [
            {
              "ID  ": 1,
              "VAL ": 50000,
              "EXPR": 1776627629
            }
          ]
        }
      ]
    }
  }
}
```

**ACK Body Fields:**

| Symbol | Name | Type | Description |
|---|---|---|---|
| `WALT` | Wallet ID | int | The wallet identifier. |
| `STAT` | Wallet State | Symbol | Current state of the wallet. See [Section 10](#10-wallet-state-reference). |
| `EXPR` | Expiry Date | date (Unix) | When the wallet expires. |
| `MAXC` | Max Concurrent | int | Maximum number of concurrent sessions permitted. |
| `ACTV` | Activation Date | date (Unix) | When the wallet was activated. |
| `LUSE` | Last Used | date (Unix) | Timestamp of the last transaction against this wallet. |
| `SCUR` | System Currency | int | ISO 4217 currency code for the system's base currency. |
| `UCUR` | User Currency | int | ISO 4217 currency code for the user's display currency. |
| `BALS` | Balances | array | Array of `BalanceInfo` objects. See below. |

**BalanceInfo Object (within `BALS`):**

| Symbol | Name | Type | Description |
|---|---|---|---|
| `BTYP` | Balance Type | int | The balance type identifier. |
| `LIMT` | Limit Type | Symbol | The limit type. See [Section 11](#11-balance-limit-type-reference). |
| `STOT` | System Currency Total | int | Total balance in system currency units. |
| `BUNT` | Balance Unit | int | The unit type for this balance. |
| `BKTS` | Buckets | array | Array of `BucketInfo` objects. See below. |

**BucketInfo Object (within `BKTS`):**

| Symbol | Name | Type | Description |
|---|---|---|---|
| `ID  ` | Bucket ID | int | The bucket identifier. |
| `VAL ` | Value | int | The balance value in this bucket (system currency units). |
| `EXPR` | Expiry Date | date (Unix) | When this bucket expires. `null` if no expiry. |

**Possible NAck Codes:** `WDIS`, `NCNT`

---

### 5.2 POST /api/initial-reservation

Initiates a call/session reservation against a subscriber's wallet. This is the first step in the call reservation lifecycle. A successful response grants permission to proceed with a call for up to the returned number of units.

**Maps to BE message type:** `IR  ` (Initial Reservation)

**HTTP Method:** `POST`

**URL:** `/api/initial-reservation`

**Query Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `billingEngineId` | int | No | Override the target BE Server ID. |
| `preferredEngine` | string | No | `"primary"` or `"secondary"`. |

**Request Body:**

```json
{
  "ACTN": "REQ ",
  "TYPE": "IR  ",
  "HEAD": {
    "SVID": 1,
    "CMID": 2001,
    "VER ": 100,
    "DUP ": 0
  },
  "BODY": {
    "WALT": 12345,
    "AREF": 999,
    "ACTY": 5,
    "CLI ": "447700900123",
    "DN  ": "447911234567",
    "CDAT": 1774035629,
    "TZ  ": "GMT",
    "ERSL": 120,
    "BCOR": 3,
    "TPO ": 7,
    "RPO ": 300,
    "PREC": "SECS",
    "CSC ": "STD01",
    "SUBN": "447700900123:1"
  }
}
```

**Request Body Fields (BODY):**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to reserve against. Used for routing. |
| `AREF` | Account Reference | int | **M** | Account reference ID (`CCS_ACCR_REFERENCE.ID`). |
| `ACTY` | Account Type | int | **M** | Account type identifier. |
| `CLI ` | Calling Line ID | string | **M** | The originating subscriber's MSISDN. |
| `DN  ` | Dialled Number | string | **M** | The destination number dialled by the subscriber. |
| `CDAT` | Call Date | date (Unix) | **M** | Date/time of the call in GMT. |
| `TZ  ` | Time Zone | string | **M** | Time zone string (e.g. `"GMT"`, `"Europe/London"`). |
| `ERSL` | Expected Reservation Length | int | **M** | The expected length of the reservation in precision units (see `PREC`). Used to pre-allocate funds. |
| `BCOR` | Balance Cascade Override | int | O | Override for the balance cascade order. |
| `TPO ` | Tariff Plan Override | int | O | Override the tariff plan ID used for rating. |
| `RPO ` | Reservation Period Override | int | O | Override the reservation period in seconds. |
| `PREC` | Precision | Symbol | O | Unit of measurement for time values. `"SECS"` (seconds) or `"MINS"` (minutes). Defaults to `"SECS"`. |
| `CSC ` | Call Scenario Code | string | O | The call scenario code used for tariff selection (e.g. `"STD01"`). |
| `SUBN` | Subscriber Number | string | O | Subscriber identifier string, often in the format `"MSISDN:instance"`. |
| `BTOR` | Balance Type Override | int | O | Override for the balance type to deduct from. |

**Successful Response (ACK):**

```json
{
  "format": "raw",
  "message": {
    "ACTN": "ACK ",
    "TYPE": "IR  ",
    "HEAD": {
      "SVID": 1,
      "CMID": 2001,
      "VER ": 100,
      "DUP ": 0
    },
    "BODY": {
      "NUM ": 120,
      "TOT ": 14400,
      "LOWT": 30,
      "FCD ": "HON ",
      "TCOD": "PEAK",
      "LOWA": 60
    }
  }
}
```

**ACK Body Fields:**

| Symbol | Name | Type | Description |
|---|---|---|---|
| `NUM ` | Number of Units Granted | int | The number of units (in `PREC` units) the caller is authorised to use. The call must end or a Subsequent Reservation (`SR`) must be sent before these expire. |
| `TOT ` | Total Available | int | Total units available in the wallet (in `PREC` units). |
| `LOWT` | Low Credit Time | int | If the wallet is nearing empty, the number of seconds until it runs out. Used to trigger low-balance announcements. |
| `FCD ` | Free Call Disposition | Symbol | How to handle free calls. `"HON "` = honour free call, `"IGNR"` = ignore free call rules, `"REL "` = release the call. |
| `TCOD` | Tariff Code | string | The tariff code that was applied (e.g. `"PEAK"`, `"OFF-PEAK"`). |
| `LOWA` | Low Balance Announcement | int | Threshold (in units) at which a low-balance announcement should be played. |

**NAck Response Example (Insufficient Funds):**

```json
{
  "format": "raw",
  "message": {
    "ACTN": "NACK",
    "TYPE": "IR  ",
    "HEAD": {
      "SVID": 1,
      "CMID": 2002,
      "VER ": 100,
      "DUP ": 0
    },
    "BODY": {
      "CODE": "INSF",
      "WHAT": "Insufficient funds in wallet 12345"
    }
  }
}
```

**Possible NAck Codes:** `INSF`, `WDIS`, `TMNY`, `CRIS`, `NACC`, `NGEO`, `NRAT`, `NBIL`, `NCAS`, `NTAR`, `MAXL`, `NOSC`, `SYSF`

---

### 5.3 GET /api/stats

Returns usage statistics for the API gateway, broken into time-period buckets. This endpoint is useful for monitoring call volumes, detecting unusual patterns, and auditing unauthorised access attempts.

**HTTP Method:** `GET`

**URL:** `/api/stats`

**Authentication:** Requires a valid JWT token with `/stats` in `allowedEndpoints`.

**Query Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `hours` | int | No | `24` | How many hours of historical data to return. |

**Request Example:**

```
GET /api/stats?hours=1
Authorization: Bearer <token>
```

**Response:**

```json
{
  "periodMinutes": 15,
  "periodAggregates": [
    {
      "periodStart": "2026-03-27T10:00:00.000Z",
      "totalCalls": 42,
      "unauthorisedAttempts": 2,
      "byEndpoint": {
        "/wallet-info": 30,
        "/initial-reservation": 12
      },
      "byClient": {
        "MyBillingSystem": 40,
        "TestClient": 2
      }
    },
    {
      "periodStart": "2026-03-27T10:15:00.000Z",
      "totalCalls": 18,
      "unauthorisedAttempts": 0,
      "byEndpoint": {
        "/wallet-info": 18
      },
      "byClient": {
        "MyBillingSystem": 18
      }
    }
  ]
}
```

**Response Fields:**

| Field | Type | Description |
|---|---|---|
| `periodMinutes` | int | The size of each time bucket in minutes. |
| `periodAggregates` | array | An array of period bucket objects, ordered chronologically. |
| `periodAggregates[].periodStart` | ISO8601 string | The start time of this bucket. |
| `periodAggregates[].totalCalls` | int | Total number of API calls in this period. |
| `periodAggregates[].unauthorisedAttempts` | int | Number of requests rejected due to missing, invalid, or expired tokens, or insufficient endpoint permissions. |
| `periodAggregates[].byEndpoint` | object | Breakdown of successful calls by endpoint path. |
| `periodAggregates[].byClient` | object | Breakdown of calls by `clientId` (from the JWT token). |

---

## 6. Message Type Reference

The following section documents all supported BE Protocol message types. While the REST gateway currently exposes `/wallet-info` and `/initial-reservation` as dedicated endpoints, the underlying message protocol supports a full range of operations. Future endpoint additions will use the same message structures described here.

---

### 6.1 Wallet Operations

#### WI — Wallet Info

Retrieves the current state and balance details of a wallet. See [Section 5.1](#51-post-apiwallet-info) for full detail.

| | |
|---|---|
| **Type Symbol** | `WI  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |
| **Failure Response** | `NACK` |

---

#### WC — Wallet Create

Creates a new wallet with an initial set of balances and buckets.

| | |
|---|---|
| **Type Symbol** | `WC  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | Pass `0` to allow the system to assign an ID. |
| `CLI ` | Calling Line ID | string | **M** | Subscriber MSISDN. |
| `WTYP` | Wallet Type | int | **M** | Wallet type identifier. |
| `ACTY` | Account Type | int | **M** | Account type ID. |
| `STAT` | State | Symbol | **M** | Initial wallet state. See [Section 10](#10-wallet-state-reference). |
| `MAXC` | Max Concurrent | int | **M** | Maximum concurrent sessions. |
| `EXPR` | Expiry Date | date (Unix) | **M** | When the wallet expires. |
| `ACTV` | Activation Date | date (Unix) | **M** | When the wallet becomes active. |
| `SPID` | Service Provider ID | int | **M** | Service Provider identifier. |
| `ABAL` | Alter Balances | array | **M** | Array of `BalanceInfo` objects defining the initial balances. |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "WC  ",
  "HEAD": { "SVID": 1, "CMID": 8001 },
  "BODY": {
    "WALT": 0,
    "CLI ": "447700900123",
    "WTYP": 1,
    "ACTY": 5,
    "STAT": "ACTV",
    "MAXC": 3,
    "EXPR": 1805571629,
    "ACTV": 1774035629,
    "SPID": 101,
    "ABAL": [
      {
        "BTYP": 1,
        "LIMT": "DEBT",
        "BKTS": [
          { "ID  ": 0, "VAL ": 100000, "EXPR": null }
        ]
      }
    ]
  }
}
```

---

#### WU — Wallet Update

Updates an existing wallet's properties and/or balances.

| | |
|---|---|
| **Type Symbol** | `WU  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to update. |
| `AREF` | Account Reference | int | O | Account reference ID. |
| `ACTY` | Account Type | int | O | Account type ID. |
| `STAT` | State | Symbol | O | New wallet state. |
| `MAXC` | Max Concurrent | int | O | New maximum concurrent sessions value. |
| `SPLG` | Suppress Plugins | null | O | If `null`, suppresses plugin execution. |
| `ABID` | Account Batch ID | int | O | Account batch ID. |
| `NACT` | New Account Type | int | O | New account type (replaces `ACTY`). |
| `ABAL` | Alter Balances | array | O | Array of balance modifications. |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "WU  ",
  "HEAD": { "SVID": 1, "CMID": 8002 },
  "BODY": {
    "WALT": 12345,
    "AREF": 999,
    "ACTY": 5,
    "STAT": "ACTV",
    "MAXC": 5,
    "SPLG": null,
    "ABID": 0,
    "NACT": 6,
    "ABAL": [
      {
        "BTYP": 1,
        "BKTS": [ { "ID  ": 1, "VAL ": 5000 } ]
      }
    ]
  }
}
```

---

#### WD — Wallet Delete

Permanently deletes a wallet.

| | |
|---|---|
| **Type Symbol** | `WD  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to delete. |
| `CLI ` | Calling Line ID | string | **M** | Subscriber MSISDN (for audit). |
| `WTYP` | Wallet Type | int | **M** | Wallet type. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `DLKW` | Delete Locked Wallet | null | O | If present (as `null`), allows deletion even if the wallet is locked. |
| `DLRM` | Don't Log Remove | null | O | If present, suppresses the removal log entry. |

---

#### WRI — Wallet Reservations Info

Retrieves details of all active reservations on a wallet.

| | |
|---|---|
| **Type Symbol** | `WRI ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to query. |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "WRI ",
  "HEAD": { "SVID": 1, "CMID": 13001 },
  "BODY": { "WALT": 12345 }
}
```

---

#### WRE — Wallet Reservation End

Forces the end of a specific reservation on a wallet.

| | |
|---|---|
| **Type Symbol** | `WRE ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet. |
| `SCPI` | SCP ID / Client ID | int | **M** | First half of the reservation key (Client ID). |
| `CALI` | Call ID | int | **M** | Second half of the reservation key (Call/Message ID). |
| `RESO` | Reservation Operation | int | **M** | The operation to perform: `1` = Commit, `2` = Revoke, `3` = Timeout. |

---

#### WGR — Wallet General Recharge

Performs a generalised recharge operation on a wallet, applying credit to one or more balance buckets according to a recharge policy.

| | |
|---|---|
| **Type Symbol** | `WGR ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to recharge. |
| `AREF` | Account Reference | int | **M** | Account reference ID. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `SPID` | Service Provider ID | int | **M** | Service Provider ID. |
| `WTYP` | Wallet Type | int | **M** | Wallet type. |
| `AEXP` | Account Expiry | date (Unix) | O | New account expiry date to apply after recharge. |
| `APOL` | Account Expiry Policy | Symbol | O | Policy symbol for account expiry calculation (e.g. `"AXPB"`). |
| `BPOL` | Balance Expiry Policy | Symbol | O | Policy symbol for balance expiry calculation (e.g. `"BXPB"`). |
| `AEXT` | Account Expiry Extension | int | O | Number of days to extend the account expiry. |
| `BEXT` | Balance Expiry Extension | int | O | Number of days to extend the balance expiry. |
| `ACFB` | Apply Config Bonus | null | O | If present, applies configured bonus logic to the recharge. |
| `MBPO` | Missing Balance Policy | Symbol | O | Policy if balance type doesn't exist (`MBPA` = Allow, `MBPF` = Fail). |
| `UDWS` | Update Wallet Status | null | O | Controls wallet status update. |
| `RBAA` | Recharge Balance Array | array | **M** | Array of recharge balance instructions. See `RBAA` structure below. |

**`RBAA` (Recharge Balance Array) Item:**

| Symbol | Name | Type | Description |
|---|---|---|---|
| `BTYP` | Balance Type | int | The balance type to recharge. |
| `DBKP` | Delete Bucket Policy | Symbol | Policy for handling deleted buckets. |
| `RBIA` | Recharge Bucket Info Array | array | Array of bucket recharge instructions. |

**`RBIA` Item:**

| Symbol | Name | Type | Description |
|---|---|---|---|
| `BKID` | Bucket ID | int | `-1` to create a new bucket, or the ID of an existing bucket to update. |
| `VAL ` | Value | int | Amount to add (in system currency units). |
| `BEXT` | Balance Expiry Extension | int | Days to extend bucket expiry. |
| `BPOL` | Bucket Expiry Policy | Symbol | Policy for bucket expiry. |
| `BNEW` | New Bucket | null | If non-null, forces creation of a new bucket. |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "WGR ",
  "HEAD": { "SVID": 1, "CMID": 9001 },
  "BODY": {
    "WALT": 12345,
    "AREF": 999,
    "ACTY": 5,
    "SPID": 101,
    "WTYP": 1,
    "AEXP": 1805571629,
    "APOL": "AXPB",
    "BPOL": "BXPB",
    "AEXT": 720,
    "BEXT": 720,
    "RBAA": [
      {
        "BTYP": 1,
        "DBKP": "AXPB",
        "RBIA": [
          {
            "BKID": -1,
            "VAL ": 10000,
            "BEXT": 720,
            "BPOL": "BXPB",
            "BNEW": null
          }
        ]
      }
    ]
  }
}
```

---

#### WSI — Wallet State Information

Returns the current state of a wallet without full balance detail.

| | |
|---|---|
| **Type Symbol** | `WSI ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to query. |

---

#### MGW — Merge Wallets

Merges the balances from a source wallet into a target wallet.

| | |
|---|---|
| **Type Symbol** | `MGW ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |
| **Failure Response** | `NACK` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `SPID` | Service Provider ID | int | **M** | Service Provider. |
| `TSUB` | Target Subscriber | int | **M** | Target subscriber ID. |
| `TWID` | Target Wallet ID | int | **M** | The wallet that will receive the merged balances. |
| `TDID` | Target Domain ID | int | **M** | Target domain ID. |
| `TATI` | Target Account Type | int | **M** | Target account type. |
| `SSUB` | Source Subscriber | int | **M** | Source subscriber ID. |
| `SWID` | Source Wallet ID | int | **M** | The wallet whose balances will be merged into the target. |
| `SDID` | Source Domain ID | int | **M** | Source domain ID. |
| `SCLI` | Source CLI | string | **M** | Source subscriber MSISDN. |
| `SCID` | Source Currency ID | int | **M** | Source currency (ISO 4217 integer). |
| `SATI` | Source Account Type | int | **M** | Source account type. |
| `SWTI` | Source Wallet Type | int | **M** | Source wallet type. |

**NAck Codes:** `NSSW`, `NSTW`, `SWIR`, `TWID`, `TWNR`, `BSWS`, `BTWS`, `NTMR`, `NODB`, `NSPI`, `NSSI`, `NTSI`, `NSCL`, `NSCI`, `NTAT`, `NSAT`, `NSWT`, `IERR`, `MBEP`, `MWEP`, `ASWS`

---

### 6.2 Call Reservation Flow

The standard call charging lifecycle follows this sequence:

```
IR_Req → IR_Ack
           │
           ├─(if more time needed)→ SR_Req → SR_Ack → (repeat)
           │
           └─(call ends)────────────────────────────────────────┐
                                                                  │
                                 ┌────────────────────────────────┘
                                 │
                     ┌───────────┴────────────┐
                     │                         │
                   CR_Req                    RR_Req
               (Commit: charge               (Revoke: no charge,
                units used)                   e.g. call dropped)
                     │                         │
                  CR_Ack                     RR_Ack
```

#### IR — Initial Reservation

See [Section 5.2](#52-post-apiinitial-reservation) for full detail.

---

#### SR — Subsequent Reservation

Extends an existing reservation. Must be sent before the units granted by the `IR_Ack` (or previous `SR_Ack`) are exhausted.

| | |
|---|---|
| **Type Symbol** | `SR  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |
| **Failure Response** | `NACK` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet (must match the originating `IR_Req`). |
| `TUC ` | Total Units Consumed | int | O | Total units consumed so far in the call. |
| `ERSL` | Expected Reservation Length | int | O | Requested extension length in precision units. |
| `NUM ` | Number of Units | int | O | Specific number of units to request (alternative to `ERSL`). |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "SR  ",
  "HEAD": { "SVID": 1, "CMID": 2003 },
  "BODY": {
    "WALT": 12345,
    "TUC ": 60,
    "ERSL": 120,
    "NUM ": 30
  }
}
```

**ACK Body Fields:** Same as `IR_Ack` (`NUM `, `TOT `, `LOWT`, `FCD `, `TCOD`, `LOWA`).

**NAck Codes:** `INSF`, `WDIS`, `TMNY`, `TLNG`

---

#### CR — Commit Reservation

Commits the reservation and charges the wallet for the actual units consumed. Must be sent at the end of a call.

| | |
|---|---|
| **Type Symbol** | `CR  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet (must match the originating `IR_Req`). |
| `RESN` | Reason | Symbol | **M** | How the call ended. `"HANG"` = normal hangup, `"UNKN"` = unknown/abnormal. |
| `NUM ` | Units Consumed | int | **M** | The actual number of units consumed by the call. |
| `CDAT` | Call Date | date (Unix) | O | The date/time the call ended. |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "CR  ",
  "HEAD": { "SVID": 1, "CMID": 2004 },
  "BODY": {
    "WALT": 12345,
    "RESN": "HANG",
    "NUM ": 95,
    "CDAT": 1774035629
  }
}
```

---

#### RR — Revoke Reservation

Cancels an existing reservation without charging the wallet. Used when a call fails to connect, is dropped before connecting, or is otherwise abandoned.

| | |
|---|---|
| **Type Symbol** | `RR  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet. |
| `RESN` | Reason | Symbol | **M** | Why the reservation is being revoked. `"UNKN"` is typical for call drops. |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "RR  ",
  "HEAD": { "SVID": 1, "CMID": 2005 },
  "BODY": {
    "WALT": 12345,
    "RESN": "UNKN"
  }
}
```

---

#### ATC — Apply Tariffed Charge

Applies a tariffed charge to a wallet for a completed call, without a prior reservation. This is a one-shot charge operation (no IR/SR/CR lifecycle).

| | |
|---|---|
| **Type Symbol** | `ATC ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |
| **Failure Response** | `NACK` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to charge. |
| `AREF` | Account Reference | int | **M** | Account reference ID. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `CLI ` | Calling Line ID | string | **M** | Originating MSISDN. |
| `DN  ` | Dialled Number | string | **M** | Destination number. |
| `CDAT` | Call Date | date (Unix) | **M** | Date/time of the call (GMT). |
| `TZ  ` | Time Zone | string | **M** | Time zone. |
| `NUM ` | Units Consumed | int | **M** | Actual units consumed. |
| `RESN` | Reason | Symbol | **M** | Reason the call ended (e.g. `"HANG"`). |
| `BTOR` | Balance Type Override | int | O | Override for balance type. |
| `BCOR` | Balance Cascade Override | int | O | Override for balance cascade. |
| `TPO ` | Tariff Plan Override | int | O | Override for tariff plan. |
| `PREC` | Precision | Symbol | O | Unit of measurement: `"SECS"` or `"MINS"`. |
| `CSC ` | Call Scenario Code | string | O | Tariff selection code. |
| `SUBN` | Subscriber Number | string | O | Subscriber identifier. |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "ATC ",
  "HEAD": { "SVID": 1, "CMID": 3001 },
  "BODY": {
    "WALT": 12345,
    "AREF": 999,
    "ACTY": 5,
    "CLI ": "447700900123",
    "DN  ": "447911234567",
    "CDAT": 1774035629,
    "TZ  ": "GMT",
    "NUM ": 180,
    "RESN": "HANG",
    "BTOR": 1,
    "BCOR": 3,
    "TPO ": 7,
    "PREC": "SECS",
    "CSC ": "STD01",
    "SUBN": "447700900123:1"
  }
}
```

**NAck Codes:** `INSF`, `WDIS`, `NACC`, `NRAT`, `NCAS`

---

### 6.3 Named Event Operations

Named Events allow charging for non-voice services (e.g. data sessions, SMS, content downloads). Events are defined by a class and a name.

#### NE — Named Event

Charges for a named event directly (no reservation lifecycle).

| | |
|---|---|
| **Type Symbol** | `NE  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |
| **Failure Response** | `NACK` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to charge. |
| `AREF` | Account Reference | int | **M** | Account reference ID. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `CDAT` | Call Date | date (Unix) | **M** | Date/time of the event (GMT). |
| `TZ  ` | Time Zone | string | **M** | Time zone. |
| `EVTS` | Events | array | **M** | Array of Named Event descriptors. See below. |
| `NSFP` | No Suppress Free Period | int | O | `0` = normal, `1` = suppress any free period. |
| `WTYP` | Wallet Type | int | O | Wallet type. |
| `BTOR` | Balance Type Override | int | O | Balance type override. |
| `BCOR` | Balance Cascade Override | int | O | Balance cascade override. |

**Named Event Descriptor (item in `EVTS`):**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `CLSS` | Event Class | string | **M** | Category of the event (e.g. `"Data"`, `"SMS"`, `"Content"`). |
| `NAME` | Event Name | string | **M** | Specific event name (e.g. `"GPRS_Session"`, `"MT_SMS"`). |
| `MIN ` | Minimum | int | **M** | Minimum units to charge. |
| `MAX ` | Maximum | int | **M** | Maximum units to charge. |
| `DISC` | Discount | int | O | Discount percentage (0–100). |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "NE  ",
  "HEAD": { "SVID": 1, "CMID": 4001 },
  "BODY": {
    "WALT": 12345,
    "AREF": 999,
    "ACTY": 5,
    "CDAT": 1774035629,
    "TZ  ": "GMT",
    "EVTS": [
      {
        "CLSS": "Data",
        "NAME": "GPRS_Session",
        "MIN ": 1,
        "MAX ": 100,
        "DISC": 0
      }
    ],
    "NSFP": 0,
    "WTYP": 1,
    "BTOR": 2,
    "BCOR": 0
  }
}
```

---

#### INER / SNER / CNER / RNER — Named Event Reservation Lifecycle

Named Event Reservations allow pre-authorising an amount of named events before they occur, similar to the IR/SR/CR/RR lifecycle for voice calls.

| Type | Symbol | Description |
|---|---|---|
| Initial Named Event Reservation | `INER` | Reserve capacity for named events. Returns granted units per event. |
| Subsequent Named Event Reservation | `SNER` | Extend an existing named event reservation. |
| Confirm Named Event Reservation | `CNER` | Commit the reservation; charge for events actually consumed. |
| Revoke Named Event Reservation | `RNER` | Cancel the reservation without charging. |

**INER Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet. |
| `AREF` | Account Reference | int | **M** | Account reference. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `CDAT` | Call Date | date (Unix) | **M** | Event date (GMT). |
| `TZ  ` | Time Zone | string | **M** | Time zone. |
| `EVTS` | Events | array | **M** | Events to reserve for (class, name, min, max). |
| `ERSL` | Expected Reservation Length | int | **M** | Expected session duration in seconds. |
| `WTYP` | Wallet Type | int | O | Wallet type. |

**Example INER Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "INER",
  "HEAD": { "SVID": 1, "CMID": 4010 },
  "BODY": {
    "WALT": 12345,
    "AREF": 999,
    "ACTY": 5,
    "CDAT": 1774035629,
    "TZ  ": "GMT",
    "EVTS": [
      { "CLSS": "Data", "NAME": "GPRS_Session", "MIN ": 1, "MAX ": 500, "DISC": 0 }
    ],
    "ERSL": 3600,
    "WTYP": 1
  }
}
```

**Example CNER Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "CNER",
  "HEAD": { "SVID": 1, "CMID": 4012 },
  "BODY": {
    "WALT": 12345,
    "EVTS": [
      { "NUM ": 320, "DISC": 0 }
    ]
  }
}
```

---

### 6.4 Amount Reservation Operations

Amount Reservations allow a monetary amount to be reserved from a wallet, for use cases where the exact charge is unknown until after the fact (e.g. content purchases, data charging with unknown volume).

The lifecycle: `IARR → SARR (optional) → CARR or RARR`

| Type | Symbol | Description |
|---|---|---|
| Initial Amount Reservation | `IARR` | Reserve a monetary amount. Returns the amount reserved and session lifetime. |
| Subsequent Amount Reservation | `SARR` | Extend the amount reservation. |
| Confirm Amount Reservation | `CARR` | Commit; charge the wallet for the amount actually used. |
| Revoke Amount Reservation | `RARR` | Cancel without charging. |

**IARR Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to reserve from. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `AREF` | Account Reference | int | **M** | Account reference. |
| `LIFE` | Session Lifetime | int | **M** | Maximum duration of the reservation in seconds. |
| `WTYP` | Wallet Type | int | **M** | Wallet type. |
| `BTYP` | Balance Type | int | **M** | The specific balance type to reserve from. |
| `AMNT` | Amount | int | **M** | The amount to reserve (in system currency units). |
| `MINA` | Minimum Amount | int | **M** | Minimum acceptable reservation amount (e.g. if the full amount is unavailable). |
| `BALC` | Balance Cascade | int | O | Balance cascade strategy. |

**IARR ACK Body Fields:**

| Symbol | Name | Type | Description |
|---|---|---|---|
| `RSRV` | Reserved Amount | int | The amount actually reserved (may be less than `AMNT` if wallet has less than requested but more than `MINA`). |
| `TMLF` | Time to Live | int | Reservation lifetime in seconds. |

**Example IARR Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "IARR",
  "HEAD": { "SVID": 1, "CMID": 5001 },
  "BODY": {
    "WALT": 12345,
    "ACTY": 5,
    "AREF": 999,
    "LIFE": 3600,
    "WTYP": 1,
    "BTYP": 1,
    "AMNT": 10000,
    "MINA": 1000,
    "BALC": 2
  }
}
```

**Example CARR Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "CARR",
  "HEAD": { "SVID": 1, "CMID": 5003 },
  "BODY": {
    "WALT": 12345,
    "RESN": "HANG",
    "CNFM": 8500
  }
}
```

`CNFM` is the amount to actually charge (must be ≤ the reserved amount).

---

### 6.5 Direct Amount Operations

#### DA — Direct Amount

Applies a direct credit or debit to a wallet's balance, bypassing tariff calculations. Used for manual adjustments, refunds, or bonus credits.

| | |
|---|---|
| **Type Symbol** | `DA  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet to adjust. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `AREF` | Account Reference | int | **M** | Account reference. |
| `DDAM` | Direct Debit/Credit Amount | int | **M** | Amount to apply. **Negative values debit the wallet; positive values credit.** (e.g. `-500` charges 500 units; `+500` adds 500 units). |
| `WTYP` | Wallet Type | int | **M** | Wallet type. |
| `BTYP` | Balance Type | int | **M** | Balance type to apply the adjustment to. |
| `BALC` | Balance Cascade | int | O | Balance cascade strategy. |
| `BVMO` | Balance Validation Mode | int | O | `0` = validate balance before operation, `1` = skip validation. |
| `WVMO` | Wallet Validation Mode | int | O | `0` = validate wallet state, `1` = skip wallet state check. |

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "DA  ",
  "HEAD": { "SVID": 1, "CMID": 6001 },
  "BODY": {
    "WALT": 12345,
    "ACTY": 5,
    "AREF": 999,
    "DDAM": -500,
    "WTYP": 1,
    "BTYP": 1,
    "BALC": 2,
    "BVMO": 0,
    "WVMO": 0
  }
}
```

---

### 6.6 Rate Query Operations

Rate queries allow the caller to discover the tariff rates that would be applied to a call or event, without actually charging anything.

#### USR — Unit Second Rate

Returns the per-second (or per-minute) rate for a voice call.

| | |
|---|---|
| **Type Symbol** | `USR ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `CLI ` | Calling Line ID | string | **M** | Originating MSISDN. |
| `DN  ` | Dialled Number | string | **M** | Destination number. |
| `CDAT` | Call Date | date (Unix) | **M** | Date/time (GMT). |
| `TZ  ` | Time Zone | string | **M** | Time zone. |
| `AREF` | Account Reference | int | **M** | Account reference. |
| `PREC` | Precision | Symbol | O | `"SECS"` or `"MINS"`. |
| `CSC ` | Call Scenario Code | string | O | Tariff selection code. |

---

#### NER — Named Event Rate

Returns the rate for a named event without charging.

| | |
|---|---|
| **Type Symbol** | `NER ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `CLSS` | Event Class | string | **M** | Event class (e.g. `"Data"`). |
| `NAME` | Event Name | string | **M** | Event name (e.g. `"GPRS_Session"`). |
| `CDAT` | Call Date | date (Unix) | **M** | Date/time (GMT). |
| `TZ  ` | Time Zone | string | **M** | Time zone. |

---

### 6.7 Voucher Operations

#### VI — Voucher Info

Returns information about a voucher without redeeming it.

| | |
|---|---|
| **Type Symbol** | `VI  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `VNUM` | Voucher Number | string | **M** | The voucher number (typically the PIN printed on the voucher card). |
| `SPID` | Service Provider ID | int | **M** | Service Provider. |

---

#### VR — Voucher Redeem

Initiates a voucher redemption against a wallet. Two-phase: VR then CVR (commit) or RVR (revoke).

| | |
|---|---|
| **Type Symbol** | `VR  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |
| **Failure Response** | `NACK` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `VNUM` | Voucher Number | string | **M** | The voucher PIN/number. |
| `SPID` | Service Provider ID | int | **M** | Service Provider. |
| `RWLT` | Redeeming Wallet ID | int | **M** | The wallet to credit on successful redemption. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `RARF` | Redeeming Account Ref | string | **M** | The redeeming subscriber reference (e.g. MSISDN). |
| `SCEN` | Scenario | int | O | Scenario ID controlling the redemption behaviour. `0` = default. |

**NAck Codes:** `NVOU`, `AVOU`, `VARD`, `VFRZ`, `VDEL`, `VPIN`, `INVD`, `VBUA`, `LVOU`

**Example Request:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "VR  ",
  "HEAD": { "SVID": 1, "CMID": 10002 },
  "BODY": {
    "VNUM": "1234567890",
    "SPID": 101,
    "RWLT": 12345,
    "ACTY": 5,
    "RARF": "447700900123",
    "SCEN": 0
  }
}
```

---

#### CVR — Commit Voucher Redeem

Commits the pending voucher redemption (called after a successful `VR_Ack`).

| | |
|---|---|
| **Type Symbol** | `CVR ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `VNUM` | Voucher Number | string | **M** | The voucher number. |
| `SCEN` | Scenario | int | O | Scenario ID. |

---

#### RVR — Revoke Voucher Redeem

Cancels a pending voucher redemption (called after a `VR_Ack` if the operation should be abandoned).

| | |
|---|---|
| **Type Symbol** | `RVR ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `VNUM` | Voucher Number | string | **M** | The voucher number. |

---

#### VRW — Voucher Redeem Wallet

A combined operation that redeems a voucher and creates or updates a wallet in one step.

| | |
|---|---|
| **Type Symbol** | `VRW ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `VNUM` | Voucher Number | string | **M** | Voucher PIN. |
| `SPID` | Service Provider ID | int | **M** | Service Provider. |
| `WTSP` | Wallet Type Service Provider | int | **M** | Wallet type for service provider. |
| `RWLT` | Redeeming Wallet ID | int | **M** | Target wallet. |
| `AREF` | Account Reference | int | **M** | Account reference. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `SVID` | BE Server ID | int | **M** | BE Server ID. |
| `WALR` | Wallet Reference | string | **M** | Wallet reference string. |
| `SUBN` | Subscriber Number | string | **M** | Subscriber MSISDN. |
| `RARF` | Redeeming Account Ref | string | **M** | Redeeming subscriber reference. |
| `RWAL` | Redeeming Wallet | int | O | If non-zero, an existing wallet to recharge. |
| `SCEN` | Scenario | int | O | Scenario ID. |

---

#### VU — Voucher Update

Updates a voucher's status (e.g. marking it as redeemed after an out-of-band process).

| | |
|---|---|
| **Type Symbol** | `VU  ` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `VNUM` | Voucher Number | string | **M** | Voucher number. |
| `STAT` | State | Symbol | **M** | New voucher state (e.g. `"RDMD"` = Redeemed). |
| `RWLT` | Redeeming Wallet | int | O | Wallet that redeemed the voucher. |
| `DATE` | Date | date (Unix) | O | Date of the update. |

---

#### VTR / VTRC — Voucher Type Recharge / Confirm

Recharges a wallet using a voucher type name (as opposed to a specific voucher PIN). `VTR` initiates the recharge; `VTRC` confirms it.

**VTR Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `VNME` | Voucher Type Name | string | **M** | The name of the voucher type (e.g. `"STANDARD_RECHARGE_10"`). |
| `SPID` | Service Provider ID | int | **M** | Service Provider. |
| `WALT` | Wallet ID | int | **M** | The wallet to recharge. |
| `AREF` | Account Reference | int | **M** | Account reference. |
| `ACTY` | Account Type | int | **M** | Account type. |
| `SVID` | BE Server ID | int | **M** | BE Server ID. |
| `WALR` | Wallet Reference | string | **M** | Wallet reference string. |
| `SUBN` | Subscriber Number | string | **M** | Subscriber MSISDN. |

---

#### BPIN — Bad PIN

Records a bad PIN attempt for a wallet (used for voucher redemption PIN validation).

| | |
|---|---|
| **Type Symbol** | `BPIN` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `WALT` | Wallet ID | int | **M** | The wallet. |
| `AREF` | Account Reference | int | **M** | Account reference. |
| `ACTY` | Account Type | int | **M** | Account type. |

**ACK Body Fields:**

| Symbol | Name | Type | Description |
|---|---|---|---|
| `STAT` | Wallet State | Symbol | Current wallet state after recording the bad PIN. |
| `PINC` | Bad PIN Count | int | Total number of consecutive bad PIN attempts. |

---

### 6.8 Administrative Operations

#### LDMF — Reload MFile

Instructs the BE Server to reload its Master File (MFile) configuration. Used after configuration changes.

| | |
|---|---|
| **Type Symbol** | `LDMF` |
| **Request Action** | `REQ ` |
| **Success Response** | `ACK ` |

**Request Body Fields:**

| Symbol | Name | Type | M/O | Description |
|---|---|---|---|---|
| `MFTY` | MFile Type | string | **M** | Which MFile to reload. `"MAIN"` = the main configuration file. |

> **Warning:** This is an administrative operation and should only be callable by privileged tokens. Ensure `/api/reload-mfile` (or equivalent) is NOT included in general integration tokens.

---

#### BEG — Begin Communication

Registers a BE Client with the BE Server. This is typically handled internally by the gateway and does not need to be sent by third-party integrations.

#### CHKD — Check Dialect

Verifies that the BE Server understands the protocol version specified in `HEAD.VER`. Handled internally by the gateway.

#### HTBT — Heartbeat

A keepalive message sent over the TCP connection to detect link failures. Not applicable to the REST API layer; handled internally.

---

## 7. Response Types

### 7.1 ACK (Positive Acknowledgement)

An `ACK` response indicates the request was processed successfully.

```json
{
  "ACTN": "ACK ",
  "TYPE": "<same-type-as-request>",
  "HEAD": { "SVID": 1, "CMID": <echo-of-request-cmid>, "VER ": 100 },
  "BODY": { ... }
}
```

The `BODY` fields of an ACK are specific to each message type (documented per-operation above).

---

### 7.2 NACK (Negative Acknowledgement)

A `NACK` indicates the system is working correctly but the specific request could not be fulfilled. This is a business-logic failure, not a system error (e.g. insufficient funds, wallet disabled).

```json
{
  "ACTN": "NACK",
  "TYPE": "<same-type-as-request>",
  "HEAD": { "SVID": 1, "CMID": <echo>, "VER ": 100 },
  "BODY": {
    "CODE": "<nack-code>",
    "WHAT": "<human-readable-description>"
  }
}
```

| Symbol | Name | Type | Description |
|---|---|---|---|
| `CODE` | NAck Code | Symbol (4-char) | Machine-readable reason code. See [Section 8](#8-nack-code-reference). |
| `WHAT` | Description | string | Human-readable explanation of why the request was declined. |

---

### 7.3 EXCP (Exception)

An `EXCP` response indicates a system-level failure. These should never occur in normal operation and should always be logged and investigated.

```json
{
  "ACTN": "EXCP",
  "TYPE": "<exception-type>",
  "HEAD": { "SVID": 1, "CMID": <echo>, "VER ": 100 },
  "BODY": {
    "CODE": "<exception-code>",
    "WHAT": "<human-readable-description>"
  }
}
```

| Exception Type (`TYPE`) | Description |
|---|---|
| `COM ` | Communications Exception — the message could not be delivered. |
| `MSG ` | Message Exception — the message was malformed or unrecognised. |
| `DATA` | Data Exception — a field contained an invalid value (e.g. a wallet ID that doesn't exist). |
| `PROC` | Processing Exception — an internal processing failure occurred (e.g. a VWARS error). |

---

## 8. NAck Code Reference

| Code | Symbol Name | Applicable To | Description |
|---|---|---|---|
| `INSF` | Insufficient Funds | IR, SR, ATC, NE | The wallet has insufficient balance to complete the operation. |
| `CRIS` | Call Restricted | IR, ATC | The call is restricted for this calling/called number. |
| `NACC` | No Account Type Entry | IR, ATC, NE | No account type entry found in the MFile for this configuration. |
| `NGEO` | Geography Not Defined | IR | No geography set defined in the MFile. |
| `NRAT` | No Rate Info | IR, ATC, NER | No rate information defined in the MFile for this call. |
| `NBIL` | No Billing Periods | IR | No billing periods defined in the MFile. |
| `NCAS` | No Balance Type Cascade | IR, ATC | No balance type cascade defined. |
| `NBPN` | No Bad PIN Balance Type | BPIN | No bad PIN balance type configured. |
| `NTAR` | No Tariff Plan Selector | IR | No tariff plan selector entry found. |
| `MAXL` | Max Call Length | IR | Maximum configured call length would be exceeded. |
| `WDIS` | Wallet Disabled | IR, WI | Wallet state is not active (see wallet state for specifics). |
| `NRCH` | Balance Not Rechargeable | WGR | The balance's limit type is `SUSE` (single-use debit) and cannot be recharged. |
| `TMNY` | Too Many Concurrent | IR, SR | The wallet has reached its maximum concurrent session limit (`MAXC`). |
| `WBIN` | Wallet Batch Inactive | IR | The wallet's batch is inactive. |
| `BBDS` | Wallet Batch Disabled | IR | The wallet's batch is disabled. |
| `BKOV` | Bucket Overflow | DA | Adding to the bucket would cause an overflow (value > 2^32). |
| `NENA` | Named Event Not Allowed | NE, INER | No configuration entry for this named event/account type combination. |
| `TLNG` | Call Too Long | SR | The call has exceeded the maximum permitted length. |
| `NOSC` | No System Currency | IR | No system currency defined in the configuration. |
| `NVOU` | Unknown Voucher | VR | The voucher number was not found. |
| `AVOU` | Ambiguous Voucher | VR | More than one voucher matched the given number. |
| `VARD` | Voucher Already Redeemed | VR | The voucher has already been redeemed. |
| `VFRZ` | Voucher Frozen | VR | The voucher is in a frozen state and cannot be redeemed. |
| `VDEL` | Voucher Deleted | VR | The voucher has been deleted. |
| `VPIN` | Voucher Auth Failed | VR | The PIN provided with the voucher is incorrect. |
| `INVD` | Invalid Voucher Digits | VR | The voucher number format is invalid. |
| `VBUA` | Voucher Batch Unavailable | VRW | The voucher batch is not available for the recharge. |
| `BDVV` | Bad Voucher Value | WGR | The voucher value was not found in the Bonus Recharge table. |
| `BDVR` | Bad Recharge Attempt | WGR | Cannot recharge a balance with zero extension when no existing balance exists. |
| `LVOU` | Limited Voucher | VR | Voucher is restricted and not available for this account type. |
| `SNIL` | State Not In List | WU | The wallet state was not in the permitted list for this operation. |
| `SINV` | Invalid State | WU | The new state value is invalid. |
| `SYSF` | System Failure | Various | Miscellaneous system failure. |
| `BSCN` | Bad Scenario | VR, VRW | The scenario ID provided is invalid. |
| `REQD` | Request Declined | Various | The request was declined (generic). |
| `NBTY` | No Balance Type | IARR | The specified balance type does not exist. |
| `NCNT` | No Context Data | SR, CR | No context data found (i.e. no prior `IR_Req` exists for this session). |
| `WNR ` | Wallet Not Rechargeable | WGR | The wallet type does not support recharging. |
| `NSSW` | No Such Source Wallet | MGW | The source wallet ID does not exist. |
| `NSTW` | No Such Target Wallet | MGW | The target wallet ID does not exist. |
| `SWIR` | Source Wallet Is Reserved | MGW | The source wallet has active reservations and cannot be merged. |
| `TWID` | Target Wallet Is Disabled | MGW | The target wallet is in a disabled state. |
| `TWNR` | Target Wallet Not Rechargeable | MGW | The target wallet type does not support recharging. |
| `BSWS` | Bad Source Wallet State | MGW | The source wallet is not in an acceptable state for merging. |
| `BTWS` | Bad Target Wallet State | MGW | The target wallet is not in an acceptable state for merging. |
| `NTMR` | Nothing To Merge | MGW | No balances were available to merge or relink. |
| `NODB` | Could Not Log In DB | MGW | Database logging failed during the merge. |
| `NSPI` | No Service Provider ID | MGW | Service Provider ID is missing or invalid. |
| `NSSI` | No Source Subscriber ID | MGW | Source subscriber ID is missing. |
| `NTSI` | No Target Subscriber ID | MGW | Target subscriber ID is missing. |
| `NSCL` | No Source CLI | MGW | Source CLI (MSISDN) is missing. |
| `NSCI` | No Source Currency ID | MGW | Source currency ID is missing. |
| `NTAT` | No Target Account Type | MGW | Target account type ID is missing. |
| `NSAT` | No Source Account Type | MGW | Source account type ID is missing. |
| `NSWT` | No Source Wallet Type | MGW | Source wallet type ID is missing. |
| `IERR` | Internal Merge Error | MGW | An internal error occurred during the merge operation. |

---

## 9. Exception Code Reference

### Communications Exceptions (`TYPE: "COM "`)

| Code | Description |
|---|---|
| `XCLI` | Could not contact the BE Client. |
| `XSEQ` | Message sequence error (e.g. an `SR_Req` received before an `IR_Req`). |
| `UNSE` | Unknown BE Server ID — the target server could not be resolved. |
| `XSER` | Could not contact either server in the BE Server pair. |
| `TIMD` | Message timed out — no response received from the BE Server within the configured timeout period. |

### Message Exceptions (`TYPE: "MSG "`)

| Code | Description |
|---|---|
| `UNMS` | Unknown message — the action/type combination was not recognised. |
| `UNVE` | Unknown version — the protocol version was not supported. |
| `MIFD` | Missing field — a mandatory field was absent from the message. |
| `TYFD` | Bad field type — a field was present but had the wrong data type. |
| `CRPT` | Corrupt message — the internal message structure was invalid. |

### Data Exceptions (`TYPE: "DATA"`)

| Code | Description |
|---|---|
| *(field symbol)* | The `CODE` field contains the symbol of the field whose value was invalid. The `WHAT` and `STRV` fields describe the bad value. |

### Processing Exceptions (`TYPE: "PROC"`)

| Code | Description |
|---|---|
| `VWAR` | A failure occurred in the BE VWARS component. |
| `PLUG` | A failure occurred in a BE Server message-handler plugin. |

---

## 10. Wallet State Reference

The `STAT` field on wallet-related messages uses one of the following 4-character symbols:

| Symbol | Name | Description |
|---|---|---|
| `ACTV` | Active | The wallet is active and can be charged. |
| `DORM` | Dormant | The wallet exists but is in a dormant (inactive) state. |
| `FROZ` | Frozen | The wallet is frozen; no charging is permitted. |
| `PREU` | Pre-Use | The wallet has been created but not yet activated. |
| `SUSP` | Suspended | The wallet is suspended (e.g. due to non-payment). |
| `TERM` | Terminated | The wallet has been terminated permanently. |

---

## 11. Balance Limit Type Reference

The `LIMT` field on `BalanceInfo` objects indicates the type of balance limit in effect:

| Symbol | Name | Description |
|---|---|---|
| `DEBT` | Debit | A standard debit balance. Value decreases as charges are applied. |
| `CRED` | Credit | A credit balance. Value increases as credits are applied. |
| `LCRD` | Limited Credit | A credit balance with a defined maximum credit limit. |
| `SUSE` | Single Use Debit | A debit balance that can only be used once and cannot be recharged. |

---

## 12. Error Handling

### HTTP-Level Errors

| HTTP Status | Meaning |
|---|---|
| `200 OK` | Request was processed. The response body contains the BE response (which may be an ACK, NACK, or EXCP). |
| `400 Bad Request` | The request body was malformed or could not be parsed as valid JSON. |
| `401 Unauthorized` | Authentication failed (missing, invalid, or expired token). |
| `403 Forbidden` | Token is valid but does not have permission for this endpoint. |
| `500 Internal Server Error` | The REST gateway encountered an unexpected error. |
| `502 Bad Gateway` | The gateway could not contact the BE Server (both primary and secondary are unreachable). |
| `504 Gateway Timeout` | The BE Server did not respond within the configured timeout. |

### BE-Level Errors

BE-level errors are returned with HTTP `200 OK` but with `ACTN: "NACK"` or `ACTN: "EXCP"` in the message body.

- **NACK** responses indicate a business logic rejection. These are expected and should be handled by the calling application (e.g. play an "insufficient funds" announcement).
- **EXCP** responses indicate a system failure. These should trigger alerts and be investigated. They should not occur in normal operation.

### Retry and Idempotency

- If you receive a `502` or `504` response, the request may not have been processed. Use `HEAD.DUP ` set to `1` when retrying to signal that the message may be a duplicate.
- If the gateway's failover to the secondary engine occurs mid-request, the response will indicate which engine handled the call.
- For operations that must be idempotent (e.g. after a crash during commit), use the `HEAD.CMID` to correlate requests and check whether an operation already succeeded before retrying.

---

## 13. Integration Examples

### Example 1: Check Wallet Balance (Node.js)

```javascript
const jwt = require('jsonwebtoken');

const SECRET = process.env.BE_JWT_SECRET;
const API_BASE_URL = 'http://localhost:3010/api';

const token = jwt.sign(
  { clientId: 'MyIntegration', allowedEndpoints: ['/wallet-info'] },
  SECRET,
  { expiresIn: '1h' }
);

async function getWalletInfo(walletId) {
  const payload = {
    "ACTN": "REQ ",
    "TYPE": "WI  ",
    "HEAD": { "SVID": 1, "CMID": Date.now() % 100000 },
    "BODY": { "WALT": walletId }
  };

  const response = await fetch(`${API_BASE_URL}/wallet-info`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`HTTP error: ${response.status}`);
  }

  const { format, message } = await response.json();

  if (message.ACTN === 'ACK ') {
    console.log('Wallet state:', message.BODY.STAT);
    console.log('Balances:', JSON.stringify(message.BODY.BALS, null, 2));
    return message.BODY;
  } else if (message.ACTN === 'NACK') {
    console.warn('Wallet query declined:', message.BODY.CODE, message.BODY.WHAT);
    return null;
  } else {
    console.error('System exception:', message.BODY.WHAT);
    throw new Error(message.BODY.WHAT);
  }
}

getWalletInfo(12345);
```

---

### Example 2: Voice Call Reservation Lifecycle (Node.js)

```javascript
let cmid = 1000;
function nextCmid() { return ++cmid; }

async function performCallCharge(walletId, cli, dn, callDate, durationSeconds) {
  // Step 1: Initial Reservation
  const irResponse = await sendRequest('/initial-reservation', {
    "ACTN": "REQ ",
    "TYPE": "IR  ",
    "HEAD": { "SVID": 1, "CMID": nextCmid() },
    "BODY": {
      "WALT": walletId,
      "AREF": 999,
      "ACTY": 5,
      "CLI ": cli,
      "DN  ": dn,
      "CDAT": callDate,
      "TZ  ": "GMT",
      "ERSL": durationSeconds,
      "PREC": "SECS",
      "CSC ": "STD01"
    }
  });

  if (irResponse.ACTN === 'NACK') {
    if (irResponse.BODY.CODE === 'INSF') {
      console.log('Subscriber has insufficient funds. Refusing call.');
      return false;
    }
    throw new Error(`IR NAck: ${irResponse.BODY.CODE} - ${irResponse.BODY.WHAT}`);
  }

  const grantedUnits = irResponse.BODY['NUM '];
  console.log(`Reservation granted: ${grantedUnits} seconds`);

  // Step 2: Simulate call...
  const actualDuration = Math.min(durationSeconds, grantedUnits);

  // Step 3: Commit the reservation
  const crResponse = await sendRequest('/commit-reservation', {
    "ACTN": "REQ ",
    "TYPE": "CR  ",
    "HEAD": { "SVID": 1, "CMID": nextCmid() },
    "BODY": {
      "WALT": walletId,
      "RESN": "HANG",
      "NUM ": actualDuration,
      "CDAT": callDate
    }
  });

  if (crResponse.ACTN === 'ACK ') {
    console.log(`Call committed. Charged: ${actualDuration} seconds.`);
    return true;
  }
}
```

---

### Example 3: Voucher Redemption Flow (Python)

```python
import requests
import jwt
import time

SECRET = 'YOUR_SUPER_SECRET_KEY_CHANGE_IN_PRODUCTION'
API_BASE = 'http://localhost:3010/api'

token = jwt.encode(
    {
        'clientId': 'PythonClient',
        'allowedEndpoints': ['/voucher-redeem', '/voucher-commit'],
        'exp': int(time.time()) + 3600
    },
    SECRET,
    algorithm='HS256'
)

headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}

# Step 1: Initiate Voucher Redeem
vr_payload = {
    "ACTN": "REQ ",
    "TYPE": "VR  ",
    "HEAD": {"SVID": 1, "CMID": 10002},
    "BODY": {
        "VNUM": "1234567890",
        "SPID": 101,
        "RWLT": 12345,
        "ACTY": 5,
        "RARF": "447700900123",
        "SCEN": 0
    }
}

vr_res = requests.post(f'{API_BASE}/voucher-redeem', json=vr_payload, headers=headers)
vr_data = vr_res.json()

if vr_data['message']['ACTN'] == 'NACK':
    code = vr_data['message']['BODY']['CODE']
    what = vr_data['message']['BODY']['WHAT']
    print(f'Redemption declined: {code} - {what}')
elif vr_data['message']['ACTN'] == 'ACK ':
    # Step 2: Confirm the redemption
    cvr_payload = {
        "ACTN": "REQ ",
        "TYPE": "CVR ",
        "HEAD": {"SVID": 1, "CMID": 10003},
        "BODY": {"VNUM": "1234567890", "SCEN": 0}
    }
    cvr_res = requests.post(f'{API_BASE}/voucher-commit', json=cvr_payload, headers=headers)
    print('Voucher redeemed successfully:', cvr_res.json())
```

---

### Example 4: Complex Multi-Balance Update (Raw Format)

This example demonstrates updating multiple balance types and bucket values in a single atomic message using raw symbols.

```javascript
const payload = {
  "ACTN": "REQ ",
  "TYPE": "WU  ",
  "HEAD": { "SVID": 1, "CMID": 9005 },
  "BODY": {
    "WALT": 12345,
    "ABAL": [
      {
        "BTYP": 1,
        "BKTS": [{ "BKID": 101, "VAL ": 5000 }]
      },
      {
        "BTYP": 4,
        "BKTS": [{ "BKID": -1, "VAL ": 100, "EXPR": 1784035629 }]
      }
    ]
  }
};

const response = await fetch(`${API_BASE_URL}/wallet-update`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify(payload)
});

const { message } = await response.json();
// Raw format responses will also use symbols (ACTN, TYPE, etc.)
// message will use human-readable keys
console.log('Response format:', format); // "friendly"
```

---

## 14. Security Best Practices

### Token Management

- **Use short-lived tokens.** Tokens should have an expiry of 1 hour or less for operational workloads. Use a refresh/rotation mechanism if longer sessions are required.
- **Scope tokens to the minimum required endpoints.** A token for a call control system should only have `/initial-reservation` in its `allowedEndpoints`, not `/wallet-info` or administrative endpoints.
- **Never share tokens between systems.** Each integrating system should have its own unique `clientId` and token.
- **Store the JWT secret securely.** Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.) rather than environment variables in source code.
- **Rotate the JWT secret periodically.** Coordinate rotation to minimise downtime; issue new tokens before revoking the old secret.

### Network Security

- **Use HTTPS in production.** The API should be placed behind a TLS-terminating reverse proxy (e.g. nginx, AWS ALB) in production environments. Never transmit tokens over unencrypted HTTP in production.
- **Restrict network access.** The API gateway port (3010) should not be publicly accessible. Use firewall rules or security groups to restrict access to known source IPs.
- **Monitor unauthorised attempts.** Poll `/api/stats` regularly and alert if `unauthorisedAttempts` rises unexpectedly. This may indicate a token has been compromised or a system misconfiguration.

### Input Validation

- **Validate wallet IDs.** Ensure wallet IDs are positive integers before submitting to the API.
- **Validate MSISDN formats.** The `CLI ` and `DN  ` fields should contain valid E.164 format numbers.
- **Sanitise voucher numbers.** Voucher numbers should be validated for length and format before submission.

### Error Handling

- **Do not expose raw BE exceptions to end users.** Exception messages from the BE may contain internal system details. Present generic error messages to end users and log the raw exception internally.
- **Log all EXCP responses.** Exceptions represent system failures and should always be captured with full context for investigation.

---

## 15. Field Symbol Reference (Raw Format)

This section provides a consolidated reference of all 4-character symbols used across BE Protocol messages.

### Header Symbols

| Symbol | Field Name | Type |
|---|---|---|
| `HEAD` | Header container | Map |
| `SVID` | BE Server ID | int |
| `CMID` | Client Message ID | int |
| `DATE` | Date/time | date |
| `USEC` | Microseconds | int |
| `VER ` | Protocol Version | int |
| `DUP ` | Duplicate flag | int |

### Action Symbols

| Symbol | Meaning |
|---|---|
| `ACTN` | Action key |
| `REQ ` | Request |
| `ACK ` | Acknowledgement |
| `NACK` | Negative Acknowledgement |
| `EXCP` | Exception |
| `ABRT` | Abort |

### Message Type Symbols

| Symbol | Message Type |
|---|---|
| `WI  ` | Wallet Info |
| `WC  ` | Wallet Create |
| `WU  ` | Wallet Update |
| `WD  ` | Wallet Delete |
| `WRI ` | Wallet Reservations Info |
| `WRE ` | Wallet Reservation End |
| `WGR ` | Wallet General Recharge |
| `WSI ` | Wallet State Information |
| `MGW ` | Merge Wallets |
| `IR  ` | Initial Reservation |
| `SR  ` | Subsequent Reservation |
| `CR  ` | Commit Reservation |
| `RR  ` | Revoke Reservation |
| `ATC ` | Apply Tariffed Charge |
| `NE  ` | Named Event |
| `INER` | Initial Named Event Reservation |
| `SNER` | Subsequent Named Event Reservation |
| `CNER` | Confirm Named Event Reservation |
| `RNER` | Revoke Named Event Reservation |
| `IARR` | Initial Amount Reservation |
| `SARR` | Subsequent Amount Reservation |
| `CARR` | Confirm Amount Reservation |
| `RARR` | Revoke Amount Reservation |
| `DA  ` | Direct Amount |
| `USR ` | Unit Second Rate |
| `NER ` | Named Event Rate |
| `VI  ` | Voucher Info |
| `VR  ` | Voucher Redeem |
| `CVR ` | Commit Voucher Redeem |
| `RVR ` | Revoke Voucher Redeem |
| `VRW ` | Voucher Redeem Wallet |
| `VU  ` | Voucher Update |
| `VTR ` | Voucher Type Recharge |
| `VTRC` | Voucher Type Recharge Confirm |
| `BPIN` | Bad PIN |
| `LDMF` | Reload MFile |
| `BEG ` | Begin Communication |
| `CHKD` | Check Dialect |
| `HTBT` | Heartbeat |
| `CCDR` | Create CDR |
| `TRAN` | Transaction (internal) |

### Common Body Field Symbols

| Symbol | Field Name | Type |
|---|---|---|
| `BODY` | Body container | Map |
| `WALT` | Wallet ID | int |
| `VCHR` | Voucher ID | int |
| `VNUM` | Voucher Number | string |
| `STAT` | State | Symbol |
| `EXPR` | Expiry Date | date |
| `ACTV` | Activation Date | date |
| `LUSE` | Last Used | date |
| `MAXC` | Max Concurrent | int |
| `SCUR` | System Currency | int |
| `UCUR` | User Currency | int |
| `BALS` | Balances Array | array |
| `BTYP` | Balance Type | int |
| `LIMT` | Limit Type | Symbol |
| `STOT` | System Total | int |
| `BUNT` | Balance Unit | int |
| `BKTS` | Buckets Array | array |
| `ABAL` | Alter Balances | array |
| `WALT` | Wallet ID | int |
| `AREF` | Account Reference | int |
| `ACTY` | Account Type | int |
| `WTYP` | Wallet Type | int |
| `CLI ` | Calling Line ID | string |
| `DN  ` | Dialled Number | string |
| `CDAT` | Call Date | date |
| `TZ  ` | Time Zone | string |
| `ERSL` | Expected Reservation Length | int |
| `PREC` | Precision | Symbol |
| `CSC ` | Call Scenario Code | string |
| `SUBN` | Subscriber Number | string |
| `SPID` | Service Provider ID | int |
| `NUM ` | Number / Units | int |
| `TOT ` | Total | int |
| `LOWT` | Low Credit Time | int |
| `FCD ` | Free Call Disposition | Symbol |
| `TCOD` | Tariff Code | string |
| `LOWA` | Low Balance Announcement | int |
| `RESN` | Reason | Symbol |
| `CODE` | Code (NAck/Exception) | Symbol |
| `WHAT` | Description | string |
| `TUC ` | Total Units Consumed | int |
| `DDAM` | Direct Debit/Credit Amount | int |
| `AMNT` | Amount | int |
| `MINA` | Minimum Amount | int |
| `RSRV` | Reserved Amount | int |
| `TMLF` | Time to Live | int |
| `CNFM` | Confirm Amount | int |
| `EVTS` | Events Array | array |
| `CLSS` | Event Class | string |
| `NAME` | Event Name | string |
| `MIN ` | Minimum | int |
| `MAX ` | Maximum | int |
| `DISC` | Discount | int |
| `RBAA` | Recharge Balance Array | array |
| `RBIA` | Recharge Bucket Array | array |
| `LOCK` | Lock Duration (ms) | int |
| `BCOR` | Balance Cascade Override | int |
| `BTOR` | Balance Type Override | int |
| `TPO ` | Tariff Plan Override | int |
| `RPO ` | Reservation Period Override | int |
| `SPLG` | Suppress Plugins | null |
| `SPCP` | Suppress Periodic Charge Plugin | null |
| `UDWS` | Update Wallet Status | null |
| `SDNF` | Start Date No Filter | null |
| `PINC` | Bad PIN Count | int |
| `SCPI` | SCP ID / Client ID | int |
| `CALI` | Call ID | int |
| `RESO` | Reservation Operation | int |
| `MFTY` | MFile Type | string |
| `WALR` | Wallet Reference | string |
| `LIFE` | Session Lifetime | int |
| `BALC` | Balance Cascade | int |
| `RWLT` | Redeeming Wallet ID | int |
| `RARF` | Redeeming Account Ref | string |
| `SCEN` | Scenario | int |
| `VNME` | Voucher Type Name | string |
| `DLKW` | Delete Locked Wallet | null |
| `DLRM` | Don't Log Remove | null |
| `ABID` | Account Batch ID | int |
| `NACT` | New Account Type | int |
| `APOL` | Account Expiry Policy | Symbol |
| `BPOL` | Balance Expiry Policy | Symbol |
| `AEXT` | Account Expiry Extension | int |
| `BEXT` | Balance Expiry Extension | int |
| `AEXP` | Account Expiry Date | date |

---

## 16. Extended Wallet Features

The OCNCC BE Client supports advanced "Extended" feature logic for granular balance management, specifically around future-dated buckets and complex lifecycle updates.

### 16.1 Future-Dated Buckets (STDT)

The Billing Engine allows buckets to be created with a **Start Date (`STDT`)** in the future. These buckets are inactive and hidden from standard balance queries until their start date is reached.

#### Visibility via "Start Date No Filter" (SDNF)

To retrieve all buckets, including those with a future start date, use the `SDNF` field in a `WI` (Wallet Info) request.

**Request Example (Raw Format):**
```json
{
  "ACTN": "REQ ",
  "TYPE": "WI  ",
  "BODY": {
    "WALR": "447700900123",
    "SDNF": null
  }
}
```
*Note: Setting `SDNF` to `null` disables the default BE date filtering logic.*

#### Adding Future-Dated Buckets (WU)

When performing a `WU` (Wallet Update), you can provision buckets that only become available for consumption at a specific future timestamp.

**Request Example (Adding a Future Bucket):**
```json
{
  "ACTN": "REQ ",
  "TYPE": "WU  ",
  "HEAD": { "CMID": 5001 },
  "BODY": {
    "WALT": 12345,
    "ABAL": [
      {
        "BTYP": 1,
        "BKTS": [
          {
            "VAL ": 1000,
            "STDT": 1750000000,
            "EXPR": 1760000000
          }
        ]
      }
    ]
  }
}
```

### 16.2 Multi-Bucket Updates in a Single Message

The `Alter Balances` (`ABAL`) field is an array, allowing you to modify multiple balance types or multiple buckets within a single atomic operation.

**Example: Deducting from one balance while adding a future bucket to another:**
```json
{
  "ACTN": "REQ ",
  "TYPE": "WU  ",
  "BODY": {
    "WALT": 12345,
    "ABAL": [
      {
        "BTYP": 1,
        "BKTS": [
          { "BKID": 1, "VAL ": -500 }
        ]
      },
      {
        "BTYP": 2,
        "BKTS": [
          {
            "VAL ": 5000,
            "STDT": 1745000000,
            "EXPR": 1755000000
          }
        ]
      }
    ]
  }
}
```

### 16.3 Extended Message Fields

| Symbol | Friendly Name | Type | Usage |
| :--- | :--- | :--- | :--- |
| `SDNF` | Start Date No Filter | null | Set to `null` in `WI` to see future buckets. |
| `STDT` | Start Date | date | The timestamp when a bucket becomes active. |
| `ABAL` | Alter Balances | array | Container for balance/bucket modifications in `WU`. |
| `BKTS` | Buckets | array | Nested array within `ABAL` for specific bucket changes. |
| `EDRC` | Create EDR | int | Set to `1` in `WU` to force EDR generation for the update. |

---

*End of Document*

> For questions regarding this API, contact the Blue Bridge Software integration team.
> © 2026 Blue Bridge Software Ltd. All rights reserved.
