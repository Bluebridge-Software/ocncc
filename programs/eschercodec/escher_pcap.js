#!/usr/bin/env node
'use strict';
// =============================================================================
// escher_pcap.js
//
// Copyright © 2026 Blue Bridge Software Ltd. All rights reserved.
//
// This material is the confidential property of Blue Bridge Software Ltd
// or its licensors and may be used, reproduced, stored or transmitted
// only in accordance with a valid Blue Bridge Software Ltd license or
// sublicense agreement.
//
// -----------------------------------------------------------------------------
// Unified ESCHER <-> PCAP conversion tool (pure Node.js, no dependencies).
//
// Usage:
//   node escher_pcap.js encode  input.json   output.pcap  [--port 1500]
//   node escher_pcap.js decode  input.pcap   output.json  [--port 1500] [--raw]
//
// encode:  Reads a JSON array of ESCHER message objects and writes a PCAP file
//          that Wireshark decodes correctly with escher_dissector.lua.
//
// decode:  Reads every TCP packet on the ESCHER port from a PCAP file and
//          writes a JSON array of decoded message objects.
//
// Options:
//   --port N   TCP port carrying ESCHER traffic (default: 1500)
//   --raw      (decode only) Emit raw 4-char symbols as keys instead of
//              human-readable labels
//   --meta     incude metadata in the decoded output'
//
// JSON value conventions (encode):
//   number (integer)  -> INT32, or INT64 if out of 32-bit range
//   number (float)    -> FLOAT64
//   string            -> SYMBOL if exactly 4 chars A-Z+SPACE, else STRING
//   "~date:N"         -> DATE with unix timestamp N
//   { _type:"date", unix:N } -> DATE (round-trips decoder output)
//   object            -> nested MAP
//   array             -> ARRAY (TC_LIST=11, as the billing engine sends)
//   null / true       -> NULL (presence flag)
//   false             -> skipped (same as Python bool=False -> TC_NULL)
//
// JSON value conventions (decode):
//   TC_NULL    -> null
//   TC_INT32   -> number
//   TC_INT64   -> number (safe) or BigInt string "9007199254741992n" if > 2^53
//   TC_DATE    -> { _type:"date", unix:N, utc:"YYYY-MM-DD HH:MM:SS UTC" }
//   TC_SYMBOL  -> string (4 chars, trailing spaces preserved)
//   TC_FLOAT64 -> number (finite) or { _type:"float", raw_hex:"..." }
//   TC_STRING  -> string
//   TC_MAP     -> object
//   TC_ARRAY / TC_LIST -> array
//   TC_RAW     -> { _type:"raw", hex:"..." }
// =============================================================================

const fs   = require('fs');
const path = require('path');

// =============================================================================
// Shared: Symbol encoding / decoding
// =============================================================================
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ';

/** Pad/trim a symbol key to exactly 4 chars. */
function padSym(s) {
  if (s.length <= 4) return (s + '    ').slice(0, 4);
  const trimmed = s.replace(/\s+$/, '');
  if (trimmed.length <= 4) return (trimmed + '    ').slice(0, 4);
  throw new Error(
    `ESCHER symbol ${JSON.stringify(s)} is ${s.length} chars; maximum is 4.`
  );
}

/** Encode a 4-char symbol string to its 32-bit unsigned integer representation. */
function encodeSymbolInt(s) {
  // Returns a regular JS number — safe because max value is
  // 26*161243136 + 26*5971968 + 26*221184 + 26*8192 = 4,294,967,168 < 2^32
  // which fits in a 53-bit JS float without precision loss.
  return (
    ALPHABET.indexOf(s[0]) * 161243136 +
    ALPHABET.indexOf(s[1]) *   5971968 +
    ALPHABET.indexOf(s[2]) *    221184 +
    ALPHABET.indexOf(s[3]) *      8192
  );
}

/** Decode a 32-bit unsigned integer to a 4-char ESCHER symbol string. */
function decodeSymbol(val) {
  // JavaScript bitwise operations produce signed int32, so values with the
  // high bit set (>= 0x80000000) come back negative after masking in the
  // caller.  >>> 0 coerces to unsigned before the arithmetic divisions.
  val = val >>> 0;
  const r1 = Math.floor(val / 161243136) % 27;
  const r2 = Math.floor(val /   5971968) % 27;
  const r3 = Math.floor(val /    221184) % 27;
  const r4 = Math.floor(val /      8192) % 27;
  return ALPHABET[r1] + ALPHABET[r2] + ALPHABET[r3] + ALPHABET[r4];
}

/** True if a string is a valid bare 4-char ESCHER symbol value. */
function isSymbolValue(s) {
  if (s.length !== 4) return false;
  return [...s].every(c => ALPHABET.includes(c));
}

// =============================================================================
// Shared: Field label mapping (symbol -> friendly name)
//   Loaded from escher_fields.json in the same directory if present;
//   falls back to raw symbols otherwise.
// =============================================================================
let SYMBOL_TO_LABEL = {};   // for decode:  'WALT' -> 'Wallet ID'
let LABEL_TO_SYMBOL = {};   // for encode:  'Wallet ID' -> 'WALT'

try {
  const fieldsPath = path.join(__dirname, 'escher_fields.json');
  const raw = JSON.parse(fs.readFileSync(fieldsPath, 'utf8'));
  SYMBOL_TO_LABEL = raw;
  for (const [sym, label] of Object.entries(raw)) {
    LABEL_TO_SYMBOL[label] = sym;
  }
} catch (_) {
  // escher_fields.json is optional — raw symbols are used as fallback.
}

// =============================================================================
// Shared: Typecodes
// =============================================================================
const TC_NULL   = 0;
const TC_INT32  = 1;
const TC_DATE   = 2;
const TC_SYMBOL = 3;
const TC_FLOAT  = 4;
const TC_STRING = 5;
const TC_ARRAY  = 6;   // decode-only alias; billing engine sends TC_LIST
const TC_RAW    = 8;
const TC_INT64  = 9;
const TC_LIST   = 11;  // billing engine uses this for all array values
const TC_MAP    = 12;

// =============================================================================
// Shared: Timestamp formatter (manual — avoids locale/timezone issues)
// =============================================================================
function formatTimestamp(tsSec, tsUsec = 0) {
  let days = Math.floor(tsSec / 86400);
  let rem  = tsSec % 86400;
  const hh = Math.floor(rem / 3600);
  const mm = Math.floor((rem % 3600) / 60);
  const ss = rem % 60;

  let year = 1970;
  while (true) {
    const leap  = (year % 4 === 0) && (year % 100 !== 0 || year % 400 === 0);
    const ydays = leap ? 366 : 365;
    if (days < ydays) break;
    days -= ydays;
    year++;
  }

  const leap  = (year % 4 === 0) && (year % 100 !== 0 || year % 400 === 0);
  const mdays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  let month   = 1;
  for (let m = 0; m < 12; m++) {
    if (days < mdays[m]) { month = m + 1; break; }
    days -= mdays[m];
  }
  const day = days + 1;

  const pad2 = n => String(n).padStart(2, '0');
  const pad4 = n => String(n).padStart(4, '0');
  const pad6 = n => String(n).padStart(6, '0');
  return `${pad4(year)}-${pad2(month)}-${pad2(day)} ${pad2(hh)}:${pad2(mm)}:${pad2(ss)}.${pad6(tsUsec)} UTC`;
}

function formatDateField(ts) {
  return {
    _type: 'date',
    unix:  ts,
    utc:   formatTimestamp(ts, 0).split('.')[0] + ' UTC',
  };
}

// =============================================================================
// Shared: Alignment
// =============================================================================
function align4(n) { return (n + 3) & ~3; }

// =============================================================================
// ENCODER
// =============================================================================

// Fields the billing engine always encodes as INT64 regardless of value size.
const INT64_FIELDS = new Set([
  'CMID', 'WALT', 'AREF', 'ID  ', 'VAL ', 'UVAL',
  'STOT', 'UTOT', 'BDLT', 'CNFM', 'DELT', 'AMNT', 'MINA', 'MCHG',
]);

// Fields whose values must always be TC_STRING even if they look like symbols.
const STRING_VALUE_FIELDS = new Set([
  'TAG ', 'NAME', 'WHAT', 'STRV', 'SNUS', 'SCNM', 'VNME',
]);

/** Encode a UTF-8 string with ESCHER's 1- or 2-byte length prefix + 4-byte alignment. */
function encodeString(s) {
  const strBytes = Buffer.from(s, 'utf8');
  const n = strBytes.length;
  let hdr;
  if (n < 128) {
    hdr = Buffer.from([n]);
  } else {
    hdr = Buffer.allocUnsafe(2);
    hdr.writeUInt16BE(n | 0x8000, 0);
  }
  const raw   = Buffer.concat([hdr, strBytes]);
  const padded = align4(raw.length);
  const out   = Buffer.alloc(padded, 0);
  raw.copy(out);
  return out;
}

/** Byte-reverse a float64 for the wire (Linux htonf convention). */
function encodeFloat64Wire(v) {
  const buf = Buffer.allocUnsafe(8);
  buf.writeDoubleBE(v, 0);
  buf.reverse();
  return buf;
}

/** Write a signed 64-bit integer to a Buffer using BigInt arithmetic. */
function writeInt64BE(buf, offset, value) {
  // Accept Number or BigInt.
  const bi = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
  const mask32 = BigInt(0xFFFFFFFF);
  const hi = Number((bi >> 32n) & mask32);
  const lo = Number(bi & mask32);
  buf.writeInt32BE(hi, offset);        // signed high word
  buf.writeUInt32BE(lo, offset + 4);   // unsigned low word
}

/**
 * Encode a single value.
 * Returns [typecode, Buffer].
 */
function encodeValue(v, forceInt64 = false, forceString = false) {
  if (v === null || v === true) {
    return [TC_NULL, Buffer.alloc(0)];
  }

  if (typeof v === 'string' && v.startsWith('~date:')) {
    const ts = parseInt(v.slice(6), 10);
    const b  = Buffer.allocUnsafe(4);
    b.writeUInt32BE(ts >>> 0, 0);
    return [TC_DATE, b];
  }

  // Round-trip from decoder: { _type:'date', unix:N }
  if (typeof v === 'object' && !Array.isArray(v) && v !== null && v._type === 'date' && v.unix != null) {
    const b = Buffer.allocUnsafe(4);
    b.writeUInt32BE(v.unix >>> 0, 0);
    return [TC_DATE, b];
  }

  if (typeof v === 'boolean') {
    // false → NULL (presence-flag semantics, matches Python)
    return [TC_NULL, Buffer.alloc(0)];
  }

  if (typeof v === 'bigint') {
    const b = Buffer.allocUnsafe(8);
    writeInt64BE(b, 0, v);
    return [TC_INT64, b];
  }

  if (typeof v === 'number') {
    if (Number.isInteger(v)) {
      if (forceInt64 || v < -2147483648 || v > 2147483647) {
        const b = Buffer.allocUnsafe(8);
        writeInt64BE(b, 0, v);
        return [TC_INT64, b];
      }
      const b = Buffer.allocUnsafe(4);
      b.writeInt32BE(v, 0);
      return [TC_INT32, b];
    }
    // float
    return [TC_FLOAT, encodeFloat64Wire(v)];
  }

  if (typeof v === 'string') {
    if (!forceString && isSymbolValue(v)) {
      const b = Buffer.allocUnsafe(4);
      b.writeUInt32BE(encodeSymbolInt(v), 0);
      return [TC_SYMBOL, b];
    }
    return [TC_STRING, encodeString(v)];
  }

  if (Array.isArray(v)) {
    return [TC_LIST, encodeArray(v)];
  }

  if (typeof v === 'object' && v !== null) {
    return [TC_MAP, encodeMap(v)];
  }

  throw new Error(`Cannot encode value: ${typeof v} ${JSON.stringify(v)}`);
}

/** Encode an ESCHER MAP from a plain JS object. */
function encodeMap(obj) {
  const entries = [];

  for (const [rawKey, val] of Object.entries(obj)) {
    if (rawKey.startsWith('_')) continue;   // skip _meta, _type, etc.

    // Accept friendly labels as keys if escher_fields.json was loaded.
    const sym = LABEL_TO_SYMBOL[rawKey] || rawKey;
    const key = padSym(sym);

    const forceInt64  = INT64_FIELDS.has(key);
    const forceString = STRING_VALUE_FIELDS.has(key);

    const [tc, data] = encodeValue(val, forceInt64, forceString);
    entries.push({ key, tc, data });
  }

  // Keys MUST be sorted by ascending symbol integer (Escher binary-searches the index).
  // ESCHER alphabet: SPACE > Z, so plain ASCII/lexicographic order is wrong.
  entries.sort((a, b) => encodeSymbolInt(a.key) - encodeSymbolInt(b.key));

  const n         = entries.length;
  const dataStart = align4(8 + n * 4);   // standard map: 8-byte hdr + n*4 index

  // First pass: compute data offsets and collect data buffers.
  let pos = dataStart;
  const offsets   = [];
  const dataParts = [];

  for (const { tc, data } of entries) {
    if (tc === TC_NULL || data.length === 0) {
      offsets.push(0);
    } else {
      offsets.push(pos >>> 2);   // offset in 4-byte words from map start
      dataParts.push(data);
      pos += data.length;
    }
  }

  const totalLen = pos;
  const buf      = Buffer.alloc(totalLen, 0);

  // Map header
  buf.writeUInt16BE(totalLen, 0);
  buf.writeUInt16BE(n,        2);
  buf.writeUInt32BE(0,        4);   // internal_ptr = 0

  // Index entries
  for (let i = 0; i < entries.length; i++) {
    const { key, tc } = entries[i];
    const symVal = encodeSymbolInt(key);
    // Bitwise OR produces a signed int32 in JS; >>> 0 coerces to unsigned
    // so writeUInt32BE receives a value in [0, 2^32) rather than going negative.
    const entry  = ((symVal & 0xFFFFE000) | ((tc & 0xF) << 9) | (offsets[i] & 0x1FF)) >>> 0;
    buf.writeUInt32BE(entry, 8 + i * 4);
  }

  // Data section
  let writePos = dataStart;
  for (const d of dataParts) {
    d.copy(buf, writePos);
    writePos += d.length;
  }

  return buf;
}

/** Encode an ESCHER ARRAY from a JS array. */
function encodeArray(lst) {
  const entries = lst.map(v => {
    const [tc, data] = encodeValue(v);
    return { tc, data };
  });

  const n         = entries.length;
  const dataStart = align4(8 + n * 2);   // standard array: 8-byte hdr + n*2 index

  let pos = dataStart;
  const offsets   = [];
  const dataParts = [];

  for (const { tc, data } of entries) {
    if (tc === TC_NULL || data.length === 0) {
      offsets.push(0);
    } else {
      offsets.push(pos >>> 2);
      dataParts.push(data);
      pos += data.length;
    }
  }

  const totalLen = pos;
  const buf      = Buffer.alloc(totalLen, 0);

  buf.writeUInt16BE(totalLen, 0);
  buf.writeUInt16BE(n,        2);
  buf.writeUInt32BE(0,        4);

  for (let i = 0; i < entries.length; i++) {
    const { tc } = entries[i];
    const entry  = ((tc & 0xF) << 9) | (offsets[i] & 0x1FF);
    buf.writeUInt16BE(entry, 8 + i * 2);
  }

  let writePos = dataStart;
  for (const d of dataParts) {
    d.copy(buf, writePos);
    writePos += d.length;
  }

  return buf;
}

// ---------------------------------------------------------------------------
// PCAP writer
// ---------------------------------------------------------------------------

/** Build the 24-byte PCAP global header (little-endian, Ethernet link type). */
function makePcapGlobalHeader() {
  const buf = Buffer.allocUnsafe(24);
  buf.writeUInt32LE(0xa1b2c3d4, 0);  // magic
  buf.writeUInt16LE(2,           4);  // major version
  buf.writeUInt16LE(4,           8);  // minor version
  buf.writeInt32LE( 0,           8);  // timezone (GMT)
  buf.writeUInt32LE(0,          12);  // sig figs
  buf.writeUInt32LE(65535,      16);  // snaplen
  buf.writeUInt32LE(1,          20);  // link type: Ethernet
  return buf;
}

/** Wrap an ESCHER payload in Ethernet + IPv4 + TCP headers (no real checksums). */
function wrapInEthernetIpTcp(payload, srcPort, dstPort = 1500, seq = 1) {
  // TCP (20 bytes, no options)
  const tcp = Buffer.alloc(20, 0);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(seq,     4);   // seq
  tcp.writeUInt32BE(0,       8);   // ack
  tcp[12] = 0x50;                  // data offset: 5 * 4 = 20 bytes
  tcp[13] = 0x18;                  // flags: PSH + ACK
  tcp.writeUInt16BE(65535,  14);   // window
  tcp.writeUInt16BE(0,      16);   // checksum (unchecked)
  tcp.writeUInt16BE(0,      18);   // urgent

  // IPv4 (20 bytes, no options)
  const ipTotalLen = 20 + tcp.length + payload.length;
  const ip = Buffer.alloc(20, 0);
  ip[0] = 0x45;                             // version=4, IHL=5
  ip[1] = 0;                                // DSCP
  ip.writeUInt16BE(ipTotalLen,  2);
  ip.writeUInt16BE(0,           4);          // id
  ip.writeUInt16BE(0x4000,      6);          // flags: DF
  ip[8]  = 64;                              // TTL
  ip[9]  = 6;                               // protocol: TCP
  ip.writeUInt16BE(0,          10);          // checksum (unchecked)
  ip.writeUInt8(192, 12); ip.writeUInt8(168, 13);  // src: 192.168.1.1
  ip.writeUInt8(  1, 14); ip.writeUInt8(  1, 15);
  ip.writeUInt8(192, 16); ip.writeUInt8(168, 17);  // dst: 192.168.1.2
  ip.writeUInt8(  1, 18); ip.writeUInt8(  2, 19);

  // Ethernet (14 bytes)
  const eth = Buffer.from([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // dst MAC
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  // src MAC
    0x08, 0x00,                           // EtherType: IPv4
  ]);

  return Buffer.concat([eth, ip, tcp, payload]);
}

/** Build a single PCAP packet record. */
function makePcapRecord(frame, tsSec, tsUsec = 0) {
  const hdr = Buffer.allocUnsafe(16);
  hdr.writeUInt32LE(tsSec,         0);
  hdr.writeUInt32LE(tsUsec,        4);
  hdr.writeUInt32LE(frame.length,  8);
  hdr.writeUInt32LE(frame.length, 12);
  return Buffer.concat([hdr, frame]);
}

/**
 * Encode an array of ESCHER message objects to a PCAP Buffer.
 * @param {object[]} messages  - Array of plain JS objects (ESCHER maps).
 * @param {number}   dstPort   - Destination TCP port (default 1500).
 * @returns {Buffer}
 */
function encodeToPcap(messages, dstPort = 1500) {
  const tsBase = Math.floor(Date.now() / 1000);
  const parts  = [makePcapGlobalHeader()];

  for (let i = 0; i < messages.length; i++) {
    const payload = encodeMap(messages[i]);
    const frame   = wrapInEthernetIpTcp(payload, 20000 + i, dstPort, i + 1);
    const record  = makePcapRecord(frame, tsBase + i, i * 100000);
    parts.push(record);
  }

  return Buffer.concat(parts);
}

// =============================================================================
// DECODER
// =============================================================================

/**
 * Read a signed 64-bit big-endian integer from buf at offset.
 * Returns a JS Number if the value is within Number.MAX_SAFE_INTEGER range,
 * otherwise returns a BigInt (serialised as "Nn" string in JSON output).
 */
function readInt64BE(buf, offset) {
  const hi = buf.readInt32BE(offset);          // signed high word
  const lo = buf.readUInt32BE(offset + 4);     // unsigned low word
  const bi = (BigInt(hi) << 32n) | BigInt(lo);
  // If value fits in a safe JS integer, return as Number for clean JSON output.
  if (bi >= BigInt(Number.MIN_SAFE_INTEGER) && bi <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(bi);
  }
  // Otherwise return BigInt — the JSON replacer below will serialise it.
  return bi;
}

/** Decode a single typed value from buf at absOff. */
function decodeValue(buf, typecode, absOff, useLabels) {
  const vd = absOff < buf.length ? buf.slice(absOff) : Buffer.alloc(0);

  switch (typecode) {
    case TC_NULL:
      return null;

    case TC_INT32:
      if (vd.length < 4) return null;
      return vd.readInt32BE(0);

    case TC_DATE: {
      if (vd.length < 4) return null;
      return vd.readUInt32BE(0);
    }

    case TC_SYMBOL: {
      if (vd.length < 4) return null;
      const sv = vd.readUInt32BE(0);
      return decodeSymbol(sv);
    }

    case TC_FLOAT: {
      if (vd.length < 8) return null;
      // Wire bytes are byte-reversed on Linux (htonf); reverse to recover the double.
      const reversed = Buffer.from([
        vd[7], vd[6], vd[5], vd[4], vd[3], vd[2], vd[1], vd[0],
      ]);
      const val = reversed.readDoubleBE(0);
      if (isFinite(val)) return val;
      return { _type: 'float', raw_hex: vd.slice(0, 8).toString('hex') };
    }

    case TC_STRING: {
      if (vd.length < 1) return null;
      let slen, sStart;
      if (vd[0] & 0x80) {
        if (vd.length < 2) return null;
        slen   = vd.readUInt16BE(0) & 0x7FFF;
        sStart = 2;
      } else {
        slen   = vd[0];
        sStart = 1;
      }
      if (vd.length < sStart + slen) return null;
      try {
        return vd.slice(sStart, sStart + slen).toString('utf8');
      } catch (_) {
        return { _type: 'bytes', hex: vd.slice(sStart, sStart + slen).toString('hex') };
      }
    }

    case TC_ARRAY:
    case TC_LIST:
      return decodeArray(vd, useLabels);

    case TC_RAW: {
      if (vd.length < 4) return null;
      const rawLen  = vd.readUInt32BE(0);
      const rawData = vd.slice(4, 4 + rawLen);
      return { _type: 'raw', hex: rawData.toString('hex') };
    }

    case TC_INT64: {
      if (vd.length < 8) return null;
      return readInt64BE(vd, 0);
    }

    case TC_MAP:
      return decodeMap(vd, useLabels);

    default:
      return { _type: `unknown_tc${typecode}`, hex: vd.slice(0, 16).toString('hex') };
  }
}

/** Decode an ESCHER MAP from a Buffer. Returns a plain JS object. */
function decodeMap(buf, useLabels = true) {
  if (buf.length < 8) return { _error: 'map too short' };

  let totalLen, numItems, itemsStart, itemStride, extIndex;
  const firstU16 = buf.readUInt16BE(0);

  if (firstU16 === 0xFFFE) {
    // Extended map
    if (buf.length < 12) return { _error: 'extended map header truncated' };
    const ctrl = buf[3];
    extIndex   = !!(ctrl & 0x04);
    totalLen   = buf.readUInt32BE(4);
    numItems   = buf.readUInt32BE(8);
    itemsStart = 12;
    itemStride = extIndex ? 8 : 4;
  } else {
    // Standard map
    totalLen   = firstU16;
    numItems   = buf.readUInt16BE(2);
    extIndex   = false;
    itemsStart = 8;
    itemStride = 4;
  }

  const result = {};

  for (let i = 0; i < numItems; i++) {
    const idxOff = itemsStart + i * itemStride;
    if (idxOff + 4 > buf.length) break;

    const entryRaw = buf.readUInt32BE(idxOff);
    const symVal   = (entryRaw & 0xFFFFE000) >>> 0;   // >>> 0 = coerce to unsigned uint32
    const typecode = (entryRaw >>> 9) & 0x0F;
    const symName  = decodeSymbol(symVal);

    let dataOffWords;
    if (extIndex && idxOff + 8 <= buf.length) {
      dataOffWords = buf.readUInt32BE(idxOff + 4);
    } else {
      dataOffWords = entryRaw & 0x1FF;
    }

    const dataAbsOff = dataOffWords * 4;   // byte offset from start of this buffer
    const value      = decodeValue(buf, typecode, dataAbsOff, useLabels);

    const key = useLabels ? (SYMBOL_TO_LABEL[symName] || symName) : symName;
    result[key] = value;
  }

  return result;
}

/** Decode an ESCHER ARRAY from a Buffer. Returns a JS array. */
function decodeArray(buf, useLabels = true) {
  if (buf.length < 8) return [];

  let numItems, itemsStart, itemStride, extIndex;
  const firstU16 = buf.readUInt16BE(0);

  if (firstU16 === 0xFFFE) {
    if (buf.length < 12) return [];
    const ctrl = buf[3];
    extIndex   = !!(ctrl & 0x04);
    numItems   = buf.readUInt32BE(8);
    itemsStart = 12;
    itemStride = extIndex ? 6 : 2;
  } else {
    numItems   = buf.readUInt16BE(2);
    extIndex   = false;
    itemsStart = 8;
    itemStride = 2;
  }

  const result = [];

  for (let i = 0; i < numItems; i++) {
    const idxOff = itemsStart + i * itemStride;
    if (idxOff + 2 > buf.length) break;

    const entryRaw   = buf.readUInt16BE(idxOff);
    const typecode   = (entryRaw >>> 9) & 0x0F;
    let   dataOffWords;

    if (extIndex && idxOff + 6 <= buf.length) {
      dataOffWords = buf.readUInt32BE(idxOff + 2);
    } else {
      dataOffWords = entryRaw & 0x1FF;
    }

    const dataAbsOff = dataOffWords * 4;
    result.push(decodeValue(buf, typecode, dataAbsOff, useLabels));
  }

  return result;
}

// ---------------------------------------------------------------------------
// PCAP reader
// ---------------------------------------------------------------------------

/**
 * Iterate over every TCP payload in a PCAP Buffer.
 * Yields objects: { pktNum, tsSec, tsUsec, srcIp, srcPort, dstIp, dstPort, payload }
 */
function* iterPcapPackets(raw) {
  const magic = raw.readUInt32LE(0);
  if (magic !== 0xa1b2c3d4) {
    throw new Error(
      `Not a PCAP file (magic=0x${magic.toString(16).padStart(8,'0')}). ` +
      'Only little-endian PCAP (not pcapng) is supported.'
    );
  }

  let offset = 24;   // skip 24-byte global header
  let pktNum = 0;

  while (offset + 16 <= raw.length) {
    const tsSec  = raw.readUInt32LE(offset);
    const tsUsec = raw.readUInt32LE(offset + 4);
    const inclLen = raw.readUInt32LE(offset + 8);
    offset += 16;

    const pkt = raw.slice(offset, offset + inclLen);
    offset   += inclLen;
    pktNum++;

    // ---- Ethernet ----
    if (pkt.length < 14) continue;
    const etherType = pkt.readUInt16BE(12);
    if (etherType !== 0x0800) continue;   // not IPv4

    // ---- IPv4 ----
    const ipStart = 14;
    const ihl     = (pkt[ipStart] & 0x0F) * 4;
    const proto   = pkt[ipStart + 9];
    if (proto !== 6) continue;            // not TCP
    const ipEnd   = ipStart + ihl;

    // IP source/destination addresses are at fixed offsets from ipStart.
    const srcIp = `${pkt[ipStart+12]}.${pkt[ipStart+13]}.${pkt[ipStart+14]}.${pkt[ipStart+15]}`;
    const dstIp = `${pkt[ipStart+16]}.${pkt[ipStart+17]}.${pkt[ipStart+18]}.${pkt[ipStart+19]}`;

    // ---- TCP ----
    const srcPort    = pkt.readUInt16BE(ipEnd);
    const dstPort    = pkt.readUInt16BE(ipEnd + 2);
    const seq = pkt.readUInt32BE(ipEnd + 4);

    const tcpDataOff = (pkt[ipEnd + 12] >>> 4) * 4;
    const payload    = pkt.slice(ipEnd + tcpDataOff);

    if (!payload.length) continue;

    //yield { pktNum, tsSec, tsUsec, srcIp, srcPort, dstIp, dstPort, payload };
    yield { pktNum, tsSec, tsUsec, srcIp, srcPort, dstIp, dstPort, payload, seq };
  }
}

/**
 * Decode all ESCHER messages from a PCAP Buffer.
 * @param {Buffer}  raw        - Raw PCAP file contents.
 * @param {number}  escherPort - TCP port to filter on (default 1500).
 * @param {boolean} useLabels  - Replace raw symbols with friendly names.
 * @returns {object[]}
 */
function decodeFromPcap(raw, escherPort = 1500, useLabels = true, exportMetadata = false) {
  const messages = [];

  for (const { pktNum, tsSec, tsUsec, srcIp, srcPort, dstIp, dstPort, payload }
       of iterPcapPackets(raw)) {

    if (srcPort !== escherPort && dstPort !== escherPort) continue;
    if (payload.length < 8) continue;

    const decoded   = decodeMap(payload, useLabels);
    const direction = dstPort === escherPort ? 'client->server' : 'server->client';

    if (exportMetadata) {
      messages.push({
        _meta: {
          packet:    pktNum,
          timestamp: formatTimestamp(tsSec, tsUsec),
          src:       `${srcIp}:${srcPort}`,
          dst:       `${dstIp}:${dstPort}`,
          direction,
          bytes:     payload.length,
        },
        ...decoded,
      });
    } else {
      messages.push({
        ...decoded,
      });
    }
  }

  return messages;
}

/**
 * TCP Flow Key Generator
 * @param {string} srcIp    - Source IPv4 address (e.g. "192.168.1.10")
 * @param {number} srcPort  - Source TCP port
 * @param {string} dstIp    - Destination IPv4 address
 * @param {number} dstPort  - Destination TCP port
 * @returns {string} Unique flow identifier in the form "srcIp:srcPort-dstIp:dstPort"
 */
function flowKey(srcIp, srcPort, dstIp, dstPort) {
  return `${srcIp}:${srcPort}-${dstIp}:${dstPort}`;
}

/**
 * Decode all ESCHER messages from a PCAP Buffer, but use TCP Stream Reassembly.
 * @param {Buffer}  raw        - Raw PCAP file contents.
 * @param {number}  escherPort - TCP port to filter on (default 1500).
 * @param {boolean} useLabels  - Replace raw symbols with friendly names.
 * @returns {object[]}
 */
function decodeFromPcapReassembled(raw, escherPort = 1500, useLabels = true, exportMetadata = false) {
  const flows = new Map();
  // --- Step 1: group packets into flows ---
  for (const pkt of iterPcapPackets(raw)) {
    const { srcIp, srcPort, dstIp, dstPort, payload } = pkt;

    if (srcPort !== escherPort && dstPort !== escherPort) continue;
    if (!payload.length) continue;

    const key = flowKey(srcIp, srcPort, dstIp, dstPort);

    if (!flows.has(key)) {
      flows.set(key, {
        packets: [],
        buffer: Buffer.alloc(0),
      });
    }

    flows.get(key).packets.push(pkt);
  }

  const messages = [];

  // --- Step 2: process each flow ---
  for (const [key, flow] of flows.entries()) {
    // Sort by sequence number (critical!)
    flow.packets.sort((a, b) => a.seq - b.seq);

    for (const pkt of flow.packets) {
      const { payload, tsSec, tsUsec, srcIp, srcPort, dstIp, dstPort, pktNum } = pkt;

      // Append to stream buffer
      flow.buffer = Buffer.concat([flow.buffer, payload]);

      // --- Step 3: extract ESCHER messages ---
      while (flow.buffer.length >= 8) {
        const totalLen = flow.buffer.readUInt16BE(0);

        // Sanity check (ESCHER header validation)
        if (totalLen < 8 || totalLen > 65535) {
          // Not valid ESCHER → discard 1 byte and retry (resync)
          flow.buffer = flow.buffer.slice(1);
          continue;
        }

        if (flow.buffer.length < totalLen) {
          // Wait for more data
          break;
        }

        const msgBuf = flow.buffer.slice(0, totalLen);
        flow.buffer = flow.buffer.slice(totalLen);

        let decoded;
        try {
          decoded = decodeMap(msgBuf, useLabels);
        } catch (e) {
          continue;
        }

        const direction = dstPort === escherPort
          ? 'client->server'
          : 'server->client';

        if(exportMetadata) {
          messages.push({
            _meta: {
              packet: pktNum,
              timestamp: formatTimestamp(tsSec, tsUsec),
              src: `${srcIp}:${srcPort}`,
              dst: `${dstIp}:${dstPort}`,
              direction,
              bytes: msgBuf.length,
              flow: key,
            },
            ...decoded,
          });
        } else {
          messages.push({
            ...decoded,
          });
        }
      }
    }
  }

  return messages;
}

// =============================================================================
// JSON serialisation helper
// BigInt values are not natively serialisable — emit them as "Nn" strings
// (e.g. "9007199254741993n") so they survive a round-trip.
// =============================================================================
function jsonReplacer(_key, value) {
  if (typeof value === 'bigint') return `${value}n`;
  return value;
}

// =============================================================================
// CLI entry point
// =============================================================================
function printUsage() {
  console.error([
    '',
    'Usage:',
    '  node escher_pcap.js encode  input.json  output.pcap  [--port N]',
    '  node escher_pcap.js decode  input.pcap  output.json  [--port N] [--raw]',
    '',
    'Commands:',
    '  encode   Convert a JSON array of ESCHER message objects to a PCAP file.',
    '  decode   Extract and decode ESCHER messages from a PCAP file to JSON.',
    '',
    'Options:',
    '  --port N   TCP port carrying ESCHER traffic (default: 1500)',
    '  --raw      (decode) Emit raw 4-char symbols as keys instead of labels',
    '  --meta     incude metadata in the decoded output',
    '',
  ].join('\n'));
}

function main() {
  const args = process.argv.slice(2);

  // Parse flags
  let portIdx = args.indexOf('--port');
  let port    = 1500;
  if (portIdx !== -1) {
    port = parseInt(args[portIdx + 1], 10);
    if (isNaN(port)) { console.error('--port requires a numeric argument'); process.exit(1); }
    args.splice(portIdx, 2);
  }

  const rawIdx  = args.indexOf('--raw');
  const useLabels = rawIdx === -1;

  const metaIdx = args.indexOf('--meta');
  const exportMetadata = metaIdx != -1;

  if (rawIdx !== -1) args.splice(rawIdx, 1);

  const [command, inputFile, outputFile] = args;

  if (!command || !inputFile || !outputFile) {
    printUsage();
    process.exit(1);
  }

  // ---- ENCODE ----
  if (command === 'encode') {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
    } catch (e) {
      console.error(`Failed to read/parse ${inputFile}: ${e.message}`);
      process.exit(1);
    }

    const messages = Array.isArray(data) ? data : [data];
    if (!Array.isArray(messages) || typeof messages[0] !== 'object') {
      console.error('ERROR: JSON must be an object or array of objects');
      process.exit(1);
    }

    const pcapBuf = encodeToPcap(messages, port);
    fs.writeFileSync(outputFile, pcapBuf);
    console.log(`Written ${messages.length} packet${messages.length !== 1 ? 's' : ''} to ${outputFile}`);
    return;
  }

  // ---- DECODE ----
  if (command === 'decode') {
    let raw;
    try {
      raw = fs.readFileSync(inputFile);
    } catch (e) {
      console.error(`Failed to read ${inputFile}: ${e.message}`);
      process.exit(1);
    }

    let messages;
    try {
      messages = decodeFromPcapReassembled(raw, port, useLabels, exportMetadata);
    } catch (e) {
      console.error(`Decode error: ${e.message}`);
      process.exit(1);
    }

    const json = JSON.stringify(messages, jsonReplacer, 2);
    fs.writeFileSync(outputFile, json, 'utf8');
    console.log(`Decoded ${messages.length} ESCHER message${messages.length !== 1 ? 's' : ''} -> ${outputFile}`);
    return;
  }

  console.error(`Unknown command: ${command}`);
  printUsage();
  process.exit(1);
}

main();