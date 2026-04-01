/**
 * OCNCC Billing Engine Escher Codec.
 * Escher protocol binary encoder/decoder
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const { SYMBOL_TO_LABEL, LABEL_TO_SYMBOL } = require('./escher-fields');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ';

const TC_NULL = 0;
const TC_INT32 = 1;
const TC_DATE = 2;
const TC_SYMBOL = 3;
const TC_FLOAT = 4;
const TC_STRING = 5;
const TC_ARRAY = 6;   // decoded only — the billing engine sends TC_LIST for all arrays
const TC_LIST = 11;   // used by the billing engine for ALL array values (ABAL, BKTS, CDR, BALS …)
const TC_RAW = 8;
const TC_INT64 = 9;
const TC_MAP = 12;

// ---------------------------------------------------------------------------
// Fields that the billing engine always encodes as INT64, even when the value
// fits in INT32.  Derived from live PCAP analysis: wallet IDs, bucket IDs, and
// monetary/unit amounts are INT64; small enum-like values (BTYP, BUNT, ACTY …)
// are INT32.
// ---------------------------------------------------------------------------
const INT64_FIELDS = new Set([
  'CMID', // request serial number
  'WALT', // wallet ID
  'AREF', // account reference
  'ID  ', // bucket ID (inside BKTS)
  'VAL ', // monetary value (inside BKTS and CDR)
  'UVAL', // unit value
  'STOT', // system total
  'UTOT', // unit total
  'BDLT', // balance delta
  'CNFM', // confirmed amount
  'DELT', // delta amount
  'AMNT', // amount
  'MINA', // minimum amount
  'MCHG', // max charge
]);

// ---------------------------------------------------------------------------
// Fields whose VALUES must always be encoded as TC_STRING, even if the value
// happens to be exactly 4 uppercase characters that would normally satisfy
// isSymbolValue().  The billing engine's C++ struct for these fields declares
// the value as std::string, not Symbol — sending TC_SYMBOL causes a TYFD
// ("Bad type for field") exception.
//
// Example: TAG ="USER" inside a CDR map.  "USER" is 4 uppercase chars so
// isSymbolValue() returns true, but the server rejects TC_SYMBOL for TAG .
// ---------------------------------------------------------------------------
const STRING_VALUE_FIELDS = new Set([
  'TAG ', // CDR tag name — always free-form text (USER, TERMINAL, MSISDN …)
  //'VAL ', // CDR value — always free-form text (USER, TERMINAL, MSISDN …)
  'NAME', // client/entity name
  'WHAT', // error description text
  'STRV', // string value (explicit string field by protocol definition)
  'SNUS', // serial number string
  'SCNM', // scenario name
  'VNME', // voucher type name
]);

// ---------------------------------------------------------------------------
// Symbol encoding / decoding
// ---------------------------------------------------------------------------
function padSym(s) {
  return (s + '    ').substring(0, 4);
}

function isSymbolValue(s) {
  if (s.length !== 4) return false;
  for (const c of s) {
    if (!ALPHABET.includes(c)) return false;
  }
  return true;
}

function encodeSymbolInt(s) {
  if (s.length !== 4) throw new Error(`Symbol must be 4 chars: "${s}"`);
  return (
    ALPHABET.indexOf(s[0]) * 161243136 +
    ALPHABET.indexOf(s[1]) * 5971968 +
    ALPHABET.indexOf(s[2]) * 221184 +
    ALPHABET.indexOf(s[3]) * 8192
  ) >>> 0; // force unsigned
}

function decodeSymbol(val) {
  if (val < 0) val += 4294967296;
  const r1 = Math.floor(val / 161243136) % 27;
  const r2 = Math.floor(val / 5971968) % 27;
  const r3 = Math.floor(val / 221184) % 27;
  const r4 = Math.floor(val / 8192) % 27;
  return ALPHABET[r1] + ALPHABET[r2] + ALPHABET[r3] + ALPHABET[r4];
}

// ---------------------------------------------------------------------------
// Alignment
// ---------------------------------------------------------------------------
function align4(n) {
  return (n + 3) & ~3;
}

// ---------------------------------------------------------------------------
// Date formatting
// ---------------------------------------------------------------------------
/**
 * Format a DATE typecode value (u32 unix timestamp) into the same structure
 * that pcap_to_escher.py produces, so messages decoded by either implementation
 * have an identical shape.
 *
 * To RE-ENCODE a decoded date, pass `"~date:" + value.unix` to encodeValue.
 */
function formatDateField(ts) {
  const d = new Date(ts * 1000);
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  const utc =
    `${pad(d.getUTCFullYear(), 4)}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
  return { _type: 'date', unix: ts, utc };
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------
function encodeString(s) {
  const b = Buffer.from(s, 'utf-8');
  const n = b.length;
  let hdr;
  if (n < 128) {
    hdr = Buffer.alloc(1);
    hdr[0] = n;
  } else {
    hdr = Buffer.alloc(2);
    hdr.writeUInt16BE(n | 0x8000, 0);
  }
  const raw = Buffer.concat([hdr, b]);
  const padded = align4(raw.length);
  if (padded > raw.length) {
    return Buffer.concat([raw, Buffer.alloc(padded - raw.length)]);
  }
  return raw;
}

function encodeFloat64Wire(v) {
  const buf = Buffer.alloc(8);
  buf.writeDoubleBE(v, 0);
  // Reverse bytes (Linux htonf convention)
  return Buffer.from([buf[7], buf[6], buf[5], buf[4], buf[3], buf[2], buf[1], buf[0]]);
}

function encodeValue(v, forceInt64 = false, forceString = false) {
  if (v === null || v === undefined) {
    return { tc: TC_NULL, data: Buffer.alloc(0) };
  }
  if (typeof v === 'string' && v.startsWith('~date:')) {
    const ts = parseInt(v.substring(6), 10);
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(ts >>> 0, 0);
    return { tc: TC_DATE, data: buf };
  }
  // Accept the rich date object produced by the decoder (or pcap_to_escher.py)
  if (v !== null && typeof v === 'object' && v._type === 'date' && typeof v.unix === 'number') {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(v.unix >>> 0, 0);
    return { tc: TC_DATE, data: buf };
  }
  if (typeof v === 'boolean') {
    return { tc: TC_NULL, data: Buffer.alloc(0) };
  }
  // Accept both Number integers and BigInt
  if (typeof v === 'bigint') {
    if (!forceInt64 && v >= -2147483648n && v <= 2147483647n) {
      const buf = Buffer.alloc(4);
      buf.writeInt32BE(Number(v), 0);
      return { tc: TC_INT32, data: buf };
    }
    const buf = Buffer.alloc(8);
    buf.writeBigInt64BE(v, 0);
    return { tc: TC_INT64, data: buf };
  }
  if (typeof v === 'number' && Number.isInteger(v)) {
    // forceInt64: fields like CMID, WALT, VAL  are always 64-bit in the billing engine
    if (forceInt64 || v < -2147483648 || v > 2147483647) {
      const buf = Buffer.alloc(8);
      buf.writeBigInt64BE(BigInt(v), 0);
      return { tc: TC_INT64, data: buf };
    }
    const buf = Buffer.alloc(4);
    buf.writeInt32BE(v, 0);
    return { tc: TC_INT32, data: buf };
  }
  if (typeof v === 'number') {
    return { tc: TC_FLOAT, data: encodeFloat64Wire(v) };
  }
  if (typeof v === 'string') {
    // forceString: fields declared as std::string in the billing engine must always
    // use TC_STRING even if the value is 4 uppercase chars (e.g. TAG ="USER").
    // Without this, isSymbolValue("USER") returns true and we'd send TC_SYMBOL,
    // which causes a TYFD ("Bad type for field") exception from the server.
    if (!forceString && isSymbolValue(v)) {
      const buf = Buffer.alloc(4);
      buf.writeUInt32BE(encodeSymbolInt(v), 0);
      return { tc: TC_SYMBOL, data: buf };
    }
    return { tc: TC_STRING, data: encodeString(v) };
  }
  if (Array.isArray(v)) {
    // The billing engine always uses TC_LIST (11) for array values, not TC_ARRAY (6).
    return { tc: TC_LIST, data: encodeArray(v) };
  }
  if (typeof v === 'object') {
    return { tc: TC_MAP, data: encodeMap(v) };
  }
  throw new Error(`Cannot encode type: ${typeof v}`);
}

function encodeMap(d) {
  const entries = [];
  for (const [rawKey, val] of Object.entries(d)) {
    if (rawKey.startsWith('_')) continue; // skip comment keys
    // Convert friendly label back to symbol if present
    const sym = LABEL_TO_SYMBOL[rawKey] || rawKey;
    const key = padSym(sym);
    // Validate: all characters must be in the Escher alphabet (A-Z + space).
    // Lowercase or non-alphabet characters produce a garbage symbol on the wire.
    for (const c of key) {
      if (!ALPHABET.includes(c)) {
        throw new Error(
          `Escher map key "${rawKey}" (padded: "${key}") contains character ` +
          `"${c}" which is not in the Escher alphabet (A-Z, space). ` +
          `Keys must be 1–4 uppercase letters; use escher_fields.json labels or raw symbols.`
        );
      }
    }
    // Some fields must always be encoded as INT64 regardless of value magnitude,
    // because the billing engine's C++ structs declare them as 64-bit integers.
    const forceInt64 = INT64_FIELDS.has(key);
    // Some fields must always be encoded as TC_STRING even if the value is exactly
    // 4 uppercase characters (which would normally match isSymbolValue).  The
    // billing engine declares these fields as std::string in C++; sending TC_SYMBOL
    // causes a TYFD ("Bad type for field") exception.
    const forceString = STRING_VALUE_FIELDS.has(key);
    const { tc, data } = encodeValue(val, forceInt64, forceString);
    entries.push({ key, tc, data });
  }

  // Sort map keys by their 32-bit symbol representation.
  // The Escher server uses binary search on the index, so keys MUST be
  // sorted in ascending symbol-integer order.  The Escher alphabet gives
  // ' ' (space) a higher ordinal value than 'Z', so plain ASCII order is wrong.
  // Use explicit < / > rather than subtraction: both operands are uint32 (up to
  // ~4.2 B), and their difference can exceed 2^31, making the subtraction trick
  // unreliable when the comparator result is then coerced to a signed integer
  // internally by some JS engines.
  entries.sort((a, b) => {
    const va = encodeSymbolInt(a.key);
    const vb = encodeSymbolInt(b.key);
    return va < vb ? -1 : va > vb ? 1 : 0;
  });
  const n = entries.length;
  const dataStart = align4(8 + n * 4);

  const offsets = [];
  const dataParts = [];
  let pos = dataStart;
  for (const { tc, data } of entries) {
    if (tc === TC_NULL || data.length === 0) {
      offsets.push(0);
    } else {
      offsets.push(Math.floor(pos / 4));
      dataParts.push(data);
      pos += data.length;
    }
  }

  const totalLen = pos;
  const buf = Buffer.alloc(totalLen);

  buf.writeUInt16BE(totalLen, 0);
  buf.writeUInt16BE(n, 2);
  buf.writeUInt32BE(0, 4); // internal_ptr = 0

  for (let i = 0; i < entries.length; i++) {
    const symVal = encodeSymbolInt(entries[i].key);
    const entry = ((symVal & 0xFFFFE000) | ((entries[i].tc & 0xF) << 9) | (offsets[i] & 0x1FF)) >>> 0;
    buf.writeUInt32BE(entry, 8 + i * 4);
  }

  let writePos = dataStart;
  for (const data of dataParts) {
    data.copy(buf, writePos);
    writePos += data.length;
  }

  return buf;
}

function encodeArray(lst) {
  const entries = [];
  for (const val of lst) {
    const { tc, data } = encodeValue(val);
    entries.push({ tc, data });
  }

  const n = entries.length;
  // Array header: [u16 total_byte_length][u16 num_items][u32 internal_ptr = 0]
  // This matches the billing engine's wire format exactly (confirmed from live PCAP).
  // The 8-byte header is identical in structure to a MAP header; the difference
  // is that array index entries are 2 bytes each (not 4), and carry no symbol field.
  const dataStart = align4(8 + n * 2);

  const offsets = [];
  const dataParts = [];
  let pos = dataStart;
  for (const { tc, data } of entries) {
    if (tc === TC_NULL || data.length === 0) {
      offsets.push(0);
    } else {
      offsets.push(Math.floor(pos / 4));
      dataParts.push(data);
      pos += data.length;
    }
  }

  const totalLen = pos;
  const buf = Buffer.alloc(totalLen);

  buf.writeUInt16BE(totalLen, 0);
  buf.writeUInt16BE(n, 2);
  buf.writeUInt32BE(0, 4); // internal_ptr = 0

  for (let i = 0; i < entries.length; i++) {
    const entry = ((entries[i].tc & 0xF) << 9) | (offsets[i] & 0x1FF);
    buf.writeUInt16BE(entry, 8 + i * 2);
  }

  let writePos = dataStart;
  for (const data of dataParts) {
    data.copy(buf, writePos);
    writePos += data.length;
  }

  return buf;
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------
function decodeMap(data, useLabels = true) {
  if (data.length < 8) return { _error: 'map too short' };

  const firstU16 = data.readUInt16BE(0);
  let numItems, itemsStart, extIndex;

  if (firstU16 === 0xFFFE) {
    // Extended map
    if (data.length < 12) return { _error: 'extended map header truncated' };
    const ctrl = data[3];
    extIndex = !!(ctrl & 0x04);
    numItems = data.readUInt32BE(8);
    itemsStart = 12;
  } else {
    numItems = data.readUInt16BE(2);
    extIndex = false;
    itemsStart = 8;
  }

  const itemStride = extIndex ? 8 : 4;
  const result = {};

  for (let i = 0; i < numItems; i++) {
    const idxOff = itemsStart + i * itemStride;
    if (idxOff + 4 > data.length) break;

    const entryRaw = data.readUInt32BE(idxOff);
    const symVal = entryRaw & 0xFFFFE000;
    const typecode = (entryRaw >> 9) & 0x0F;
    const symName = decodeSymbol(symVal);

    let dataOffWords;
    if (extIndex && idxOff + 8 <= data.length) {
      dataOffWords = data.readUInt32BE(idxOff + 4);
    } else {
      dataOffWords = entryRaw & 0x1FF;
    }

    const dataAbsOff = dataOffWords * 4;
    const value = decodeValue(data, typecode, dataAbsOff, useLabels);

    const key = useLabels ? (SYMBOL_TO_LABEL[symName] || symName) : symName;
    result[key] = value;
  }

  return result;
}

function decodeArray(data, useLabels = true) {
  if (data.length < 8) return [];

  const firstU16 = data.readUInt16BE(0);
  let numItems, itemsStart, extIndex;

  if (firstU16 === 0xFFFE) {
    if (data.length < 12) return [];
    const ctrl = data[3];
    extIndex = !!(ctrl & 0x04);
    numItems = data.readUInt32BE(8);
    itemsStart = 12;
  } else {
    numItems = data.readUInt16BE(2);
    extIndex = false;
    itemsStart = 8;
  }

  const itemStride = extIndex ? 6 : 2;
  const result = [];

  for (let i = 0; i < numItems; i++) {
    const idxOff = itemsStart + i * itemStride;
    if (idxOff + 2 > data.length) break;

    const entryRaw = data.readUInt16BE(idxOff);
    const typecode = (entryRaw >> 9) & 0x0F;

    let dataOffWords;
    if (extIndex && idxOff + 6 <= data.length) {
      dataOffWords = data.readUInt32BE(idxOff + 2);
    } else {
      dataOffWords = entryRaw & 0x1FF;
    }

    const dataAbsOff = dataOffWords * 4;
    result.push(decodeValue(data, typecode, dataAbsOff, useLabels));
  }

  return result;
}

function decodeValue(data, typecode, absOff, useLabels = true) {
  const vd = absOff < data.length ? data.subarray(absOff) : Buffer.alloc(0);

  switch (typecode) {
    case TC_NULL:
      return null;

    case TC_INT32:
      if (vd.length < 4) return null;
      return vd.readInt32BE(0);

    case TC_DATE:
      if (vd.length < 4) return null;
      return vd.readUInt32BE(0);
    //return formatDateField(vd.readUInt32BE(0));

    case TC_SYMBOL:
      if (vd.length < 4) return null;
      return decodeSymbol(vd.readUInt32BE(0));

    case TC_FLOAT: {
      if (vd.length < 8) return null;
      // Reverse bytes (Linux htonf convention)
      const reversed = Buffer.from([vd[7], vd[6], vd[5], vd[4], vd[3], vd[2], vd[1], vd[0]]);
      return reversed.readDoubleBE(0);
    }

    case TC_STRING: {
      if (vd.length < 1) return null;
      const first = vd[0];
      let slen, sStart;
      if (first & 0x80) {
        if (vd.length < 2) return null;
        slen = vd.readUInt16BE(0) & 0x7FFF;
        sStart = 2;
      } else {
        slen = first;
        sStart = 1;
      }
      return vd.subarray(sStart, sStart + slen).toString('utf-8');
    }

    case TC_ARRAY:
    case 11: // TC_LIST (similar to Array, used for Vectors like BALS)
      return decodeArray(vd, useLabels);

    case TC_RAW: {
      if (vd.length < 4) return null;
      const rawLen = vd.readUInt32BE(0);
      return { _type: 'raw', hex: vd.subarray(4, 4 + rawLen).toString('hex') };
    }

    case TC_INT64: {
      if (vd.length < 8) return null;
      const big = vd.readBigInt64BE(0);
      // Return a plain Number when the value fits in the safe-integer range
      // (i.e. no precision is lost).  For values outside that range, return a
      // BigInt so the caller is not silently handed a rounded value.
      return big >= Number.MIN_SAFE_INTEGER && big <= Number.MAX_SAFE_INTEGER
        ? Number(big)
        : big;
    }

    case TC_MAP:
      return decodeMap(vd, useLabels);

    default:
      return { _type: `unknown_tc${typecode}`, hex: vd.subarray(0, 16).toString('hex') };
  }
}

/**
 * Detect whether a JSON message uses friendly labels or raw symbols.
 * Returns true if friendly labels are detected.
 */
function isFriendlyFormat(msg) {
  // Check top-level keys for friendly labels
  const friendlyTopKeys = ['FOX Type', 'FOX Action', 'Header', 'Body'];
  return friendlyTopKeys.some(k => k in msg);
}

/**
 * Normalise a JSON message to raw symbol format for encoding.
 * If it's already in raw format, return as-is.
 */
function normaliseToRaw(msg) {
  if (!isFriendlyFormat(msg)) return msg;
  return convertKeys(msg, LABEL_TO_SYMBOL);
}

/**
 * Convert a decoded raw message to friendly format.
 */
function convertToFriendly(msg) {
  return convertKeys(msg, SYMBOL_TO_LABEL);
}

function convertKeys(obj, mapping) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(item => convertKeys(item, mapping));
  if (typeof obj !== 'object') return obj;

  const result = {};
  for (const [key, val] of Object.entries(obj)) {
    const newKey = mapping[key] || key;
    result[newKey] = convertKeys(val, mapping);
  }
  return result;
}

module.exports = {
  encodeMap,
  encodeArray,
  encodeValue,
  decodeMap,
  decodeArray,
  decodeValue,
  encodeSymbolInt,
  decodeSymbol,
  padSym,
  isFriendlyFormat,
  normaliseToRaw,
  convertToFriendly,
  INT64_FIELDS,
  STRING_VALUE_FIELDS,
  TC_NULL, TC_INT32, TC_DATE, TC_SYMBOL, TC_FLOAT,
  TC_STRING, TC_ARRAY, TC_LIST, TC_RAW, TC_INT64, TC_MAP
};