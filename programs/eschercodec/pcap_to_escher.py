#!/usr/bin/env python3
"""
pcap_to_escher.py

Copyright © 2026 Blue Bridge Software Ltd. All rights reserved.

This material is the confidential property of Blue Bridge Software Ltd
or its licensors and may be used, reproduced, stored or transmitted
only in accordance with a valid Blue Bridge Software Ltd license or
sublicense agreement.

----------------------
Decode every ESCHER message in a PCAP file and write each to a JSON file.

Usage:
    python3 escher_pcap_to_json.py input.pcap output.json [--port 1500]

Each decoded message in the JSON array has the shape:
{
  "_meta": {
    "packet":    <int>   packet number in the PCAP (1-based),
    "timestamp": <str>   "YYYY-MM-DD HH:MM:SS.ffffff UTC",
    "src":       <str>   "IP:port",
    "dst":       <str>   "IP:port",
    "direction": <str>   "client->server" or "server->client",
    "bytes":     <int>   TCP payload length
  },
  ... decoded ESCHER map fields ...
}

Field encoding rules (inverse of escher_to_pcap.py):
  NULL         -> null
  INT32/INT64  -> integer
  DATE         -> {"_type":"date","unix":<int>,"utc":"YYYY-MM-DD HH:MM:SS UTC"}
  SYMBOL       -> string (4 chars, trailing spaces preserved)
  FLOAT64      -> float  (bytes un-reversed from wire)
  STRING       -> string
  MAP          -> object
  ARRAY        -> array
  RAW          -> {"_type":"raw","hex":"..."}
"""

import struct
import json
import sys
import math
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# Symbol decoder  (matches Symbol::toString; same logic as the Lua dissector)
# ---------------------------------------------------------------------------
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

def decode_symbol(val):
    """Decode a 32-bit unsigned integer to a 4-char ESCHER symbol string."""
    if val < 0:
        val += 4294967296          # bit.band() signed-int fix
    r1 = int(val // 161243136) % 27
    r2 = int(val //   5971968) % 27
    r3 = int(val //    221184) % 27
    r4 = int(val //      8192) % 27
    return ALPHABET[r1] + ALPHABET[r2] + ALPHABET[r3] + ALPHABET[r4]

# ---------------------------------------------------------------------------
# Load shared symbol -> label mapping
# ---------------------------------------------------------------------------
SYMBOL_TO_LABEL = {}
try:
    with open(Path(__file__).parent / "escher_fields.json", "r") as f:
        SYMBOL_TO_LABEL = json.load(f)
except Exception:
    pass # Fall back to raw symbols if mapping is missing

# ---------------------------------------------------------------------------
# Timestamp formatter
# ---------------------------------------------------------------------------
def format_timestamp(ts_sec, ts_usec=0):
    """Convert unix seconds + microseconds to an ISO-style UTC string."""
    days   = ts_sec // 86400
    rem    = ts_sec % 86400
    hh     = rem // 3600
    mm     = (rem % 3600) // 60
    ss     = rem % 60

    year = 1970
    while True:
        leap  = (year % 4 == 0) and (year % 100 != 0 or year % 400 == 0)
        ydays = 366 if leap else 365
        if days < ydays:
            break
        days -= ydays
        year += 1

    leap  = (year % 4 == 0) and (year % 100 != 0 or year % 400 == 0)
    mdays = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    month = 1
    for m in range(12):
        if days < mdays[m]:
            month = m + 1
            break
        days -= mdays[m]
    day = days + 1

    return f"{year:04d}-{month:02d}-{day:02d} {hh:02d}:{mm:02d}:{ss:02d}.{ts_usec:06d} UTC"

def format_date_field(ts):
    """Format a DATE typecode value (u32 unix timestamp)."""
    return {
        "_type": "date",
        "unix":  ts,
        "utc":   format_timestamp(ts, 0).split('.')[0] + " UTC"
    }

# ---------------------------------------------------------------------------
# Typecodes
# ---------------------------------------------------------------------------
TC_NULL   = 0
TC_INT32  = 1
TC_DATE   = 2
TC_SYMBOL = 3
TC_FLOAT  = 4
TC_STRING = 5
TC_ARRAY  = 6
TC_RAW    = 8
TC_INT64  = 9
TC_MAP    = 12

def align4(n):
    return (n + 3) & ~3

# ---------------------------------------------------------------------------
# ESCHER decoder
# ---------------------------------------------------------------------------
def decode_map(data, use_labels=True):
    """
    Decode an ESCHER MAP from bytes.
    Returns an OrderedDict-style dict preserving key order.
    """
    if len(data) < 8:
        return {"_error": "map too short"}

    first_u16 = struct.unpack('>H', data[0:2])[0]

    if first_u16 == 0xFFFE:
        # Extended map
        if len(data) < 12:
            return {"_error": "extended map header truncated"}
        ctrl        = data[3]
        ext_index   = bool(ctrl & 0x04)
        total_len   = struct.unpack('>I', data[4:8])[0]
        num_items   = struct.unpack('>I', data[8:12])[0]
        items_start = 12
        item_stride = 8 if ext_index else 4
    else:
        # Standard map: [u16 total][u16 count][u32 ptr][index…]
        total_len   = first_u16
        num_items   = struct.unpack('>H', data[2:4])[0]
        ext_index   = False
        items_start = 8
        item_stride = 4

    result = {}

    for i in range(num_items):
        idx_off = items_start + i * item_stride
        if idx_off + 4 > len(data):
            break

        entry_raw  = struct.unpack('>I', data[idx_off:idx_off+4])[0]
        sym_val    = entry_raw & 0xFFFFE000
        typecode   = (entry_raw >> 9) & 0x0F
        sym_name   = decode_symbol(sym_val)

        if ext_index and idx_off + 8 <= len(data):
            data_off_words = struct.unpack('>I', data[idx_off+4:idx_off+8])[0]
        else:
            data_off_words = entry_raw & 0x1FF

        data_abs_off = data_off_words * 4   # offset from MAP START (byte 0 of data)
        value        = decode_value(data, typecode, data_abs_off, use_labels)

        if use_labels:
            key = SYMBOL_TO_LABEL.get(sym_name, sym_name)
        else:
            key = sym_name

        result[key] = value

    return result


def decode_array(data, use_labels=True):
    """Decode an ESCHER ARRAY from bytes. Returns a list."""
    if len(data) < 8:
        return []

    first_u16 = struct.unpack('>H', data[0:2])[0]

    if first_u16 == 0xFFFE:
        if len(data) < 12:
            return []
        ctrl        = data[3]
        ext_index   = bool(ctrl & 0x04)
        num_items   = struct.unpack('>I', data[8:12])[0]
        items_start = 12
        item_stride = 6 if ext_index else 2
    else:
        num_items   = struct.unpack('>H', data[2:4])[0]
        ext_index   = False
        items_start = 8
        item_stride = 2

    result = []

    for i in range(num_items):
        idx_off = items_start + i * item_stride
        if idx_off + 2 > len(data):
            break

        entry_raw  = struct.unpack('>H', data[idx_off:idx_off+2])[0]
        typecode   = (entry_raw >> 9) & 0x0F

        if ext_index and idx_off + 6 <= len(data):
            data_off_words = struct.unpack('>I', data[idx_off+2:idx_off+6])[0]
        else:
            data_off_words = entry_raw & 0x1FF

        data_abs_off = data_off_words * 4
        result.append(decode_value(data, typecode, data_abs_off, use_labels))

    return result


def decode_value(data, typecode, abs_off, use_labels=True):
    """Decode a single typed value from data[abs_off:]."""
    vd = data[abs_off:] if abs_off < len(data) else b''

    if typecode == TC_NULL:
        return None

    elif typecode == TC_INT32:
        if len(vd) < 4:
            return None
        return struct.unpack('>i', vd[:4])[0]

    elif typecode == TC_DATE:
        if len(vd) < 4:
            return None
        ts = struct.unpack('>I', vd[:4])[0]
        return format_date_field(ts)

    elif typecode == TC_SYMBOL:
        if len(vd) < 4:
            return None
        sv = struct.unpack('>I', vd[:4])[0]
        return decode_symbol(sv)

    elif typecode == TC_FLOAT:
        # Wire bytes are reversed on Linux (htonf); reverse to recover the double
        if len(vd) < 8:
            return None
        b = vd[:8]
        native = bytes([b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]])
        val = struct.unpack('>d', native)[0]
        # Return clean float; guard against NaN/Inf
        if math.isfinite(val):
            return val
        return {"_type": "float", "raw_hex": b.hex()}

    elif typecode == TC_STRING:
        if len(vd) < 1:
            return None
        first = vd[0]
        if first & 0x80:
            if len(vd) < 2:
                return None
            slen   = struct.unpack('>H', vd[:2])[0] & 0x7FFF
            s_data = vd[2:2 + slen]
        else:
            slen   = first
            s_data = vd[1:1 + slen]
        try:
            return s_data.decode('utf-8')
        except UnicodeDecodeError:
            return {"_type": "bytes", "hex": s_data.hex()}

    elif typecode == TC_ARRAY:
        return decode_array(vd, use_labels)

    elif typecode == TC_RAW:
        if len(vd) < 4:
            return None
        raw_len = struct.unpack('>I', vd[:4])[0]
        raw_data = vd[4:4 + raw_len]
        return {"_type": "raw", "hex": raw_data.hex()}

    elif typecode == TC_INT64:
        if len(vd) < 8:
            return None
        return struct.unpack('>q', vd[:8])[0]

    elif typecode == TC_MAP:
        return decode_map(vd, use_labels)

    else:
        # Unknown typecode — return raw bytes so nothing is silently lost
        return {"_type": f"unknown_tc{typecode}", "hex": vd[:16].hex()}

# ---------------------------------------------------------------------------
# PCAP reader
# ---------------------------------------------------------------------------
def read_pcap(path):
    """Yield (pkt_num, ts_sec, ts_usec, src_ip, src_port, dst_ip, dst_port, payload)
    for every TCP packet carrying ESCHER traffic on the configured port."""
    with open(path, 'rb') as f:
        raw = f.read()

    magic = struct.unpack('<I', raw[:4])[0]
    if magic != 0xa1b2c3d4:
        raise ValueError(f"Not a PCAP file (magic={magic:#010x}). "
                         "Only little-endian PCAP (not pcapng) is supported.")

    offset  = 24   # skip global header
    pkt_num = 0

    while offset + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', raw[offset:offset+16])
        offset += 16
        pkt     = raw[offset:offset+incl_len]
        offset += incl_len
        pkt_num += 1

        # Ethernet
        if len(pkt) < 14:
            continue
        ether_type = struct.unpack('>H', pkt[12:14])[0]
        if ether_type != 0x0800:
            continue          # not IPv4

        # IPv4
        ihl   = (pkt[14] & 0x0F) * 4
        proto = pkt[14 + 9]
        if proto != 6:
            continue          # not TCP
        ip_end = 14 + ihl

        src_ip = '.'.join(str(b) for b in pkt[ip_end + 12:ip_end + 16])
        dst_ip = '.'.join(str(b) for b in pkt[ip_end + 16:ip_end + 20])

        # TCP
        tcp_data_off = (pkt[ip_end + 12] >> 4) * 4
        payload      = pkt[ip_end + tcp_data_off:]
        src_port     = struct.unpack('>H', pkt[ip_end:ip_end + 2])[0]
        dst_port     = struct.unpack('>H', pkt[ip_end + 2:ip_end + 4])[0]

        if not payload:
            continue

        yield pkt_num, ts_sec, ts_usec, src_ip, src_port, dst_ip, dst_port, payload

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def decode_pcap(pcap_path, escher_port=1500, use_labels=True):
    messages = []

    for pkt_num, ts_sec, ts_usec, src_ip, src_port, dst_ip, dst_port, payload in read_pcap(pcap_path):

        # Only process packets involving the ESCHER port
        if src_port != escher_port and dst_port != escher_port:
            continue

        # Quick sanity check: is this a plausible ESCHER map?
        if len(payload) < 8:
            continue
        declared_len = struct.unpack('>H', payload[0:2])[0]
        if declared_len != len(payload):
            # Could be a heartbeat variant or partial segment — still try
            pass

        # Decode the map
        decoded = decode_map(payload, use_labels)

        direction = "client->server" if dst_port == escher_port else "server->client"

        message = {
            "_meta": {
                "packet":    pkt_num,
                "timestamp": format_timestamp(ts_sec, ts_usec),
                "src":       f"{src_ip}:{src_port}",
                "dst":       f"{dst_ip}:{dst_port}",
                "direction": direction,
                "bytes":     len(payload),
            }
        }
        message.update(decoded)
        messages.append(message)

    return messages


def main():
    parser = argparse.ArgumentParser(description="Decode ESCHER messages from a PCAP into JSON.")
    parser.add_argument("pcap",   help="Input PCAP file")
    parser.add_argument("output", help="Output JSON file")
    parser.add_argument("--port", type=int, default=1500,
                        help="TCP port carrying ESCHER traffic (default: 1500)")
    parser.add_argument("--raw", action="store_true",
                        help="Output raw 4-char symbols as keys instead of human-readable labels")
    args = parser.parse_args()

    messages = decode_pcap(args.pcap, escher_port=args.port, use_labels=not args.raw)

    with open(args.output, 'w') as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)

    print(f"Decoded {len(messages)} ESCHER messages -> {args.output}")


if __name__ == '__main__':
    main()
