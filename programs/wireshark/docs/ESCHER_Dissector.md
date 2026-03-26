# ESCHER Protocol — Wireshark Dissector Documentation

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [What You Will See in Wireshark](#what-you-will-see-in-wireshark)
5. [Protocol Structure Reference](#protocol-structure-reference)
   - [Top-level message layout](#top-level-message-layout)
   - [Standard ESCHER Map](#standard-escher-map)
   - [Extended ESCHER Map](#extended-escher-map)
   - [ESCHER Array](#escher-array)
   - [Index entry bit layout](#index-entry-bit-layout)
   - [Data typecodes](#data-typecodes)
   - [Symbol encoding](#symbol-encoding)
6. [Known Message Patterns](#known-message-patterns)
7. [Filtering Reference](#filtering-reference)
8. [Field Label Reference](#field-label-reference)
9. [Known Limitations and Notes](#known-limitations-and-notes)
10. [Implementation Notes](#implementation-notes)

---

## Overview

This Wireshark dissector decodes the **ESCHER** binary protocol used by the Oracle/eServ Global CCS (Charging Control System) platform. ESCHER is a compact, self-describing binary serialisation format built around nested key-value maps and arrays. All communication between the FOX client and the CCS back-end billing engine takes place over TCP using this format.

The dissector is implemented as a pure Lua script (`escher_dissector.lua`) and requires no compilation. It was derived from the Oracle `cmnEscher` C++ source code and validated against live packet captures.

---

## Installation

### Wireshark version requirement

The dissector requires Wireshark **1.10 or later**. It has been tested with Wireshark 2.x and 3.x. The Lua scripting engine must be enabled (it is enabled by default in all standard Wireshark builds).

### Finding the correct plugins folder

The location of the personal Lua plugins folder depends on your operating system. You can find the exact path from within Wireshark at **Help → About Wireshark → Folders**.

| Operating System | Default personal plugins folder |
|---|---|
| **Windows** | `%APPDATA%\Wireshark\plugins\` |
| **macOS** | `~/.local/lib/wireshark/plugins/` |
| **Linux** | `~/.local/lib/wireshark/plugins/` |

Alternatively, the global plugins folder (requires administrator rights) can be used:

| Operating System | Global plugins folder |
|---|---|
| **Windows** | `C:\Program Files\Wireshark\plugins\` |
| **macOS** | `/Applications/Wireshark.app/Contents/PlugIns/wireshark/` |
| **Linux** | `/usr/lib/wireshark/plugins/` (version-dependent; check **About → Folders**) |

### Step-by-step installation

1. Copy `escher_dissector.lua` into your personal plugins folder. Create the folder if it does not exist.

2. Restart Wireshark, or reload all Lua scripts without restarting via **Analyse → Reload Lua Plugins** (or press `Ctrl+Shift+L`).

3. Verify that the dissector has loaded: open **Help → About Wireshark → Plugins** and confirm `escher_dissector.lua` appears in the list.

4. Open a capture file (or start a live capture) and look for traffic on TCP port 1500. Packets on that port should now show `ESCHER` in the Protocol column.

---

## Configuration

### TCP port

By default the dissector registers on **TCP port 1500**. This is the standard port used by the CCS back-end and was confirmed from live packet captures.

To change the port, edit the last two lines of `escher_dissector.lua`:

```lua
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(1500, escher_proto)   -- change 1500 to your port number
```

If traffic runs on multiple ports, duplicate the `tcp_table:add(...)` line for each port.

To apply the change, save the file and reload Lua plugins (`Ctrl+Shift+L`).

### Applying the dissector manually to an unknown port

If you have a capture where the port is non-standard, right-click any packet in the capture, choose **Decode As**, select the `TCP port` table, and assign it to `ESCHER`.

---

## What You Will See in Wireshark

### Packet list (Info column)

Each ESCHER packet displays a summary in the Info column. The dissector reads the top-level `ACTN` (action) and `TYPE` fields and formats the line as:

```
ESCHER ACTN='REQ ' TYPE='WI  ' (136 bytes)
ESCHER ACTN='EXCP' TYPE='PROC' (204 bytes)
ESCHER map (40 bytes, 3 items)
```

Heartbeat packets, which carry no ACTN field, show the map size and item count instead.

### Packet detail tree

Expanding an ESCHER packet in the detail pane shows a tree structured as follows:

```
▼ ESCHER Protocol
  ▼ Map: 4 items, 136 bytes
      Map Total Bytes: 136
      Map Item Count: 4
      Internal Ptr: 0x00000000
    ▼ FOX Action [ACTN] [SYMBOL]
        Index: sym='ACTN' type=SYMBOL offset_words=6 (byte +24)
        FOX Action [ACTN] = 'REQ '
    ▼ Body [BODY] [MAP]
        Index: sym='BODY' type=MAP offset_words=7 (byte +28)
      ▼ Body [BODY] [MAP] [Map: 4 items, 44 bytes]
          Map Total Bytes: 44
          ...
          ▼ Account Reference [AREF] [INT64]
              Account Reference [AREF] = 2
          ▼ Start Date No Filter [SDNF] [NULL]
              Start Date No Filter [SDNF] = (null)
          ▼ Wallet Reference [WALT] [INT64]
              Wallet Reference [WALT] = 2
          ▼ Wallet Type [WTYP] [INT32]
              Wallet Type [WTYP] = 1
    ▼ Header [HEAD] [MAP]
      ▼ Header [HEAD] [MAP] [Map: 6 items, 60 bytes]
          ▼ Request Number (CMID) [CMID] [INT64]
              Request Number (CMID) [CMID] = 0
          ▼ Call Date [DATE] [DATE]
              Call Date [DATE] = 20260320161836 (1774023516)
          ▼ Duplicate Flag [DUP ] [INT32]
              Duplicate Flag [DUP ] = 0
          ▼ BE Server ID [SVID] [INT32]
              BE Server ID [SVID] = 12
          ▼ Micro Seconds [USEC] [INT32]
              Micro Seconds [USEC] = 247024
          ▼ Protocol Version [VER ] [INT32]
              Protocol Version [VER ] = 100
    ▼ FOX Type [TYPE] [SYMBOL]
        FOX Type [TYPE] = 'WI  '
```

Each field node heading shows the **human-readable label**, the **raw 4-character symbol** in square brackets, and the **data type** in square brackets. Expanding the node shows the low-level index entry details and the decoded value.

Date fields are formatted as `YYYYMMDDHHMMSS (raw_unix_timestamp)`, for example `20260320161836 (1774023516)`.

---

## Protocol Structure Reference

### Top-level message layout

The **entire TCP payload is a single ESCHER Map**. There is no separate framing or transport header prepended to the map. The first two bytes of the TCP payload are the map's own total byte length field.

```
Byte offset  Field
──────────── ──────────────────────────────────────────────
0            ESCHER Map starts here (total_len, num_items …)
```

This means `total_byte_length` (bytes 0–1) always equals the TCP payload length for a complete, unfragmented message.

### Standard ESCHER Map

```
Offset  Size  Field
──────  ────  ───────────────────────────────────────────────────────
0       2     total_byte_length   (u16, includes this header)
2       2     num_items           (u16)
4       4     internal_ptr        (u32, always 0x00000000 on the wire)
8       4×N   index entries       (N = num_items, 4 bytes each)
8+4N    …     data area           (values stored sequentially, 4-byte aligned)
```

All multi-byte integers are **big-endian**.

### Extended ESCHER Map

An extended map is indicated when bytes 0–1 equal `0xFFFE`.

```
Offset  Size  Field
──────  ────  ───────────────────────────────────────────────────────
0       2     magic               (u16 = 0xFFFE)
2       2     control_block       (u16; bit 2 of byte[3] = ext-index flag)
4       4     total_byte_length   (u32)
8       4     num_items           (u32)
12      4×N   index entries       (4 bytes each if standard index)
   OR   8×N                       (8 bytes each if extended index)
```

When the extended-index flag is set, each 8-byte index entry contains a 4-byte key word followed by a 4-byte data offset (in 4-byte words from the map start), allowing values to be placed beyond the 512-word (2048-byte) limit of the standard 9-bit offset field.

### ESCHER Array

Arrays use the same header layout as a standard map but with 2-byte index entries instead of 4-byte ones.

```
Offset  Size  Field
──────  ────  ───────────────────────────────────────────────────────
0       2     total_byte_length   (u16)
2       2     num_items           (u16)
4       4     internal_ptr        (u32)
8       2×N   index entries       (N = num_items, 2 bytes each)
8+2N    …     data area
```

Extended arrays follow the same `0xFFFE` magic convention as extended maps.

### Index entry bit layout

Each 4-byte map index entry packs three fields into 32 bits:

```
 31      13 12    9 8        0
 ┌─────────┬──────┬──────────┐
 │ sym_val │  tc  │  offset  │
 │ 19 bits │4 bits│  9 bits  │
 └─────────┴──────┴──────────┘
```

| Field | Bits | Description |
|---|---|---|
| `sym_val` | 31–13 | Symbol value, used with `decode_symbol()` to produce a 4-char string |
| `tc` | 12–9 | Typecode (see table below) |
| `offset` | 8–0 | Data offset in 4-byte words, measured from the **start of the enclosing map** |

For 2-byte array index entries the same bit positions apply to the lower 16 bits (the symbol field is absent).

### Data typecodes

| Code | Name | Wire size | Description |
|---|---|---|---|
| 0 | NULL | 0 bytes | No value; offset field is ignored |
| 1 | INT32 | 4 bytes | Signed 32-bit big-endian integer |
| 2 | DATE | 4 bytes | Unsigned 32-bit Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) |
| 3 | SYMBOL | 4 bytes | Base-27 encoded 4-character symbol (see below) |
| 4 | FLOAT64 | 8 bytes | IEEE-754 double; byte-order reversed on Linux before sending |
| 5 | STRING | variable | 1-byte length prefix (or 2-byte with bit 15 set for strings ≥ 128 chars), then UTF-8 data, zero-padded to next 4-byte boundary |
| 6 | ARRAY | variable | Nested ESCHER Array container |
| 8 | RAW | variable | 4-byte unsigned length prefix, then raw bytes, zero-padded to next 4-byte boundary |
| 9 | INT64 | 8 bytes | Signed 64-bit big-endian integer (observed in live traffic) |
| 12 | MAP | variable | Nested ESCHER Map container. **Note:** the C++ enum `ESCHER_MAP_TYPE` has the value 12, not 7 |

### Symbol encoding

Symbols are 4-character strings drawn from the alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ ` (A=0, B=1 … Z=25, SPACE=26). They are encoded as a single unsigned 32-bit integer using base-27 positional arithmetic with the following multipliers (from `buildConversions.c`):

```
encoded_value = (index(char1) × 161243136)
              + (index(char2) ×   5971968)
              + (index(char3) ×    221184)
              + (index(char4) ×      8192)
```

Trailing spaces are significant: `"WI  "`, `"REQ "`, and `"DUP "` are three distinct symbols and must not be trimmed.

> **Implementation note:** Wireshark's Lua `bit.band()` function returns a *signed* 32-bit integer. Symbol values with bit 31 set (≥ `0x80000000`) come out of `bit.band()` as negative numbers. The dissector corrects this by adding `2^32` before performing the division, recovering the correct unsigned value. Without this fix, 189 of the 369 known symbols would decode to garbage names (e.g. `TYPE` would appear as `UHKC`).

---

## Known Message Patterns

The following top-level message structures have been observed in production traffic. Every message is a single ESCHER Map containing some or all of these top-level keys.

### Heartbeat

Sent periodically in both directions to keep the TCP connection alive.

```
TYPE = 'HTBT'
BODY = Map {}          (empty)
HEAD = Map {}          (empty)
```

### Request (client → server)

```
ACTN = 'REQ '
TYPE = <request type>  (e.g. 'WI  ' = Wallet Info)
HEAD = Map {
    CMID = <int64>     Request Number
    DATE = <timestamp> UTC timestamp
    DUP  = <int32>     Duplicate flag (0 = not duplicate)
    SVID = <int32>     BE Server ID
    USEC = <int32>     Microsecond component of timestamp
    VER  = <int32>     Protocol version (e.g. 100)
}
BODY = Map { … }       Request-specific fields
```

### Exception response (server → client)

```
ACTN = 'EXCP'
TYPE = 'PROC'
HEAD = Map { … }       (same structure as request HEAD)
BODY = Map {
    CODE = <symbol>    Error code (e.g. 'PLUG' = plugin error)
    WHAT = <string>    Human-readable error description
}
```

### Common TYPE values

| Symbol | Meaning |
|---|---|
| `WI  ` | Wallet Info |
| `WU  ` | Wallet Update |
| `WC  ` | Wallet Create |
| `WD  ` | Wallet Delete |
| `WR  ` | Wallet Recharge |
| `WGR ` | Wallet General Recharge |
| `VR  ` | Voucher Redeem |
| `IR  ` | Initial Reservation |
| `SR  ` | Subsequent Reservation |
| `CR  ` | Commit Reservation |
| `RR  ` | Revoke Reservation |
| `DA  ` | Direct Amount |
| `ATC ` | Apply Tariffed Charge |
| `NE  ` | Named Event |
| `MGW ` | Merge Wallets |
| `HTBT` | Heartbeat |
| `PROC` | Process (exception wrapper) |

---

## Filtering Reference

Wireshark display filters can be used to isolate specific ESCHER traffic. The filter field names correspond to the `ProtoField` abbreviations registered by the dissector.

| Filter | Description |
|---|---|
| `escher` | All ESCHER packets |
| `escher.val.string contains "RuntimeError"` | Packets containing a specific string value |
| `escher.val.symbol == "WI  "` | Packets where any symbol field equals `WI  ` |
| `escher.val.int32 == 12` | Packets where any INT32 field equals 12 |
| `escher.val.date` | Packets that contain a DATE field |
| `escher.map.items > 3` | Top-level maps with more than 3 items |
| `escher.entry.raw == 0x00f80606` | Packets containing a specific raw index entry |

To filter on a specific field value (e.g. only Wallet Info requests), combine symbol and string filters:

```
escher.val.symbol == "WI  "
escher.val.symbol == "EXCP"
escher.val.string contains "Insufficient"
```

---

## Field Label Reference

The dissector maintains a lookup table of 369 known symbols. When a symbol is recognised, the tree node displays the human-readable name followed by the raw 4-character symbol in square brackets. When a symbol is unknown it displays as the raw 4-character code alone, so the dissector degrades gracefully for any future protocol extensions.

The table below lists the most commonly encountered symbols in normal operation. The full set of 369 symbols, including all NACK codes, voucher states, and WLC fields, is embedded in the dissector source.

### Header fields (appear in every non-heartbeat message)

| Symbol | Display label |
|---|---|
| `ACTN` | FOX Action |
| `TYPE` | FOX Type |
| `HEAD` | Header |
| `BODY` | Body |
| `CMID` | Request Number (CMID) |
| `DATE` | Call Date |
| `DUP ` | Duplicate Flag |
| `SVID` | BE Server ID |
| `USEC` | Micro Seconds |
| `VER ` | Protocol Version |

### Common BODY fields

| Symbol | Display label |
|---|---|
| `AREF` | Account Reference |
| `CLI ` | Calling Line Identifier |
| `WALT` | Wallet Reference |
| `WTYP` | Wallet Type |
| `SDNF` | Start Date No Filter |
| `CODE` | Code |
| `WHAT` | Error Description |
| `BALS` | Balances |
| `BKTS` | Buckets |
| `STAT` | State |
| `EXPR` | Expiry Date |

### NACK codes

All NACK codes are prefixed with `NACK: ` in the dissector display.

| Symbol | Display label |
|---|---|
| `INSF` | NACK: Insufficient Funds |
| `WDIS` | NACK: Wallet Disabled |
| `NRCH` | NACK: Balance Not Rechargeable |
| `SYSF` | NACK: System Failure |
| `INVD` | NACK: Invalid Voucher Digits / Invalid Parameter |
| `VARD` | NACK: Voucher Already Redeemed |
| `NOSC` | NACK: System Currency Not Defined |

---

## Known Limitations and Notes

**FLOAT64 display.** The CCS back-end runs on Linux and byte-reverses all 64-bit floating-point values before sending them on the wire (see `Entry::htonf()` in `cmnEscherEntry.hh`). The dissector displays the raw reversed bytes rather than re-interpreting them as a double, because Wireshark's Lua API does not provide a portable mechanism for reversing byte order on a double field. The raw hex bytes are shown for completeness.

**INT64 display.** The INT64 typecode (9) is not defined in the published C++ header files but was confirmed by observing 8-byte values in the `AREF`, `WALT`, and `CMID` fields of live traffic. The value is displayed using Wireshark's `int64` field type.

**TCP reassembly.** The dissector does not implement TCP stream reassembly. If a large ESCHER message is split across multiple TCP segments, only the first segment will be decoded. Wireshark's built-in TCP reassembly (`tcp.desegment_pdus`) may help in some cases, but this is not currently configured by the dissector. In practice, all observed messages fit within a single TCP segment.

**Duplicate symbol definitions.** Several symbols share the same 4-character code across different contexts in the protocol source (for example, `RATE`, `INVD`, and `RBIA` each appear twice with different C++ key names). The dissector uses the first definition encountered, which corresponds to the most common usage.

**Port number.** The dissector registers on TCP port 1500 by default, which is the standard CCS back-end port. If your environment uses a different port, see the [Configuration](#configuration) section.

---

## Implementation Notes

These notes are intended for developers who need to modify or extend the dissector.

### File structure

The dissector is a single self-contained Lua file with the following logical sections:

| Lines | Content |
|---|---|
| 1–59 | Header comment: full protocol structure reference |
| 61–88 | `Proto` object creation and `ProtoField` declarations |
| 90–108 | `decode_symbol()`: base-27 symbol decoder with signed-integer fix |
| 110–143 | `format_timestamp()`: manual Gregorian calendar calculation |
| 145–159 | `TYPE_NAMES` table: typecode → name |
| 161–198 | `FIELD_LABELS` table (369 entries) and `field_label()` helper |
| 200–302 | `dissect_value()`: dispatches a single value by typecode |
| 304–757 | `dissect_map()`: parses standard and extended ESCHER Maps |
| 759–827 | `dissect_array()`: parses standard and extended ESCHER Arrays |
| 829–873 | `escher_proto.dissector()`: main entry point, info column |
| 875–879 | Port registration |

### Adding new symbols

To add a human-readable label for a new symbol, add one line to the `FIELD_LABELS` table:

```lua
["XYZW"] = "My New Field",
```

Symbols with trailing spaces must include the spaces inside the quotes: `["WI  "]`, `["REQ "]`.

### Adding new typecodes

If a new typecode is encountered in future protocol versions, add a branch to `dissect_value()` following the pattern of the existing branches, and add the name to `TYPE_NAMES`. Unknown typecodes currently consume 4 bytes and display as `UNK<n>`.

### Signed 32-bit integer fix

Wireshark's Lua `bit` library (from the `bitop` library) operates on signed 32-bit integers. Any symbol value with bit 31 set is returned as a negative number from `bit.band()`. The fix in `decode_symbol()` is:

```lua
if val < 0 then val = val + 4294967296 end
```

This works correctly because Lua 5.1 numbers are IEEE-754 doubles with a 53-bit mantissa, which is sufficient to represent all unsigned 32-bit values without loss of precision. The same issue does not affect typecode or offset extraction because `bit.rshift()` treats its input as unsigned before shifting.

# ESCHER Protocol Dissector for Wireshark

This Lua dissector provides deep packet inspection for the **ESCHER** protocol, a key-value map-based protocol used for network communication.

## 🚀 Installation

1. Open Wireshark and go to **About Wireshark** -> **Folders**.
2. Locate the **Personal Lua Plugins** folder.
3. Copy [escher_dissector.lua] into that folder.
4. Restart Wireshark or press **Ctrl+Shift+L** to reload plugins.

---

## 🔍 Filtering Guide

### 1. General Filters
These filters work on the protocol structure itself:

| Filter | Description |
| :--- | :--- |
| `escher` | Show all ESCHER protocol packets. |
| `escher.map.items > 5` | Find maps with more than 5 items. |
| `escher.sym == "ACTN"` | Find any packet containing an `ACTN` key. |
| `escher.field_label == "FOX Action"` | Find any packet containing a "FOX Action" key. |

### 2. Specific Field Filters (Symbol-Based)
Every known symbol from the `FIELD_LABELS` table is registered as a specific filter. Spaces are replaced by underscores, and names are lowercase.

Examples:
- **`escher.actn == "REQ "`**
- **`escher.type == "WI  "`**
- **`escher.cli == "447700900123"`**
- **`escher.cmid == "1234"`**

### 3. Advanced Filtering Techniques

#### Whitespace Stripping (Automatic)
The dissector automatically stripped trailing whitespace for symbols and strings to make filtering easier. You can use either the full padded value or the clean value:
- `escher.type == "WI  "` (Matches exact)
- `escher.type == "WI"` (Matches stripped)

#### Wildcards & Regex
Wireshark's standard filter engine supports regular expressions via the `matches` (or `~`) operator:
- **Prefix match**: `escher.cli matches "^447"*`
- **Suffix match**: `escher.cli matches "000$"`
- **Pattern match**: `escher.cli matches "44790.*000"`
- **Case-insensitive**: `escher.type matches "(?i)wi"`

1. Using matches (Regex support)
This is the most powerful way. Use .* as the wildcard: escher.cli matches "^44790.*000$" (This matches any CLI starting with 44790 and ending with 000)

2. Using contains (Substring match)
To find any CLI that contains "44790": escher.cli contains "44790"

3. Case-Insensitive Matching
If you want to match symbols or strings regardless of case: escher.type matches "(?i)wi"

Summary Table for Filter Field
| Operator  | Example                          | Description                              |
|----------|----------------------------------|------------------------------------------|
| `==`     | `escher.cli == "447700900123"`   | Exact match.                             |
| `contains` | `escher.cli contains "900"`    | Match if value contains "900".           |
| `matches` | `escher.cli matches "44790.*000"` | Match using a regular expression.        |
| `~`      | `escher.cli ~ "44790.*000"`      | Shorthand for matches.                   |