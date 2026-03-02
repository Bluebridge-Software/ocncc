# ESCHER and FOX Protocol Dissectors - Complete Guide

## Overview

There are **TWO SEPARATE** Wireshark dissectors for Oracle protocols:

1. **ESCHER Dissector** (port 1500) - Generic Escher protocol
2. **FOX Dissector** (port 1700) - FOX messaging protocol (uses Escher encoding)

Both use the same underlying **Escher binary encoding format** but are different protocols with different ports and message structures.

## Source Files Analysis

### ESCHER Dissector Source
- **`escher.c`**: C wrapper for Wireshark plugin system
- **`decodeEscher.cc`**: Main C++ dissector (751 lines)
- **`decodeEscher.h`**: Header with extern C declarations
- **`protocolHandleMap.cc/hh`**: Dynamic protocol registration
- **`subtreeHandleMap.cc/hh`**: Subtree handle management
- **`fieldWrapper.cc/hh`**: Dynamic field registration

**Key Characteristics**:
- Port: **1500**
- Generic Escher message decoder
- Dynamic field registration (fields created on-the-fly)
- Hierarchical naming: `escher.body.field`, `escher.body.map.field`
- Handles any Escher-encoded message

### FOX Dissector Source
- **`fox.c`**: C wrapper for Wireshark plugin system
- **`escherBridge.cc`**: Main C++ dissector (566 lines)
- **`escherBridge.h`**: Header with extern C declarations

**Key Characteristics**:
- Port: **1700**
- FOX-specific message decoder
- Pre-defined static fields (HEAD, BODY, ACTN, TYPE)
- Flat naming: `fox.action`, `fox.head.cmid`, `fox.body.cli`
- Extracts specific FOX message structure

## Key Differences

| Aspect | ESCHER (port 1500) | FOX (port 1700) |
|--------|-------------------|-----------------|
| **Purpose** | Generic Escher decoder | FOX messaging protocol |
| **Field Names** | `escher.*` | `fox.*` |
| **Structure** | Dynamic | Fixed (HEAD/BODY) |
| **Fields** | Created on-the-fly | Pre-registered |
| **Message Types** | Any Escher message | FOX messages (IR, SR, CR, WGR, VI, etc.) |
| **Complexity** | 751 lines C++ | 566 lines C++ |
| **Port** | 1500 | 1700 |

## Protocol Structure

### Escher Encoding Format

Both protocols use the same binary encoding:

```
┌─────────────────────────────────────┐
│ STANDARD FORMAT (< 64KB)            │
├─────────────────────────────────────┤
│ Offset 0-1: Byte length (16-bit)    │
│ Offset 2-3: Item count (16-bit)     │
│ Offset 4-N: Index section           │
│ Offset M-L: Data section            │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ EXTENDED FORMAT (>= 64KB)           │
├─────────────────────────────────────┤
│ Offset 0-1: 0xFFFE marker            │
│ Offset 2:   Control byte             │
│ Offset 3:   Control data             │
│ Offset 4-7: Byte length (32-bit)    │
│ Offset 8-11: Item count (32-bit)    │
│ Offset 12-N: Index section          │
│ Offset M-L: Data section            │
└─────────────────────────────────────┘
```

### FOX Message Structure

FOX messages are Escher Maps with specific keys:

```
┌─────────────────────────────┐
│ FOX Message (Map)           │
├─────────────────────────────┤
│ ACTN: Symbol (REQ/ACK/...)  │
│ TYPE: Symbol (IR/WGR/VI...) │
│ HEAD: Map                   │
│   ├─ CMID: Int              │
│   ├─ DATE: Date             │
│   ├─ SVID: Int              │
│   ├─ VER: Int               │
│   └─ ...                    │
│ BODY: Map                   │
│   ├─ CLI: String            │
│   ├─ AREF: Int              │
│   ├─ WALT: Int              │
│   └─ ...                    │
└─────────────────────────────┘
```

## C++ Implementation Details

### ESCHER Dissector (decodeEscher.cc)

```cpp
// Line 141: Port definition
const int DEFAULT_PORT_NUMBER = 1500;

// Line 57: Main dissector entry point
static void dissect_escher(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

// Line 59: Recursive map dissection
static gint dissectMap(proto_tree *tree, tvbuff_t *tvb, 
                       string namePrefix, const Map &msg, 
                       ::std::ostringstream &ost, int start);
```

**Dynamic Field Registration**:
```cpp
// From fieldWrapper.cc:
int FieldWrapper::getFieldWrapper(const string &theName, 
                                  const string &abbrev, 
                                  const int protoHandle) {
    // Creates field on first use
    // Registers with Wireshark
    // Returns handle for subsequent use
}
```

**Key Features**:
- Fields created dynamically as messages are decoded
- Hierarchical naming based on message structure
- Generic - works with any Escher message
- More complex code (751 lines + support classes)

### FOX Dissector (escherBridge.cc)

```cpp
// Line 67: Port definition
const int DEFAULT_PORT_NUMBER = 1700;

// Line 42: Main dissector entry point  
static void dissect_fox(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

// Line 44: Header dissection
static gint dissectHeader(proto_tree *header_tree, tvbuff_t *tvb, 
                          const Map &head, ::std::ostringstream &ost, 
                          int headStart);

// Line 49: Body dissection
static gint dissectBody(proto_tree *body_tree, tvbuff_t *tvb, 
                        const Map &msg, ::std::ostringstream &ost, 
                        int bodyStart);
```

**Static Field Registration**:
```cpp
// Lines 142-209: Pre-defined fields
static hf_register_info hf[] = {
    { &hf_fox_action, "FOX Action", "fox.action", ... },
    { &hf_fox_type, "FOX Type", "fox.type", ... },
    { &hf_fox_head_cmid, "Request Number(CMID)", "fox.head.cmid", ... },
    // ... more fields ...
};
```

**Key Features**:
- Fields pre-registered at startup
- Flat naming structure
- FOX-specific - extracts ACTN, TYPE, HEAD, BODY
- Simpler code (566 lines, no support classes)

## Lua Conversion Strategy

### Why Two Separate Dissectors?

**Option 1: Combined Dissector** ❌
- Would need port-based logic
- Different field namespaces (escher.* vs fox.*)
- Different decoding strategies
- Complex and error-prone

**Option 2: Separate Dissectors** ✅ (CHOSEN)
- Each dissector is self-contained
- Clear separation of concerns
- Easy to maintain
- Matches C++ implementation

### Conversion Approach

**ESCHER Dissector (escher_dissector.lua)**:
```lua
-- Port 1500
-- Dynamic decoding
-- Generic structure
-- Fields: escher.*

local escher_proto = Proto("ESCHER", "ESCHER Protocol")
-- Decodes any Escher message
-- Creates hierarchical tree structure
```

**FOX Dissector (fox_dissector.lua)**:
```lua
-- Port 1700
-- Extracts FOX-specific fields
-- Fixed structure (HEAD/BODY)
-- Fields: fox.*

local fox_proto = Proto("FOX", "FOX Protocol")
-- Extracts ACTN, TYPE
-- Parses HEAD and BODY maps
```

## Installation

### Install Both Dissectors

```bash
# Copy both files to Wireshark plugins directory
cp escher_dissector.lua ~/.local/lib/wireshark/plugins/
cp fox_dissector.lua ~/.local/lib/wireshark/plugins/

# Restart Wireshark
wireshark

# Verify in console:
# "ESCHER Protocol Dissector Loaded (port 1500, generic Escher)"
# "FOX Protocol Dissector Loaded (port 1700)"
```

### Directory Structure
```
~/.local/lib/wireshark/plugins/
├── escher_dissector.lua   # Port 1500 - Generic Escher
└── fox_dissector.lua      # Port 1700 - FOX messaging
```

## Usage

### ESCHER Dissector (Port 1500)

**Capture Traffic**:
```bash
tcpdump -i eth0 port 1500 -w escher_capture.pcap
```

**Display Filters**:
```
escher                      # All ESCHER messages
escher.int > 1000          # Integer values > 1000
escher.string contains "test"  # String content search
```

**Message Types**:
- Any Escher-encoded message
- Database queries
- Configuration messages
- Internal system messages

### FOX Dissector (Port 1700)

**Capture Traffic**:
```bash
tcpdump -i eth0 port 1700 -w fox_capture.pcap
```

**Display Filters**:
```
fox                         # All FOX messages
fox.action contains "REQ"  # All requests
fox.type == "WGR "         # Wallet General Recharge
fox.head.cmid              # Messages with request number
fox.body.cli contains "44" # UK phone numbers
```

**Message Types**:
- IR (Initial Reserve Seconds)
- SR (Subsequent Reserve Seconds)
- CR (Debit Seconds & Release)
- WGR (Wallet General Recharge)
- WI (Wallet Info)
- VI (Voucher Info)
- VU (Voucher Update)
- VR (Voucher Reserve)
- CVR (Commit Voucher Reservation)
- RVR (Revoke Voucher Reservation)

## Architecture Support

Both dissectors work on:

| Platform | Architecture | Status |
|----------|-------------|--------|
| SPARC Solaris | Big-endian | ✅ Works |
| x86 Linux | Little-endian | ✅ Works |
| x86_64 Linux | Little-endian | ✅ Works |
| ARM Linux | Little-endian | ✅ Should work |

**Why it works**: Wireshark's `buffer:uint()` and `buffer:int()` methods automatically handle network→host byte order conversion.

## Comparison: C++ vs Lua

| Feature | C++ ESCHER | Lua ESCHER | C++ FOX | Lua FOX |
|---------|-----------|-----------|---------|---------|
| **Lines** | 751 + support | 420 | 566 | 250 |
| **Dependencies** | cmnEscher lib | None | cmnEscher lib | None |
| **Compilation** | Required | Not required | Required | Not required |
| **Performance** | Fast | Moderate | Fast | Moderate |
| **Maintenance** | Hard | Easy | Hard | Easy |
| **Portability** | Per-platform | Universal | Per-platform | Universal |

## Testing

### Test ESCHER Dissector

```bash
# Create test traffic on port 1500
# (Your application sends Escher messages)

# Capture
tcpdump -i eth0 port 1500 -w test.pcap

# Open in Wireshark
wireshark test.pcap

# Verify:
# - Protocol shows as "ESCHER"
# - Fields expand properly
# - Values decode correctly
```

### Test FOX Dissector

```bash
# Create test traffic on port 1700
# (Your FOX application sends messages)

# Capture
tcpdump -i eth0 port 1700 -w test.pcap

# Open in Wireshark
wireshark test.pcap

# Verify:
# - Protocol shows as "FOX"
# - fox.action and fox.type visible
# - HEAD and BODY sections decode
```

### Use Both Together

```bash
# Capture both protocols
tcpdump -i eth0 'port 1500 or port 1700' -w both.pcap

# In Wireshark, you'll see:
# - ESCHER messages (port 1500)
# - FOX messages (port 1700)
# - Each decoded by correct dissector
```

## Troubleshooting

### Issue: Messages Not Decoding

**Check**:
1. Correct port (1500 for ESCHER, 1700 for FOX)
2. Dissector loaded (check Help → About → Plugins)
3. TCP reassembly enabled (Edit → Preferences → Protocols → TCP)

**Fix**:
```
Right-click packet → Decode As... → Select ESCHER or FOX
```

### Issue: Wrong Values

**Symptom**: Integer values are byte-swapped
**Cause**: Using `:le_uint()` instead of `:uint()`
**Fix**: Check dissector code uses `:uint()` for network byte order

### Issue: Both Dissectors on Same Port

**Not Recommended**: Only register one dissector per port

**If needed**:
```lua
-- In one dissector, add heuristic:
if buffer:len() > 0 then
    local header = buffer(0, 4):uint()
    if header matches FOX pattern then
        return fox_proto.dissector(buffer, pinfo, tree)
    else
        return escher_proto.dissector(buffer, pinfo, tree)
    end
end
```

## Common Scenarios

### Scenario 1: Capture FOX Transaction

**Goal**: Debug a voucher redemption

**Steps**:
1. Start capture on port 1700
2. Trigger redemption
3. Stop capture
4. Filter: `fox.type == "VR  " or fox.type == "CVR "`
5. Follow the VR → CVR sequence

### Scenario 2: Monitor ESCHER Traffic

**Goal**: Watch internal system messages

**Steps**:
1. Start capture on port 1500
2. Run your application
3. Stop capture
4. Browse all ESCHER messages
5. Look for specific field values

### Scenario 3: Compare Requests/Responses

**Goal**: Match requests with responses

**Steps**:
1. Capture FOX traffic
2. Filter: `fox.head.cmid`
3. Sort by CMID value
4. Match REQ/ACK pairs

## Summary

- **ESCHER Dissector**: Generic Escher protocol decoder (port 1500)
  - Dynamic field registration
  - Works with any Escher message
  - Hierarchical naming

- **FOX Dissector**: FOX messaging protocol (port 1700)
  - Static field registration  
  - FOX-specific structure (HEAD/BODY)
  - Extracts ACTN/TYPE

Both dissectors:
- Support SPARC and x86 Linux
- Handle TCP reassembly
- Support extended format (>64KB messages)
- Detect dirty flags
- Work independently

**Recommendation**: Install both dissectors for complete coverage of Oracle Escher-based protocols.
