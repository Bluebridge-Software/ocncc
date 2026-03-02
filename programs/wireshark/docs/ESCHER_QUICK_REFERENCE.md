# ESCHER Protocol Quick Reference Card

## Type Codes (8-bit)

| Code | Type        | Size      | Description                    |
|------|-------------|-----------|--------------------------------|
| 0x00 | NULL        | 0 bytes   | Null/empty value              |
| 0x01 | INT         | 4 bytes   | 32-bit signed integer         |
| 0x02 | DATE        | 4 bytes   | Unix timestamp (time_t)       |
| 0x03 | SYMBOL      | 4 bytes   | 4-character identifier        |
| 0x04 | FLOAT       | 8 bytes   | 64-bit IEEE 754 double        |
| 0x05 | STRING      | Variable  | Length-prefixed UTF-8 string  |
| 0x06 | ARRAY       | Variable  | Ordered sequence of values    |
| 0x07 | MAP         | Variable  | Key-value pairs (Symbol keys) |
| 0x08 | RAW         | Variable  | Binary data with length       |

## Byte Order

**Network Byte Order (Big-Endian)** - Most significant byte first

## Alignment

All values padded to **4-byte boundaries**

## Container Headers

### Standard Format (< 2048 bytes)
```
Offset  Size  Field           Description
0       2     Length          Total bytes (including header)
2       2     Count           Number of items
4       N     Index           Type and offset info
4+N     M     Data            Actual values
```

### Extended Format (≥ 2048 bytes or explicitly set)
```
Offset  Size  Field           Description
0       2     Marker          0xFFFE (Extended header ID)
2       1     CtrlLen         Control block length
3       1     CtrlData        Control block data
4       4     Length          Total bytes (32-bit)
8       4     Count           Number of items (32-bit)
12      N     Index           Type and offset info
12+N    M     Data            Actual values
```

## Map Key Encoding (32-bit)

```
Bits    Field           Description
31-13   Symbol          19-bit encoded symbol
12-9    Type            4-bit type code
8-0     Offset          9-bit offset ÷ 4
```

**Formula**: `key = (symbol & 0xFFFFE000) | (type << 9) | (offset >> 2)`

## Array Index Encoding (16-bit)

```
Bits    Field           Description
15-9    Type            4-bit type code (shifted)
8-0     Offset          9-bit offset ÷ 4
```

**Formula**: `index = (type << 9) | (offset >> 2)`

## String Encoding

### Short String (< 128 bytes)
```
Offset  Size    Description
0       1       Length (0-127)
1       N       String data
1+N     P       Padding to 4-byte boundary
```

### Long String (≥ 128 bytes)
```
Offset  Size    Description
0       2       Length with bit 15 set (length | 0x8000)
2       N       String data
2+N     P       Padding to 4-byte boundary
```

## Dirty Flag Detection

```c
#define NEW_DIRTY_MASK 0x8001
#define IS_DIRTY(x) (((x) & 0x8001) == 0x8001)
```

If first 32-bit word of Map/Array has bits 15 and 0 set:
- Structure has been unpacked to memory
- Contains pointer instead of encoded data
- Cannot be decoded without source program

## Symbol Encoding

4 ASCII characters packed into 32-bit big-endian integer:

```python
# Encode
symbol_int = struct.unpack('>I', 'TEST'.encode('ascii'))[0]

# Decode
symbol_str = struct.pack('>I', symbol_int).decode('ascii')
```

**Example**: 'WGR ' → 0x57475220

## Date/Time

Unix timestamp (seconds since Jan 1, 1970 UTC):

```c
uint32_t timestamp;  // Network byte order
```

## Float Encoding

IEEE 754 double-precision (64-bit):

```c
double value;  // Network byte order (big-endian)
```

## Raw Data

```
Offset  Size    Description
0       4       Length (32-bit)
4       N       Binary data
4+N     P       Padding to 4-byte boundary
```

## Wireshark Display Filters

```
escher                          # All Escher packets
escher.type == 0x01            # Integer values
escher.type == 0x05            # String values
escher.type == 0x07            # Maps
escher.extended == 1           # Extended format
escher.dirty == 1              # Dirty/unpacked
escher.map.symbol contains "X" # Symbol contains X
escher.int > 1000              # Integer value > 1000
escher.string contains "test"  # String contains "test"
```

## Common Message Structure

```
Message (Top-level Map)
├─ HEAD (Header Map)
│  ├─ VERS (Version: Int)
│  ├─ TIME (Timestamp: Date)
│  ├─ TYPE (Message Type: Symbol)
│  └─ SEQN (Sequence: Int)
├─ BODY (Payload Map)
│  └─ ... (Message-specific data)
└─ TAIL (Trailer Map)
   ├─ STAT (Status: Symbol)
   └─ CODE (Status Code: Int)
```

## Example: Decoding a Map

```
Hex Data:
00 20 00 02  48 45 41 44  00 04 48 45  41 44 ...

Decode:
1. Read length: 0x0020 = 32 bytes
2. Read count: 0x0002 = 2 items
3. Read key 1: 0x48454144 
   - Symbol: 0x48450000 = "HEA" (19 bits)
   - Type: 0x0 (extracted from bits 12-9)
   - Offset: 0x04 << 2 = 16 bytes
4. Navigate to offset 16, decode value
```

## Performance Tips

- Use capture filters to reduce traffic
- Apply display filters for specific analysis
- Disable dissector when not needed
- Extended format adds ~8 bytes overhead

## Troubleshooting

| Issue                    | Solution                              |
|--------------------------|---------------------------------------|
| Not decoding             | Use "Decode As..." → ESCHER          |
| Wrong values             | Check byte order (should be BE)       |
| Alignment errors         | Verify 4-byte padding                 |
| Dirty flag set           | Message was modified in memory        |
| Extended header present  | Structure > 2KB or explicitly enabled |

## Size Limits

| Format   | Max Length    | Max Items     |
|----------|---------------|---------------|
| Standard | 64 KB         | 65,535        |
| Extended | 4 GB          | 4,294,967,295 |

## Key Symbols (Examples)

Common 4-character symbols in OCNCC:
- `HEAD` - Message header
- `BODY` - Message body
- `TAIL` - Message trailer
- `TYPE` - Message type
- `VERS` - Version
- `TIME` - Timestamp
- `ACCT` - Account
- `IMSI` - IMSI number
- `STAT` - Status
- `CODE` - Status code
- `WGR ` - Wallet General Recharge (note trailing space)

## Resources

- **Wireshark**: https://www.wireshark.org/
- **Lua Reference**: https://www.lua.org/manual/5.4/
- **Protocol Docs**: See ESCHER_DISSECTOR_README.md

## Quick Commands

```bash
# Load dissector
wireshark -X lua_script:escher_dissector.lua

# Generate test messages
python3 escher_test_generator.py

# View hex dump
od -A x -t x1z -v message.escher

# Convert to PCAP
text2pcap -l 147 -t %Y-%m-%d %H:%M:%S. \
  message.hex message.pcap
```

---

**Note**: All multi-byte integers use network byte order (big-endian).
Padding bytes can contain any value and should be ignored.
