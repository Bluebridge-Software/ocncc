# Escher Dissector - x86 Linux Architecture Notes

## Architecture-Specific Considerations

### Platform Details
- **Target Architecture**: x86 (32-bit and 64-bit)
- **Operating System**: Linux
- **Endianness**: Little-endian (x86 native)
- **Network Protocol**: Big-endian (network byte order)

## Key Differences: SPARC vs x86

### SPARC (Big-Endian)
```
Memory layout of 0x12345678:
Address:  0x00  0x01  0x02  0x03
Value:    0x12  0x34  0x56  0x78  (MSB first)
```

### x86 (Little-Endian)
```
Memory layout of 0x12345678:
Address:  0x00  0x01  0x02  0x03
Value:    0x78  0x56  0x34  0x12  (LSB first)
```

## Escher Protocol on x86

### Wire Format (Network Byte Order)
The Escher protocol specification mandates **network byte order (big-endian)** for all multi-byte values on the wire, regardless of the host architecture.

```
Example: Integer value 100 (0x00000064)
On wire:     [00] [00] [00] [64]  (big-endian)
In x86 RAM:  [64] [00] [00] [00]  (little-endian)
```

### Wireshark Buffer Reading

When Wireshark reads network packets on x86 Linux:

```lua
-- Reading with :uint() or :int() 
buffer(offset, 4):uint()  -- Automatically converts from network byte order
buffer(offset, 4):int()   -- to x86 host byte order (little-endian)

-- Reading with :le_uint() or :le_int()
buffer(offset, 4):le_uint()  -- Assumes data is already in little-endian
                             -- (DO NOT use for Escher integers!)
```

**Important**: Use `:uint()` and `:int()` without the `le_` prefix for Escher protocol integers. Wireshark will automatically perform the byte order conversion.

## Symbol Table Byte Order

### The Challenge

Symbol values in the FOX_SYMBOLS table need special handling on x86:

```
Network bytes for "VNUM": [56] [4E] [55] [4D]
As 32-bit big-endian:     0x564E554D
As 32-bit little-endian:  0x4D554E56  <- What x86 sees in RAM
```

### Two Approaches

#### Approach 1: Network Byte Order Keys (Original)
```lua
local FOX_SYMBOLS = {
    [0x564E554D] = "VNUM",  -- Network byte order
}

-- Lookup after reading from buffer
local symbol_val = buffer(offset, 4):uint()  -- Gets 0x564E554D
local name = FOX_SYMBOLS[symbol_val]         -- Works!
```

**Pros**: Matches protocol specification exactly
**Cons**: Symbol table looks "byte-swapped" to x86 developers

#### Approach 2: Host Byte Order Keys (x86 Optimized)
```lua
local FOX_SYMBOLS = {
    [0x4D554E56] = "VNUM",  -- x86 byte order (what you see in memory)
}

-- Lookup after reading from buffer  
local symbol_val = buffer(offset, 4):uint()  -- Gets 0x564E554D
-- Need to byte-swap for lookup on x86
local swapped = bit.bswap(symbol_val)        -- Gets 0x4D554E56
local name = FOX_SYMBOLS[swapped]            -- Works!
```

**Pros**: Symbol table matches what x86 debuggers show
**Cons**: Requires explicit byte-swapping

### Implemented Solution

The x86-optimized dissector uses **Approach 2** with pre-swapped symbol keys:

```lua
local FOX_SYMBOLS = {
    [0x4D554E56] = "VNUM",    -- Pre-swapped for x86 lookup
    [0x46455241] = "AREF",    -- Matches x86 memory representation
    -- ...
}
```

**Why?** This makes debugging easier on x86 Linux:
- Memory dumps show recognizable values
- GDB/LLDB displays match the table
- Less confusion for developers

## Integer Values

### Correct Reading on x86

```lua
-- CORRECT: Let Wireshark handle conversion
local value = buffer(offset, 4):int()   -- Signed 32-bit
local value = buffer(offset, 4):uint()  -- Unsigned 32-bit
local value = buffer(offset, 2):uint()  -- Unsigned 16-bit

-- WRONG: Manual little-endian read
local value = buffer(offset, 4):le_int()   -- NO! This assumes LE on wire
```

### Why It Works

Wireshark's `:uint()` and `:int()` methods:
1. Read bytes from network packet (big-endian)
2. Convert to host byte order (little-endian on x86)
3. Return the correct integer value

**Example**:
```
Wire bytes:    [00] [00] [00] [64]  (100 in big-endian)
:uint() reads: 0x00000064            (100 - correct!)
:le_uint():    0x64000000            (1,677,721,600 - WRONG!)
```

## Floating Point Values

Floating point uses a different convention:

```lua
-- Floats are stored as IEEE 754 little-endian after network conversion
local value = buffer(offset, 8):le_float64()  -- CORRECT for doubles
```

**Why?** The C++ code uses `htonf()` which converts the double to network format, but the actual byte storage follows the platform's IEEE 754 representation.

## Symbol Display

### Byte Order in Display

When displaying symbols, we want to show them as ASCII strings:

```lua
local function decode_symbol(val)
    -- val is already converted to host byte order by :uint()
    -- For x86, this means it's little-endian in our variable
    
    -- Extract bytes (MSB to LSB from network perspective)
    local c1 = bit.band(bit.rshift(val, 24), 0xFF)  -- First network byte
    local c2 = bit.band(bit.rshift(val, 16), 0xFF)  -- Second network byte
    local c3 = bit.band(bit.rshift(val, 8), 0xFF)   -- Third network byte
    local c4 = bit.band(val, 0xFF)                  -- Fourth network byte
    
    return string.char(c1) .. string.char(c2) .. string.char(c3) .. string.char(c4)
end

-- Example:
-- Network bytes: [56] [4E] [55] [4D] = "VNUM"
-- After :uint() on x86: val = 0x564E554D
-- c1 = 0x56 = 'V'
-- c2 = 0x4E = 'N'  
-- c3 = 0x55 = 'U'
-- c4 = 0x4D = 'M'
-- Result: "VNUM" ✓
```

## Testing on x86 Linux

### Verify Byte Order Handling

```bash
# Create a test with known values
echo "00 00 00 64" | xxd -r -p > test_int.bin  # Integer 100

# In Python test generator:
import struct
data = struct.pack('>I', 100)  # Big-endian integer
# Result: b'\x00\x00\x00\x64'
```

### Debug in Wireshark

```lua
-- Add debug output to dissector
local function dissect_value(buffer, offset, tree, typecode)
    if typecode == INT_TYPE then
        local value = buffer(offset, 4):int()
        print(string.format("DEBUG: offset=%d, raw_bytes=%s, value=%d",
              offset,
              buffer(offset, 4):bytes():tohex(),
              value))
        -- Should print: "DEBUG: offset=4, raw_bytes=00000064, value=100"
    end
end
```

### Validate Symbol Lookup

```bash
# In Python:
symbol_bytes = b'VNUM'  # ASCII bytes
symbol_int = struct.unpack('>I', symbol_bytes)[0]  # Big-endian
print(f"Network order: 0x{symbol_int:08X}")  # 0x564E554D

# For x86 lookup table:
symbol_int_x86 = struct.unpack('<I', symbol_bytes)[0]  # Little-endian
print(f"x86 order: 0x{symbol_int_x86:08X}")      # 0x4D554E56
```

## Common Pitfalls on x86

### ❌ Mistake 1: Using Little-Endian Reads
```lua
-- WRONG
local value = buffer(offset, 4):le_uint()  -- Assumes data is little-endian
```

**Fix**: Use `:uint()` which handles network byte order conversion

### ❌ Mistake 2: Byte-Swapped Symbol Table
```lua
-- WRONG for x86
local FOX_SYMBOLS = {
    [0x564E554D] = "VNUM",  -- Network byte order
}
local symbol_val = buffer(offset, 4):uint()  -- Gets 0x564E554D on x86
-- Lookup will fail because table has network-order keys!
```

**Fix**: Pre-swap symbol table keys for x86 host order

### ❌ Mistake 3: Manual Byte Swapping
```lua
-- WRONG
local value = buffer(offset, 4):uint()
local swapped = bit.bswap(value)  -- Unnecessary! Wireshark already converted
```

**Fix**: Trust Wireshark's byte order conversion

## Performance Considerations

### x86 Optimizations

1. **Symbol Lookup**: O(1) hash table lookup with pre-swapped keys
2. **No Runtime Swapping**: Keys are pre-computed at load time
3. **Native Integer Operations**: Let Wireshark handle byte order
4. **Minimal Overhead**: Byte order conversion happens once per value

### Memory Access Patterns

x86 handles unaligned access well, but Escher uses 4-byte alignment:

```lua
-- Escher alignment (4 bytes) matches x86 cache lines
local function align(x)
    return bit.band(x + 3, bit.bnot(3))  -- Round up to 4-byte boundary
end
```

## Debugging Tips

### Hex Dump Analysis

```bash
# View raw packet bytes
tcpdump -i eth0 -X port 5000 > capture.txt

# Look for patterns:
# Big-endian int 100:    00 00 00 64
# String "VNUM":         56 4E 55 4D
# Extended header:       FF FE ...
```

### Wireshark Lua Console

```lua
-- Test byte order in Wireshark's Lua console
function test_byte_order()
    local testdata = ByteArray.new("00000064")  -- Integer 100
    local tvb = testdata:tvb()
    
    print("Big-endian read:", tvb(0, 4):uint())     -- Should print 100
    print("Little-endian read:", tvb(0, 4):le_uint()) -- Would print 1677721600
end
```

## Migration Checklist

If migrating from SPARC to x86:

- [x] Update symbol table with x86 byte order
- [x] Use `:uint()` not `:le_uint()` for integers
- [x] Keep `:le_float64()` for floats
- [x] Test with known-good PCAPs
- [x] Verify integer values decode correctly
- [x] Check symbol names display properly
- [x] Validate extended format messages

## Summary

| Aspect | SPARC (Big-Endian) | x86 (Little-Endian) |
|--------|-------------------|---------------------|
| **Network Data** | Matches host order | Needs conversion |
| **Integer Read** | `:uint()` | `:uint()` (same!) |
| **Symbol Table** | Network order keys | Host order keys |
| **Float Read** | `:le_float64()` | `:le_float64()` (same!) |
| **Byte Swapping** | Not needed | Handled by Wireshark |
| **Symbol Display** | Direct | Extract & reorder |

**Key Takeaway**: The x86-optimized dissector handles byte order automatically by:
1. Pre-swapping symbol table keys to match x86 host order
2. Using Wireshark's built-in byte order conversion (`:uint()`)
3. Correctly interpreting the protocol's network byte order data

The dissector is now optimized for x86 Linux deployments! 🎯
