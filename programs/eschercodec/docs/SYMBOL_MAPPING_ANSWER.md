# DEFINITIVE ANSWER: Symbol Mapping Requirement

## Can you avoid requiring a symbol map?

**NO.** Here's why:

### The Wire Format CANNOT Store Full Symbols

The Escher protocol uses a **19-bit encoding** for symbols in map keys. This is PERMANENT information loss.

#### Proof:

```
Full Symbol "GENE" = 0x47454E45 (32 bits)
│
├─ Byte 0: 0x47 'G' ━━━━━━━━━━━━━━━ Fully preserved ✓
├─ Byte 1: 0x45 'E' ━━━━━━━━━━━━━━━ Fully preserved ✓  
├─ Byte 2: 0x4E 'N' ━━━━━┓
│                         ├──── LOST
└─ Byte 3: 0x45 'E' ━━━━━┛       ↓
                                  ↓
Wire Format = 0x47454A03          ↓
│                                 ↓
├─ Byte 0: 0x47 'G' ━━━━━━━━━━━━━━━ Preserved ✓
├─ Byte 1: 0x45 'E' ━━━━━━━━━━━━━━━ Preserved ✓
├─ Byte 2: 0x4A 'J' ━━━━━━━━━━━━━━━ WRONG! (lost bottom bits)
└─ Byte 3: 0x03     ━━━━━━━━━━━━━━━ WRONG! (encodes type+offset)
```

**Result**: 'N' becomes 'J', 'E' becomes '\x03'
**Information permanently LOST - cannot be recovered!**

### Why Does the C++ Code Work?

The C++ application **knows the full symbol names** via hardcoded constants:

```cpp
// In C++ header files:
ESCHER_SYMBOL(KEY_ACTION, "ACTN");
ESCHER_SYMBOL(KEY_TYPE, "TYPE");
ESCHER_SYMBOL(KEY_BODY, "BODY");

// When looking up:
Symbol action = msg->getSymbol(KEY_ACTION());  // Provides full "ACTN"
//                              └────────────> Library truncates to "AC@"
//                                            for wire format lookup
```

**The application provides the full name, library truncates it for lookup.**

### Your Options

#### Option 1: Accept Truncated Symbols (CORRECT for Wireshark)

Show what's actually in the wire format:

```python
python3 escher_codec.py decode message.escher output.json
```

Output:
```json
{
  "AC@": "REQ ",
  "TY@": "IR  ",
  "BO@": {
    "CL@": "447700900123"
  }
}
```

✅ **This is CORRECT** - it shows what's actually transmitted!
✅ **Use this for Wireshark dissectors**

#### Option 2: Human-Friendly Display (requires symbol mapping)

Map truncated → full for readability:

```python
python3 escher_codec.py decode message.escher output.json symbols.json
```

Output:
```json
{
  "ACTN": "REQ ",
  "TYPE": "IR  ",
  "BODY": {
    "CLI": "447700900123"
  }
}
```

✅ Better for human readers
❌ Requires symbol mapping file

## What You Need for Complete Mapping

Extract ALL symbols from your C++ codebase:

```bash
# Run on all your C++ source files
python3 extract_symbols.py /path/to/your/*.hh /path/to/your/*.cc > symbols.json
```

This extracts all `ESCHER_SYMBOL(NAME, "SYMB")` definitions and creates the mapping:

```json
{
  "AC@": "ACTN",
  "TY@": "TYPE",
  "BO@": "BODY",
  "HE@": "HEAD",
  "CM@": "CMID",
  ...
}
```

## For Your Use Case

Since you're decoding production PCAPs for analysis:

### Recommended Approach:

1. **Generate complete symbol mapping once**:
   ```bash
   python3 extract_symbols.py /path/to/ocncc/code/**/*.hh **/*.cc > ocncc_symbols.json
   ```

2. **Use for all decoding**:
   ```bash
   python3 escher_codec.py decode capture.escher output.json ocncc_symbols.json
   ```

3. **For Lua/Wireshark dissectors**:
   - **Option A**: Show truncated symbols (what's actually there)
   - **Option B**: Build the same mapping table in Lua

### Lua Dissector Example:

```lua
-- Option A: Show wire format (simplest)
local symbol = buffer(offset, 4):string()
tree:add(field, buffer(offset, 4), symbol)  -- Shows "AC@", "TY@", etc.

-- Option B: Expand symbols (requires mapping)
local SYMBOLS = {
    ["AC@"] = "ACTN",
    ["TY@"] = "TYPE",
    ["BO@"] = "BODY",
    ["HE@"] = "HEAD"
}

local wire_symbol = buffer(offset, 4):string()
local full_symbol = SYMBOLS[wire_symbol] or wire_symbol
tree:add(field, buffer(offset, 4), full_symbol)  -- Shows "ACTN", "TYPE", etc.
```

## Summary

| Approach | Pros | Cons | Use Case |
|----------|------|------|----------|
| **No mapping** | Simple, shows actual wire format | Truncated symbols | Wireshark (recommended) |
| **With mapping** | Human-readable full names | Requires symbol file | Analysis tools |

### The Truth:

- ❌ **Cannot avoid mapping** if you want full names
- ✅ **Can avoid mapping** if truncated names are acceptable
- 🎯 **For Wireshark**: Show truncated (what's actually transmitted)
- 📊 **For analysis**: Use mapping (easier to read)

### What to Provide:

Run the extraction script on your entire OCNCC codebase to get ALL symbols:

```bash
find /path/to/ocncc -name "*.hh" -o -name "*.cc" | xargs python3 extract_symbols.py > complete_ocncc_symbols.json
```

This is a **ONE-TIME** operation. The resulting file can be used for all future decoding.
