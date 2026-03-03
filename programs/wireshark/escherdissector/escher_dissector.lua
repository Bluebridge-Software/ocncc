-- ============================================================
-- ESCHER Protocol Dissector - FIXED VERSION
-- 
-- FIX: Removed the "backing up" logic for nested maps.
-- The offset in the key already points directly to the map header.
-- ============================================================

local escher_proto = Proto("ESCHER", "ESCHER Protocol")

-- Type codes
local NULL_TYPE   = 0x00
local INT_TYPE    = 0x01
local DATE_TYPE   = 0x02
local SYMBOL_TYPE = 0x03
local FLOAT_TYPE  = 0x04
local STRING_TYPE = 0x05
local ARRAY_TYPE  = 0x06
local MAP_TYPE    = 0x07
local RAW_TYPE    = 0x08

-- Field definitions
local f_int       = ProtoField.int32("escher.int", "Integer", base.DEC)
local f_float     = ProtoField.double("escher.float", "Float")
local f_string    = ProtoField.string("escher.string", "String")
local f_symbol    = ProtoField.string("escher.symbol", "Symbol")
local f_date      = ProtoField.absolute_time("escher.date", "Date")
local f_raw       = ProtoField.bytes("escher.raw", "Raw Data")
local f_length    = ProtoField.uint16("escher.length", "Length", base.DEC)
local f_count     = ProtoField.uint16("escher.count", "Items", base.DEC)

escher_proto.fields = {f_int, f_float, f_string, f_symbol, f_date, f_raw, f_length, f_count}

-- ============================================================
-- Helper functions
-- ============================================================

local function decode_symbol(symbol_int)
    local c1 = bit.band(bit.rshift(symbol_int, 24), 0xFF)
    local c2 = bit.band(bit.rshift(symbol_int, 16), 0xFF)
    local c3 = bit.band(bit.rshift(symbol_int, 8), 0xFF)
    local c4 = bit.band(symbol_int, 0xFF)
    
    local sym = string.char(c1, c2, c3, c4)
    return sym:gsub("%z+$", ""):gsub(" +$", "")
end

local function extract_key_parts(key_val)
    local symbol = bit.band(key_val, 0xFFFFE000)
    local typecode = bit.band(bit.rshift(key_val, 9), 0x0F)
    local offset = bit.lshift(bit.band(key_val, 0x1FF), 2)
    return symbol, typecode, offset
end

-- ============================================================
-- Individual value type parsers
-- ============================================================

local function dissect_int(tvb, tree, offset)
    if offset + 4 > tvb:len() then return 0 end

    local raw = tvb(offset,4):uint()   -- big-endian
    local value = (raw >= 0x80000000) and (raw - 0x100000000) or raw

    tree:add(f_int, tvb(offset,4), value)
    return 4
end

local function dissect_float(tvb, tree, offset)
    if offset + 8 > tvb:len() then return 0 end
    tree:add(f_float, tvb(offset, 8))  -- big-endian double
    return 8
end

local function dissect_date(tvb, tree, offset)
    if offset + 4 > tvb:len() then return 0 end
    local timestamp = tvb(offset, 4):uint()  -- big-endian
    tree:add(f_date, tvb(offset, 4), timestamp)
    return 4
end

local function dissect_string(tvb, tree, offset)
    if offset >= tvb:len() then return 0 end

    local len_byte = tvb(offset, 1):uint()
    local str_len, str_start

    if bit.band(len_byte, 0x80) == 0 then
        str_len = len_byte
        str_start = 1
    else
        if offset + 2 > tvb:len() then return 0 end
        str_len = bit.band(tvb(offset, 2):uint(), 0x7FFF)
        str_start = 2
    end

    if offset + str_start + str_len > tvb:len() then return 0 end

    tree:add(f_string, tvb(offset + str_start, str_len))
    return str_start + str_len
end

local function dissect_symbol_value(tvb, tree, offset)
    if offset + 4 > tvb:len() then return 0 end
    local symbol_int = tvb(offset, 4):uint()  -- big-endian
    local symbol_str = decode_symbol(symbol_int)
    tree:add(f_symbol, tvb(offset, 4), symbol_str)
    return 4
end

-- ============================================================
-- Main map and value dispatchers
-- ============================================================

function dissect_map(tvb, tree, offset, depth)
    depth = depth or 0
    
    if offset + 4 > tvb:len() then
        return 0
    end
    
    local start_offset = offset
    local total_len = tvb(offset, 2):uint()       -- big-endian
    local num_items = tvb(offset + 2, 2):uint()   -- big-endian

    tree:add(f_length, tvb(offset, 2))
    tree:add(f_count, tvb(offset + 2, 2))
    
    if depth == 0 then
        tree:append_text(string.format(": Map with %d items, %d bytes total", num_items, total_len))
    end
    
    offset = offset + 4
    local items_start = offset
    
    -- Parse map keys and values
    if num_items > 0 and num_items < 100 then
        for i = 0, num_items - 1 do
            if offset + 4 > tvb:len() then
                break
            end
            
            local key_val = tvb(offset, 4):uint()
            local symbol, typecode, item_offset = extract_key_parts(key_val)
            local symbol_str = decode_symbol(symbol)
            
            offset = offset + 4
            
            if item_offset > 0 then
                local value_offset = items_start + item_offset
                if value_offset < tvb:len() then
                    -- FIXED: No special handling for nested maps
                    -- The offset already points directly to the map header
                    dissect_value(tvb, tree, typecode, value_offset, depth, symbol_str)
                end
            end
        end
    end
    
    return total_len
end

local function dissect_value(tvb, tree, typecode, offset, depth, name)
    if offset >= tvb:len() or depth > 16 then
        return 0
    end
    
    local subtree = tree
    if name and name ~= "" then
        subtree = tree:add(escher_proto, tvb(offset, 0), name)
    end
    
    if typecode == INT_TYPE then
        return dissect_int(tvb, subtree, offset)
    elseif typecode == FLOAT_TYPE then
        return dissect_float(tvb, subtree, offset)
    elseif typecode == DATE_TYPE then
        return dissect_date(tvb, subtree, offset)
    elseif typecode == SYMBOL_TYPE then
        return dissect_symbol_value(tvb, subtree, offset)
    elseif typecode == STRING_TYPE then
        return dissect_string(tvb, subtree, offset)
    elseif typecode == MAP_TYPE then
        return dissect_map(tvb, subtree, offset, depth + 1)
    else
        return 0
    end
end

-- ============================================================
-- Main dissector
-- ============================================================

function escher_proto.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "ESCHER"
    
    local subtree = tree:add(escher_proto, tvb(), "ESCHER Protocol")
    
    if tvb:len() >= 4 then
        dissect_map(tvb, subtree, 0, 0)
    end
    
    return tvb:len()
end

-- Register on port 1500
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1500, escher_proto)

print("=" .. string.rep("=", 80))
print("ESCHER Dissector Loaded - FIXED: Correct nested map parsing - Tony1")
print("=" .. string.rep("=", 80))
