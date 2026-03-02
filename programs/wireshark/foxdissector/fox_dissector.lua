-- ============================================================
-- Oracle FOX Protocol Dissector
-- 
-- This is the GENERIC FOX dissector (port 1500)
-- Separate from FOX dissector (port 1700)
-- 
-- Supports both SPARC (big-endian) and x86 Linux (little-endian)
--
-- © COPYRIGHT: Blue Bridge Software Ltd - 2026
-- ============================================================

local fox_proto = Proto("FOX", "FOX Protocol")

-- ================= SYMBOL MAPPING =================

local SYMBOL_MAP = {
    -- Core FOX structure
    ["AC@"] = "ACTN",
    ["TY@"] = "TYPE",
    ["BO@"] = "BODY",
    ["HE@"] = "HEAD",
    
    -- Actions
    ["RE@"] = "REQ ",
    ["NA@"] = "NACK",
    ["EX@"] = "EXCP",
    ["AB@"] = "ABRT",
    
    -- Header fields
    ["CM@"] = "CMID",
    ["DA@"] = "DATE",
    ["DU@"] = "DUP ",
    ["SV@"] = "SVID",
    ["US@"] = "USEC",
    ["VE@"] = "VER ",
    
    -- Message types
    ["BE@"] = "BEG ",
    ["CH@"] = "CHKD",
    ["TR@"] = "TRAN",
    ["CC@"] = "CCDR",
    ["AT@"] = "ATC ",
    ["IR"] = "IR  ",
    ["SR"] = "SR  ",
    ["CR"] = "CR  ",
    ["RR"] = "RR  ",
    ["NE"] = "NE  ",
    ["WG@"] = "WGR ",
    ["WI"] = "WI  ",
    ["WU"] = "WU  ",
    ["VI"] = "VI  ",
    ["VU"] = "VU  ",
    ["VR"] = "VR  ",
    ["CV@"] = "CVR ",
    ["RV@"] = "RVR ",
    ["DA"] = "DA  ",
    ["IA@"] = "IARR",
    ["SA@"] = "SARR",
    ["CA@"] = "CARR",
    ["RA@"] = "RARR",
    
    -- Body fields
    ["CO@"] = "CODE",
    ["WH@"] = "WHAT",
    ["WA@"] = "WALT",
    ["VC@"] = "VCHR",
    ["VN@"] = "VNUM",
    ["NA@"] = "NAME",
    ["HT@"] = "HTBT",
    ["CL@"] = "CLI ",
    ["AR@"] = "AREF",
    ["AM@"] = "AMNT",
    ["PI"] = "PI  ",
}

-- ================= CONFIGURATION =================

local DEFAULT_PORT = 1700
local ALIGN_SIZE = 4
local EXT_HEADER_BLOCK_ID = 0xFFFE
local NEW_DIRTY_MASK = 0x8001

local NULL_TYPE   = 0x00
local INT_TYPE    = 0x01
local DATE_TYPE   = 0x02
local SYMBOL_TYPE = 0x03
local FLOAT_TYPE  = 0x04
local STRING_TYPE = 0x05
local ARRAY_TYPE  = 0x06
local MAP_TYPE    = 0x07
local RAW_TYPE    = 0x08

-- ================= PROTOCOL FIELDS =================

local f_length      = ProtoField.uint16("fox.length", "Length", base.DEC)
local f_num_items   = ProtoField.uint16("fox.num_items", "Items", base.DEC)
local f_ext_length  = ProtoField.uint32("fox.ext_length", "Extended Length", base.DEC)
local f_ext_items   = ProtoField.uint32("fox.ext_items", "Extended Items", base.DEC)
local f_extended    = ProtoField.bool("fox.extended", "Extended Format")
local f_dirty       = ProtoField.bool("fox.dirty", "Dirty Flag")
local f_typecode    = ProtoField.uint8("fox.typecode", "Type", base.HEX, {
    [0x00]="NULL", [0x01]="INT", [0x02]="DATE", [0x03]="SYMBOL",
    [0x04]="FLOAT", [0x05]="STRING", [0x06]="ARRAY", [0x07]="MAP", [0x08]="RAW"
})

local f_int         = ProtoField.int32("fox.int", "Integer", base.DEC)
local f_float       = ProtoField.double("fox.float", "Float")
local f_string      = ProtoField.string("fox.string", "String")
local f_symbol      = ProtoField.string("fox.symbol", "Symbol")
local f_date        = ProtoField.absolute_time("fox.date", "Date")
local f_raw         = ProtoField.bytes("fox.raw", "Raw Data")

fox_proto.fields = {
    f_length, f_num_items, f_ext_length, f_ext_items,
    f_extended, f_dirty, f_typecode,
    f_int, f_float, f_string, f_symbol, f_date, f_raw
}

-- ================= HELPERS =================

local function align(x)
    return bit.band(x + ALIGN_SIZE - 1, bit.bnot(ALIGN_SIZE - 1))
end

local function is_dirty(x)
    return bit.band(x, NEW_DIRTY_MASK) == NEW_DIRTY_MASK
end

local function decode_symbol(val)
    local c1 = bit.band(bit.rshift(val, 24), 0xFF)
    local c2 = bit.band(bit.rshift(val, 16), 0xFF)
    local c3 = bit.band(bit.rshift(val, 8), 0xFF)
    local c4 = bit.band(val, 0xFF)
    
    local wire_symbol = string.char(c1, c2, c3, c4)
    wire_symbol = wire_symbol:gsub("%z+$", ""):gsub(" +$", "")
    
    return wire_symbol
end

local function expand_symbol(wire_symbol)
    wire_symbol = wire_symbol:gsub("%z+$", ""):gsub(" +$", "")
    local full_name = SYMBOL_MAP[wire_symbol]
    if full_name then
        full_name = full_name:gsub(" +$", "")
        return full_name .. " [" .. wire_symbol .. "]"
    else
        return wire_symbol
    end
end

local function extract_key_parts(key)
    local symbol = bit.band(key, 0xffffe000)
    local typecode = bit.band(bit.rshift(key, 9), 0x0f)
    local offset = bit.lshift(bit.band(key, 0x1ff), 2)
    return symbol, typecode, offset
end

local function extract_array_index(index)
    local typecode = bit.band(bit.rshift(index, 9), 0x0f)
    local offset = bit.lshift(bit.band(index, 0x1ff), 2)
    return typecode, offset
end

-- ================= DISSECTION FUNCTIONS =================

local function dissect_int(tvb, tree, offset)
    tree:add_le(f_int, tvb(offset, 4))
    return 4
end

local function dissect_date(tvb, tree, offset)
    local timestamp = tvb(offset, 4):uint()
    tree:add(f_date, tvb(offset, 4), timestamp)
    return 4
end

local function dissect_symbol(tvb, tree, offset)
    local symbol_val = tvb(offset, 4):uint()
    local wire_symbol = decode_symbol(symbol_val)
    local display_symbol = expand_symbol(wire_symbol)
    
    tree:add(f_symbol, tvb(offset, 4), display_symbol)
    return 4
end

local function dissect_float(tvb, tree, offset)
    tree:add_le(f_float, tvb(offset, 8))
    return 8
end

local function dissect_string(tvb, tree, offset)
    if offset >= tvb:len() then
        return 0
    end
    
    local strlen = tvb(offset, 1):uint()
    local str_offset = 1
    
    if bit.band(strlen, 0x80) ~= 0 then
        if offset + 2 > tvb:len() then
            return 0
        end
        strlen = bit.band(tvb(offset, 2):uint(), 0x7FFF)
        str_offset = 2
    end
    
    local total_len = str_offset + strlen
    local aligned_len = align(total_len)
    
    if offset + total_len > tvb:len() then
        return 0
    end
    
    local str_val = tvb(offset + str_offset, strlen):string()
    tree:add(f_string, tvb(offset, aligned_len), str_val)
    
    return aligned_len
end

local function dissect_raw(tvb, tree, offset)
    if offset + 4 > tvb:len() then
        return 0
    end
    
    local raw_len = tvb(offset, 4):uint()
    local total_len = 4 + raw_len
    local aligned_len = align(total_len)
    
    if offset + total_len > tvb:len() then
        return 0
    end
    
    tree:add(f_raw, tvb(offset + 4, raw_len))
    
    return aligned_len
end

local function dissect_value(tvb, tree, typecode, offset, depth, name)
    if offset >= tvb:len() then
        return 0
    end
    
    local subtree = tree
    if name then
        local wire_name = name:gsub("%z+$", ""):gsub(" +$", "")
        local display_name = expand_symbol(wire_name)
        subtree = tree:add(fox_proto, tvb(offset, 0), display_name)
    end
    
    subtree:add(f_typecode, typecode)
    
    if typecode == NULL_TYPE then
        subtree:append_text(": null")
        return 0
    elseif typecode == INT_TYPE then
        return dissect_int(tvb, subtree, offset)
    elseif typecode == DATE_TYPE then
        return dissect_date(tvb, subtree, offset)
    elseif typecode == SYMBOL_TYPE then
        return dissect_symbol(tvb, subtree, offset)
    elseif typecode == FLOAT_TYPE then
        return dissect_float(tvb, subtree, offset)
    elseif typecode == STRING_TYPE then
        return dissect_string(tvb, subtree, offset)
    elseif typecode == ARRAY_TYPE then
        return dissect_array(tvb, subtree, offset, depth + 1)
    elseif typecode == MAP_TYPE then
        return dissect_map(tvb, subtree, offset, depth + 1)
    elseif typecode == RAW_TYPE then
        return dissect_raw(tvb, subtree, offset)
    else
        subtree:append_text(": Unknown type")
        return 0
    end
end

function dissect_array(tvb, tree, offset, depth)
    if depth > 32 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Array nesting too deep")
        return 0
    end
    
    local start_offset = offset
    local is_extended = false
    local header_offset = 0
    
    if offset + 2 <= tvb:len() then
        local header_id = tvb(offset, 2):uint()
        if header_id == EXT_HEADER_BLOCK_ID then
            is_extended = true
            tree:add(f_extended, true)
            
            if offset + 3 <= tvb:len() then
                local ctrl_len = tvb(offset + 2, 1):uint()
                header_offset = bit.band(ctrl_len, 0x7F) - 1
            end
            offset = offset + 4 + header_offset
        end
    end
    
    if offset + 4 > tvb:len() then
        return 0
    end
    
    local byte_length, num_items
    
    if is_extended then
        if offset + 12 > tvb:len() then
            return 0
        end
        byte_length = tvb(offset, 4):uint()
        num_items = tvb(offset + 8, 4):uint()
        tree:add(f_ext_length, tvb(offset, 4))
        tree:add(f_ext_items, tvb(offset + 8, 4))
        offset = offset + 12
    else
        local ptr_val = tvb(offset, 4):uint()
        
        if is_dirty(ptr_val) then
            tree:add(f_dirty, true)
            tree:append_text(": <Dirty>")
            return 4
        end
        
        byte_length = tvb(offset, 2):uint()
        num_items = tvb(offset + 2, 2):uint()
        tree:add(f_length, tvb(offset, 2))
        tree:add(f_num_items, tvb(offset + 2, 2))
        offset = offset + 4
    end
    
    local items_start = offset
    tree:append_text(string.format(": Array[%d]", num_items))
    
    for i = 0, num_items - 1 do
        if offset + 2 > tvb:len() then
            break
        end
        
        local index_val = tvb(offset, 2):uint()
        local typecode, item_offset = extract_array_index(index_val)
        
        offset = offset + 2
        
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < tvb:len() then
                local item_tree = tree:add(fox_proto, tvb(value_offset, 0), string.format("[%d]", i))
                dissect_value(tvb, item_tree, typecode, value_offset, depth, nil)
            end
        end
    end
    
    return offset - start_offset + (byte_length - (offset - items_start))
end

function dissect_map(tvb, tree, offset, depth)
    if depth > 32 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Map nesting too deep")
        return 0
    end
    
    local start_offset = offset
    local is_extended = false
    local header_offset = 0
    
    if offset + 2 <= tvb:len() then
        local header_id = tvb(offset, 2):uint()
        if header_id == EXT_HEADER_BLOCK_ID then
            is_extended = true
            tree:add(f_extended, true)
            
            if offset + 3 <= tvb:len() then
                local ctrl_len = tvb(offset + 2, 1):uint()
                header_offset = bit.band(ctrl_len, 0x7F) - 1
            end
            offset = offset + 4 + header_offset
        end
    end
    
    if offset + 4 > tvb:len() then
        return 0
    end
    
    local byte_length, num_items
    
    if is_extended then
        if offset + 12 > tvb:len() then
            return 0
        end
        byte_length = tvb(offset, 4):uint()
        num_items = tvb(offset + 8, 4):uint()
        tree:add(f_ext_length, tvb(offset, 4))
        tree:add(f_ext_items, tvb(offset + 8, 4))
        offset = offset + 12
    else
        local ptr_val = tvb(offset, 4):uint()
        
        if is_dirty(ptr_val) then
            tree:add(f_dirty, true)
            tree:append_text(": <Dirty>")
            return 4
        end
        
        byte_length = tvb(offset, 2):uint()
        num_items = tvb(offset + 2, 2):uint()
        tree:add(f_length, tvb(offset, 2))
        tree:add(f_num_items, tvb(offset + 2, 2))
        offset = offset + 4
    end
    
    local items_start = offset
    tree:append_text(string.format(": Map{%d}", num_items))
    
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
                dissect_value(tvb, tree, typecode, value_offset, depth, symbol_str)
            end
        end
    end
    
    return offset - start_offset + (byte_length - (offset - items_start))
end

-- ================= MAIN DISSECTOR =================

function fox_proto.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "FOX"
    
    local subtree = tree:add(fox_proto, tvb(), "FOX Protocol")
    
    local offset = 0
    dissect_map(tvb, subtree, offset, 0)
    
    return tvb:len()
end

-- ================= REGISTRATION =================

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(DEFAULT_PORT, fox_proto)

print("FOX Protocol Dissector Loaded (port " .. DEFAULT_PORT .. ") with full dissection and symbol mapping")