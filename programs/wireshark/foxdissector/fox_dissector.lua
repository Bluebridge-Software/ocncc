-- ============================================================
-- Oracle FOX Protocol Dissector with Symbol Mapping
-- Converted from C++/C Wireshark plugin (escherBridge.cc/fox.c)
-- 
-- This is the FOX-SPECIFIC dissector (port 1700)
-- Now includes symbol mapping for human-friendly display
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
    ["AC@"] = "ACK ",  -- Note: same as ACTN
    ["NA@"] = "NACK",
    ["EX@"] = "EXCP",
    
    -- Header fields
    ["CM@"] = "CMID",
    ["DA@"] = "DATE",
    ["DU@"] = "DUP ",
    ["SV@"] = "SVID",
    ["US@"] = "USEC",
    ["VE@"] = "VER ",
    
    -- Body fields
    ["CL@"] = "CLI ",
    ["AR@"] = "AREF",
    ["WA@"] = "WALT",
    
    -- Message types
    ["IR"] = "IR  ",
    ["SR"] = "SR  ",
    ["CR"] = "CR  ",
    ["RR"] = "RR  ",
    ["WG@"] = "WGR ",
    ["WI"] = "WI  ",
    ["WU"] = "WU  ",
    ["VI"] = "VI  ",
    ["VU"] = "VU  ",
    ["VR"] = "VR  ",
    ["CV@"] = "CVR ",
    ["RV@"] = "RVR ",
}

-- ================= CONFIGURATION =================

local DEFAULT_PORT = 1700
local ALIGN_SIZE = 4
local EXT_HEADER_BLOCK_ID = 0xFFFE
local NEW_DIRTY_MASK = 0x8001

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

-- ================= PROTOCOL FIELDS =================

local f_action      = ProtoField.string("fox.action", "Action")
local f_type        = ProtoField.string("fox.type", "Type")
local f_head_cmid   = ProtoField.int32("fox.head.cmid", "Request Number (CMID)", base.DEC)
local f_head_date   = ProtoField.absolute_time("fox.head.date", "Call Date")
local f_head_dup    = ProtoField.bool("fox.head.dup", "Duplicate Flag")
local f_head_svid   = ProtoField.int32("fox.head.svid", "BE Server ID (SVID)", base.DEC)
local f_head_usec   = ProtoField.int32("fox.head.usec", "Micro Seconds", base.DEC)
local f_head_ver    = ProtoField.int32("fox.head.ver", "Protocol Version", base.DEC)
local f_body_cli    = ProtoField.string("fox.body.cli", "Calling Line Identifier (CLI)")
local f_body_aref   = ProtoField.string("fox.body.aref", "Account Reference (AREF)")
local f_body_full   = ProtoField.string("fox.body.full", "Body")

fox_proto.fields = {
    f_action, f_type,
    f_head_cmid, f_head_date, f_head_dup, f_head_svid, f_head_usec, f_head_ver,
    f_body_cli, f_body_aref, f_body_full
}

-- ================= HELPERS =================

local function decode_symbol(val)
    local c1 = bit.band(bit.rshift(val, 24), 0xFF)
    local c2 = bit.band(bit.rshift(val, 16), 0xFF)
    local c3 = bit.band(bit.rshift(val, 8), 0xFF)
    local c4 = bit.band(val, 0xFF)
    
    local function to_char(b)
        if b >= 32 and b < 127 then
            return string.char(b)
        else
            return ""
        end
    end
    
    return to_char(c1) .. to_char(c2) .. to_char(c3) .. to_char(c4)
end

local function expand_symbol(wire_symbol)
    wire_symbol = wire_symbol:gsub("%z+$", ""):gsub(" +$", "")
    local full_name = SYMBOL_MAP[wire_symbol]
    if full_name then
        return full_name:gsub(" +$", "")
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

-- ================= DISSECTION FUNCTIONS =================

local function dissect_fox_map(tvb, tree, offset)
    if offset + 4 > tvb:len() then
        return 0
    end
    
    -- Read map header
    local byte_length = tvb(offset, 2):uint()
    local num_items = tvb(offset + 2, 2):uint()
    offset = offset + 4
    
    local items_start = offset
    
    -- Variables to extract
    local action_str = nil
    local type_str = nil
    
    -- Read all keys first
    for i = 0, num_items - 1 do
        if offset + 4 > tvb:len() then
            break
        end
        
        local key_val = tvb(offset, 4):uint()
        local symbol, typecode, item_offset = extract_key_parts(key_val)
        local symbol_str = decode_symbol(symbol)
        local wire_symbol = symbol_str:gsub("%z+$", ""):gsub(" +$", "")
        
        offset = offset + 4
        
        -- Extract ACTN and TYPE for Info column
        if item_offset > 0 and typecode == SYMBOL_TYPE then
            local value_offset = items_start + item_offset
            if value_offset + 4 <= tvb:len() then
                local val_symbol = tvb(value_offset, 4):uint()
                local val_str = decode_symbol(val_symbol)
                local expanded_key = expand_symbol(wire_symbol)
                
                if expanded_key == "ACTN" or wire_symbol == "AC@" then
                    action_str = expand_symbol(val_str)
                elseif expanded_key == "TYPE" or wire_symbol == "TY@" then
                    type_str = expand_symbol(val_str)
                end
            end
        end
    end
    
    -- Set Info column
    if action_str and type_str then
        tree.text = string.format("FOX: %s %s", type_str, action_str)
    end
    
    return byte_length
end

-- ================= MAIN DISSECTOR =================

function fox_proto.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "FOX"
    
    local subtree = tree:add(fox_proto, tvb(), "FOX Protocol")
    
    dissect_fox_map(tvb, subtree, 0)
    
    return tvb:len()
end

-- ================= REGISTRATION =================

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(DEFAULT_PORT, fox_proto)

print("FOX Protocol Dissector Loaded (port " .. DEFAULT_PORT .. ") with symbol mapping enabled")
