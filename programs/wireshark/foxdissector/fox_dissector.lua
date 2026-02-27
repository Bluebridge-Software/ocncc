-- ============================================================
-- Oracle ESCHER/FOX Protocol Dissector
-- Converted from C++/C Wireshark plugin (escherBridge.cc/fox.c)
-- Supports both SPARC (big-endian) and x86 Linux (little-endian)
-- ============================================================

local fox_proto = Proto("FOX", "FOX Protocol")

-- ================= CONFIGURATION =================

local ALIGN_SIZE = 4
local EXT_HEADER_BLOCK_ID = 0xFFFE
local NEW_DIRTY_MASK = 0x8001
local DEFAULT_PORT = 1700  -- From original: DEFAULT_PORT_NUMBER = 1700

-- ================= TYPE CODES =================

local NULL_TYPE   = 0x00
local INT_TYPE    = 0x01
local DATE_TYPE   = 0x02
local SYMBOL_TYPE = 0x03
local FLOAT_TYPE  = 0x04
local STRING_TYPE = 0x05
local ARRAY_TYPE  = 0x06
local MAP_TYPE    = 0x07
local RAW_TYPE    = 0x08

-- ================= FIELD DEFINITIONS (from C++) =================

local f_action      = ProtoField.string("fox.action", "FOX Action")
local f_type        = ProtoField.string("fox.type", "FOX Type")
local f_head_cmid   = ProtoField.string("fox.head.cmid", "Request Number(CMID)")
local f_head_date   = ProtoField.string("fox.head.date", "Call Date")
local f_head_dup    = ProtoField.string("fox.head.dup", "Duplicate Flag")
local f_head_svid   = ProtoField.string("fox.head.svid", "BE Server ID")
local f_head_usec   = ProtoField.string("fox.head.usec", "Micro Seconds")
local f_head_ver    = ProtoField.string("fox.head.ver", "Protocol Version")
local f_body_cli    = ProtoField.string("fox.body.cli", "Calling Line Identifier")
local f_body_aref   = ProtoField.string("fox.body.aref", "Account Reference")
local f_body_full   = ProtoField.string("fox.body.full", "Body")

-- Additional fields for structure
local f_length      = ProtoField.uint16("fox.length", "Length", base.DEC)
local f_num_items   = ProtoField.uint16("fox.num_items", "Number of Items", base.DEC)
local f_ext_length  = ProtoField.uint32("fox.ext_length", "Extended Length", base.DEC)
local f_ext_items   = ProtoField.uint32("fox.ext_items", "Extended Items", base.DEC)
local f_extended    = ProtoField.bool("fox.extended", "Extended Format")
local f_dirty       = ProtoField.bool("fox.dirty", "Dirty Flag")
local f_typecode    = ProtoField.uint8("fox.typecode", "Type Code", base.HEX, {
    [0x00]="NULL", [0x01]="INT", [0x02]="DATE", [0x03]="SYMBOL",
    [0x04]="FLOAT", [0x05]="STRING", [0x06]="ARRAY", [0x07]="MAP", [0x08]="RAW"
})

local f_int         = ProtoField.int32("fox.int", "Integer", base.DEC)
local f_symbol_val  = ProtoField.string("fox.symbol", "Symbol")
local f_string_val  = ProtoField.string("fox.string", "String")

fox_proto.fields = {
    f_action, f_type, f_head_cmid, f_head_date, f_head_dup,
    f_head_svid, f_head_usec, f_head_ver, f_body_cli, f_body_aref, f_body_full,
    f_length, f_num_items, f_ext_length, f_ext_items,
    f_extended, f_dirty, f_typecode, f_int, f_symbol_val, f_string_val
}

-- ================= HELPERS =================

-- Add to dissector
local function debug_print(msg)
    print("FOX: " .. msg)
end

local function align(x)
    return bit.band(x + ALIGN_SIZE - 1, bit.bnot(ALIGN_SIZE - 1))
end

local function is_dirty(x)
    return bit.band(x, NEW_DIRTY_MASK) == NEW_DIRTY_MASK
end

-- Decode a 4-byte symbol to string (handles both endianness)
local function decode_symbol(val)
    -- On network (big-endian), symbol "ACTN" = [41][43][54][4E]
    -- When read with :uint(), we get the value in host order
    -- We extract bytes MSB->LSB and convert to chars
    local c1 = bit.band(bit.rshift(val, 24), 0xFF)
    local c2 = bit.band(bit.rshift(val, 16), 0xFF)
    local c3 = bit.band(bit.rshift(val, 8), 0xFF)
    local c4 = bit.band(val, 0xFF)
    
    local function to_char(b)
        if b >= 32 and b < 127 then
            return string.char(b)
        else
            return string.format("\\x%02X", b)
        end
    end
    
    return to_char(c1) .. to_char(c2) .. to_char(c3) .. to_char(c4)
end

-- Extract map key components
local function extract_key_parts(key)
    local symbol = bit.band(key, 0xffffe000)
    local typecode = bit.band(bit.rshift(key, 9), 0x0f)
    local offset = bit.lshift(bit.band(key, 0x1ff), 2)
    return symbol, typecode, offset
end

-- Get message length (mimics ConstMessage::getMessageLength)
local function get_message_length(buffer, offset)
    if buffer:len() < offset + 4 then
        return 0  -- Not enough data
    end
    
    local len = buffer(offset, 2):uint()
    debug_print(string.format("Message length: %d", len))
    -- Check for extended header
    local header_id = buffer(offset, 2):uint()
    if header_id == EXT_HEADER_BLOCK_ID then
        -- Extended format
        if buffer:len() < offset + 8 then
            return 0
        end
        local ctrl_len = buffer(offset + 2, 1):uint()
        local header_adj = bit.band(ctrl_len, 0x7F) - 1
        if buffer:len() < offset + 4 + header_adj + 4 then
            return 0
        end
        return buffer(offset + 4 + header_adj, 4):uint()
    else
        -- Standard format - first 2 bytes are length
        return buffer(offset, 2):uint()
    end
end

-- ================= VALUE DISSECTION =================

local function dissect_value(buffer, offset, tree, typecode)
    local bytes_consumed = 0
    local value_str = ""
    
    if typecode == NULL_TYPE then
        value_str = "NULL"
        bytes_consumed = 0
        
    elseif typecode == INT_TYPE then
        if offset + 4 > buffer:len() then return 0, "" end
        local value = buffer(offset, 4):int()
        tree:add(f_int, buffer(offset, 4), value)
        value_str = tostring(value)
        bytes_consumed = 4
        
    elseif typecode == FLOAT_TYPE then
        if offset + 8 > buffer:len() then return 0, "" end
        local bytes = buffer(offset, 8):bytes()
        local value = bytes:le_uint64():tonumber()
        value_str = string.format("%.6f", value)
        bytes_consumed = 8
        
    elseif typecode == STRING_TYPE then
        if offset + 1 > buffer:len() then return 0, "" end
        local strlen = buffer(offset, 1):uint()
        local str_offset = 1
        
        if bit.band(strlen, 0x80) ~= 0 then
            if offset + 2 > buffer:len() then return 0, "" end
            strlen = bit.band(buffer(offset, 2):uint(), 0x7fff)
            str_offset = 2
        end
        
        if strlen > 0 and (offset + str_offset + strlen) <= buffer:len() then
            value_str = buffer(offset + str_offset, strlen):string()
            tree:add(f_string_val, buffer(offset + str_offset, strlen), value_str)
        end
        
        bytes_consumed = align(str_offset + strlen)
        
    elseif typecode == DATE_TYPE then
        if offset + 4 > buffer:len() then return 0, "" end
        local timestamp = buffer(offset, 4):uint()
        value_str = os.date("%Y-%m-%d %H:%M:%S", timestamp)
        bytes_consumed = 4
        
    elseif typecode == SYMBOL_TYPE then
        if offset + 4 > buffer:len() then return 0, "" end
        local symbol_val = buffer(offset, 4):uint()
        value_str = decode_symbol(symbol_val)
        tree:add(f_symbol_val, buffer(offset, 4), value_str)
        bytes_consumed = 4
        
    elseif typecode == RAW_TYPE then
        if offset + 4 > buffer:len() then return 0, "" end
        local raw_len = buffer(offset, 4):uint()
        value_str = string.format("[Raw %d bytes]", raw_len)
        bytes_consumed = align(4 + raw_len)
        
    elseif typecode == ARRAY_TYPE then
        local array_bytes, array_str = dissect_array(buffer, offset, tree)
        bytes_consumed = array_bytes
        value_str = array_str
        
    elseif typecode == MAP_TYPE then
        local map_bytes, map_str = dissect_map(buffer, offset, tree)
        bytes_consumed = map_bytes
        value_str = map_str
    end
    
    return bytes_consumed, value_str
end

-- ================= ARRAY DISSECTION =================

function dissect_array(buffer, offset, tree)
    if offset + 4 > buffer:len() then return 0, "" end
    
    local array_tree = tree:add(buffer(offset), "Array")
    local values = {}
    
    -- Check for extended header
    local is_extended = false
    local header_offset = 0
    
    if offset + 2 <= buffer:len() then
        local header_id = buffer(offset, 2):uint()
        if header_id == EXT_HEADER_BLOCK_ID then
            is_extended = true
            array_tree:add(f_extended, buffer(offset, 2), true)
            if offset + 3 <= buffer:len() then
                header_offset = buffer(offset + 2, 1):uint() - 1
            end
            offset = offset + 4 + header_offset
        end
    end
    
    if offset + 4 > buffer:len() then return 4, "[]" end
    
    local num_items, byte_length
    
    if is_extended and offset + 12 <= buffer:len() then
        byte_length = buffer(offset, 4):uint()
        num_items = buffer(offset + 8, 4):uint()
        array_tree:add(f_ext_length, buffer(offset, 4), byte_length)
        array_tree:add(f_ext_items, buffer(offset + 8, 4), num_items)
        offset = offset + 12
    elseif offset + 4 <= buffer:len() then
        local ptr_val = buffer(offset, 4):uint()
        
        if is_dirty(ptr_val) then
            array_tree:add(f_dirty, buffer(offset, 4), true)
            return 4, "[Dirty]"
        end
        
        byte_length = buffer(offset, 2):uint()
        num_items = buffer(offset + 2, 2):uint()
        array_tree:add(f_length, buffer(offset, 2), byte_length)
        array_tree:add(f_num_items, buffer(offset + 2, 2), num_items)
        offset = offset + 4
    else
        return 4, "[]"
    end
    
    local items_start = offset
    
    for i = 0, num_items - 1 do
        if offset + 2 > buffer:len() then break end
        
        local entry_tree = array_tree:add(buffer(offset), string.format("[%d]", i))
        local index_val = buffer(offset, 2):uint()
        
        local typecode = bit.band(bit.rshift(index_val, 9), 0x0f)
        local item_offset = bit.lshift(bit.band(index_val, 0x1ff), 2)
        
        entry_tree:add(f_typecode, buffer(offset, 2), typecode)
        offset = offset + 2
        
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < buffer:len() then
                local _, val_str = dissect_value(buffer, value_offset, entry_tree, typecode)
                table.insert(values, val_str)
            end
        end
    end
    
    local array_str = "[" .. table.concat(values, ", ") .. "]"
    return byte_length, array_str
end

-- ================= MAP DISSECTION =================

function dissect_map(buffer, offset, tree)
    if offset + 4 > buffer:len() then return 0, "{}" end
    
    local map_tree = tree:add(buffer(offset), "Map")
    local entries = {}
    
    -- Check for extended header
    local is_extended = false
    local header_offset = 0
    
    if offset + 2 <= buffer:len() then
        local header_id = buffer(offset, 2):uint()
        if header_id == EXT_HEADER_BLOCK_ID then
            is_extended = true
            map_tree:add(f_extended, buffer(offset, 2), true)
            if offset + 3 <= buffer:len() then
                header_offset = buffer(offset + 2, 1):uint() - 1
            end
            offset = offset + 4 + header_offset
        end
    end
    
    if offset + 4 > buffer:len() then return 4, "{}" end
    
    local num_items, byte_length
    
    if is_extended and offset + 12 <= buffer:len() then
        byte_length = buffer(offset, 4):uint()
        num_items = buffer(offset + 8, 4):uint()
        map_tree:add(f_ext_length, buffer(offset, 4), byte_length)
        map_tree:add(f_ext_items, buffer(offset + 8, 4), num_items)
        offset = offset + 12
    elseif offset + 4 <= buffer:len() then
        local ptr_val = buffer(offset, 4):uint()
        
        if is_dirty(ptr_val) then
            map_tree:add(f_dirty, buffer(offset, 4), true)
            return 4, "{Dirty}"
        end
        
        byte_length = buffer(offset, 2):uint()
        num_items = buffer(offset + 2, 2):uint()
        map_tree:add(f_length, buffer(offset, 2), byte_length)
        map_tree:add(f_num_items, buffer(offset + 2, 2), num_items)
        offset = offset + 4
    else
        return 4, "{}"
    end
    
    local items_start = offset
    
    for i = 0, num_items - 1 do
        if offset + 4 > buffer:len() then break end
        
        local key_val = buffer(offset, 4):uint()
        local symbol, typecode, item_offset = extract_key_parts(key_val)
        local symbol_str = decode_symbol(symbol)
        
        local entry_tree = map_tree:add(buffer(offset), symbol_str)
        entry_tree:add(f_typecode, buffer(offset, 4), typecode)
        
        offset = offset + 4
        
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < buffer:len() then
                local _, val_str = dissect_value(buffer, value_offset, entry_tree, typecode)
                table.insert(entries, symbol_str .. "=" .. val_str)
            end
        end
    end
    
    local map_str = "{" .. table.concat(entries, ", ") .. "}"
    return byte_length, map_str
end

-- ================= MAIN DISSECTOR (matches C++ dissect_fox_msg) =================

function fox_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end
    
    pinfo.cols.protocol = "FOX"
    
    -- Get message length (mimics getMessageLength from C++)
    local msg_len = get_message_length(buffer, 0)
    if msg_len == 0 or msg_len > length then
        return 0  -- Not enough data or invalid
    end
    
    local subtree = tree:add(fox_proto, buffer(), "FOX Protocol")
    
    -- Decode the message as a Map (top level is always a Map)
    local bytes_read, msg_desc = dissect_map(buffer, 0, subtree)
    
    -- Extract key fields (mimics C++ code extracting ACTN, TYPE, HEAD, BODY)
    -- We'll do a simple parse to extract these for display
    local offset = 0
    
    -- Skip extended header if present
    if buffer:len() >= 2 and buffer(0, 2):uint() == EXT_HEADER_BLOCK_ID then
        offset = 4
        if buffer:len() >= 3 then
            offset = offset + buffer(2, 1):uint() - 1
        end
    end
    
    -- Read map header
    if buffer:len() >= offset + 4 then
        local ptr_val = buffer(offset, 4):uint()
        if not is_dirty(ptr_val) then
            local byte_length = buffer(offset, 2):uint()
            local num_items = buffer(offset + 2, 2):uint()
            offset = offset + 4
            
            local items_start = offset
            local action_val = nil
            local type_val = nil
            
            -- Parse first few entries to find ACTN and TYPE
            for i = 0, math.min(num_items - 1, 10) do
                if offset + 4 <= buffer:len() then
                    local key_val = buffer(offset, 4):uint()
                    local symbol, typecode, item_offset = extract_key_parts(key_val)
                    local symbol_str = decode_symbol(symbol)
                    
                    offset = offset + 4
                    
                    if symbol_str == "ACTN" and typecode == SYMBOL_TYPE then
                        if items_start + item_offset + 4 <= buffer:len() then
                            action_val = decode_symbol(buffer(items_start + item_offset, 4):uint())
                            subtree:add(f_action, buffer(items_start + item_offset, 4), action_val)
                        end
                    elseif symbol_str == "TYPE" and typecode == SYMBOL_TYPE then
                        if items_start + item_offset + 4 <= buffer:len() then
                            type_val = decode_symbol(buffer(items_start + item_offset, 4):uint())
                            subtree:add(f_type, buffer(items_start + item_offset, 4), type_val)
                        end
                    end
                end
            end
            
            -- Set info column
            local info = "FOX"
            if type_val then
                info = info .. " " .. type_val
            end
            if action_val then
                info = info .. " " .. action_val
            end
            pinfo.cols.info = info
        end
    end
    
    return bytes_read
end

-- ================= PDU LENGTH FUNCTION =================

-- This function tells Wireshark how to determine message boundaries
-- (mimics getFoxMessageLength from C++)
local function get_fox_pdu_len(buffer, pinfo, offset)
    local len = get_message_length(buffer, offset)
    if len == 0 then
        return 0  -- Need more data
    end
    return len
end

-- ================= REGISTRATION =================

-- Register as TCP protocol with reassembly support
local function fox_proto_dissector(buffer, pinfo, tree)
    -- Use TCP PDU dissection for message reassembly
    -- Minimum length 28 (heartbeat messages from C++ code)
    dissect_tcp_pdus(buffer, tree, 28, get_fox_pdu_len, fox_proto.dissector)
end

-- Register the dissector
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(DEFAULT_PORT, fox_proto)  -- Default port 1700
tcp_port:add(5000, fox_proto)  -- Common test port
tcp_port:add(5001, fox_proto)  -- Common test port

print("FOX Protocol Dissector Loaded (port " .. DEFAULT_PORT .. ")")