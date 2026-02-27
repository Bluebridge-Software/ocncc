-- ============================================================
-- Oracle ESCHER Protocol Dissector
-- Converted from C++/C Wireshark plugin (decodeEscher.cc/escher.c)
-- 
-- This is the GENERIC ESCHER dissector (port 1500)
-- Separate from FOX dissector (port 1700)
-- 
-- Supports both SPARC (big-endian) and x86 Linux (little-endian)
-- ============================================================

local escher_proto = Proto("ESCHER", "ESCHER Protocol")

-- ================= CONFIGURATION =================

local ALIGN_SIZE = 4
local EXT_HEADER_BLOCK_ID = 0xFFFE
local NEW_DIRTY_MASK = 0x8001
local DEFAULT_PORT = 1500  -- From C++: const int DEFAULT_PORT_NUMBER = 1500

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

-- ================= PROTOCOL FIELDS =================

-- Core fields
local f_length      = ProtoField.uint16("escher.length", "Length", base.DEC)
local f_num_items   = ProtoField.uint16("escher.num_items", "Items", base.DEC)
local f_ext_length  = ProtoField.uint32("escher.ext_length", "Extended Length", base.DEC)
local f_ext_items   = ProtoField.uint32("escher.ext_items", "Extended Items", base.DEC)
local f_extended    = ProtoField.bool("escher.extended", "Extended Format")
local f_dirty       = ProtoField.bool("escher.dirty", "Dirty Flag")
local f_typecode    = ProtoField.uint8("escher.typecode", "Type", base.HEX, {
    [0x00]="NULL", [0x01]="INT", [0x02]="DATE", [0x03]="SYMBOL",
    [0x04]="FLOAT", [0x05]="STRING", [0x06]="ARRAY", [0x07]="MAP", [0x08]="RAW"
})

-- Value fields
local f_int         = ProtoField.int32("escher.int", "Integer", base.DEC)
local f_float       = ProtoField.double("escher.float", "Float")
local f_string      = ProtoField.string("escher.string", "String")
local f_symbol      = ProtoField.string("escher.symbol", "Symbol")
local f_date        = ProtoField.absolute_time("escher.date", "Date")
local f_raw         = ProtoField.bytes("escher.raw", "Raw Data")

escher_proto.fields = {
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

-- Decode symbol (4 bytes to ASCII)
local function decode_symbol(val)
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

-- Extract array index components  
local function extract_array_index(index)
    local typecode = bit.band(bit.rshift(index, 9), 0x0f)
    local offset = bit.lshift(bit.band(index, 0x1ff), 2)
    return typecode, offset
end

-- Get message length
local function get_message_length(buffer, offset)
    if buffer:len() < offset + 4 then
        return 0
    end
    
    -- Check for extended header
    local header_id = buffer(offset, 2):uint()
    if header_id == EXT_HEADER_BLOCK_ID then
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
        return buffer(offset, 2):uint()
    end
end

-- ================= VALUE PROCESSING =================

local function process_value(buffer, offset, tree, typecode, label, name_prefix)
    local bytes_consumed = 0
    local value_str = ""
    
    if typecode == NULL_TYPE then
        value_str = "NULL"
        if tree then
            tree:add(buffer(offset, 0), string.format("%s: NULL", label))
        end
        bytes_consumed = 0
        
    elseif typecode == INT_TYPE then
        if offset + 4 > buffer:len() then return 0, "" end
        local value = buffer(offset, 4):int()
        value_str = tostring(value)
        if tree then
            tree:add(f_int, buffer(offset, 4), value):set_text(string.format("%s: %d", label, value))
        end
        bytes_consumed = 4
        
    elseif typecode == FLOAT_TYPE then
        if offset + 8 > buffer:len() then return 0, "" end
        local value = buffer(offset, 8):le_float64()
        value_str = string.format("%.6f", value)
        if tree then
            tree:add(f_float, buffer(offset, 8), value):set_text(string.format("%s: %s", label, value_str))
        end
        bytes_consumed = 8
        
    elseif typecode == STRING_TYPE then
        if offset + 1 > buffer:len() then return 0, "" end
        local strlen = buffer(offset, 1):uint()
        local str_offset = 1
        
        -- Handle long strings (>= 128 bytes)
        if bit.band(strlen, 0x80) ~= 0 then
            if offset + 2 > buffer:len() then return 0, "" end
            strlen = bit.band(buffer(offset, 2):uint(), 0x7fff)
            str_offset = 2
        end
        
        if strlen > 0 and (offset + str_offset + strlen) <= buffer:len() then
            value_str = buffer(offset + str_offset, strlen):string()
            if tree then
                tree:add(f_string, buffer(offset + str_offset, strlen), value_str):set_text(string.format("%s: \"%s\"", label, value_str))
            end
        end
        
        bytes_consumed = align(str_offset + strlen)
        
    elseif typecode == DATE_TYPE then
        if offset + 4 > buffer:len() then return 0, "" end
        local timestamp = buffer(offset, 4):uint()
        value_str = os.date("%Y-%m-%d %H:%M:%S", timestamp)
        if tree then
            tree:add(f_date, buffer(offset, 4), timestamp):set_text(string.format("%s: %s", label, value_str))
        end
        bytes_consumed = 4
        
    elseif typecode == SYMBOL_TYPE then
        if offset + 4 > buffer:len() then return 0, "" end
        local symbol_val = buffer(offset, 4):uint()
        value_str = decode_symbol(symbol_val)
        if tree then
            tree:add(f_symbol, buffer(offset, 4), value_str):set_text(string.format("%s: %s", label, value_str))
        end
        bytes_consumed = 4
        
    elseif typecode == RAW_TYPE then
        if offset + 4 > buffer:len() then return 0, "" end
        local raw_len = buffer(offset, 4):uint()
        value_str = string.format("[Raw %d bytes]", raw_len)
        if tree and raw_len > 0 and (offset + 4 + raw_len) <= buffer:len() then
            tree:add(f_raw, buffer(offset + 4, raw_len)):set_text(string.format("%s: [Raw %d bytes]", label, raw_len))
        end
        bytes_consumed = align(4 + raw_len)
        
    elseif typecode == ARRAY_TYPE then
        local array_bytes, array_str = dissect_array(buffer, offset, tree, label, name_prefix)
        bytes_consumed = array_bytes
        value_str = array_str
        
    elseif typecode == MAP_TYPE then
        local map_bytes, map_str = dissect_map(buffer, offset, tree, label, name_prefix)
        bytes_consumed = map_bytes
        value_str = map_str
    end
    
    return bytes_consumed, value_str
end

-- ================= ARRAY DISSECTION =================

function dissect_array(buffer, offset, tree, label, name_prefix)
    if offset + 4 > buffer:len() then return 0, "[]" end
    
    local start_offset = offset
    local array_tree = tree
    if tree then
        array_tree = tree:add(buffer(offset), string.format("%s: Array", label))
    end
    
    -- Check for extended header
    local is_extended = false
    local header_offset = 0
    
    if offset + 2 <= buffer:len() then
        local header_id = buffer(offset, 2):uint()
        if header_id == EXT_HEADER_BLOCK_ID then
            is_extended = true
            if array_tree then
                array_tree:add(f_extended, buffer(offset, 2), true)
            end
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
        if array_tree then
            array_tree:add(f_ext_length, buffer(offset, 4), byte_length)
            array_tree:add(f_ext_items, buffer(offset + 8, 4), num_items)
        end
        offset = offset + 12
    elseif offset + 4 <= buffer:len() then
        local ptr_val = buffer(offset, 4):uint()
        
        if is_dirty(ptr_val) then
            if array_tree then
                array_tree:add(f_dirty, buffer(offset, 4), true)
            end
            return 4, "[Dirty]"
        end
        
        byte_length = buffer(offset, 2):uint()
        num_items = buffer(offset + 2, 2):uint()
        if array_tree then
            array_tree:add(f_length, buffer(offset, 2), byte_length)
            array_tree:add(f_num_items, buffer(offset + 2, 2), num_items)
        end
        offset = offset + 4
    else
        return 4, "[]"
    end
    
    local items_start = offset
    
    -- Process array elements
    for i = 0, num_items - 1 do
        if offset + 2 > buffer:len() then break end
        
        local index_val = buffer(offset, 2):uint()
        local typecode, item_offset = extract_array_index(index_val)
        
        offset = offset + 2
        
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < buffer:len() then
                local element_label = string.format("[%d]", i)
                local new_prefix = name_prefix .. ".array"
                process_value(buffer, value_offset, array_tree, typecode, element_label, new_prefix)
            end
        end
    end
    
    return byte_length, string.format("[%d items]", num_items)
end

-- ================= MAP DISSECTION =================

function dissect_map(buffer, offset, tree, label, name_prefix)
    if offset + 4 > buffer:len() then return 0, "{}" end
    
    local start_offset = offset
    local map_tree = tree
    if tree then
        if label and label ~= "" then
            map_tree = tree:add(buffer(offset), string.format("%s: Map", label))
        else
            map_tree = tree:add(buffer(offset), "Map")
        end
    end
    
    -- Check for extended header
    local is_extended = false
    local header_offset = 0
    
    if offset + 2 <= buffer:len() then
        local header_id = buffer(offset, 2):uint()
        if header_id == EXT_HEADER_BLOCK_ID then
            is_extended = true
            if map_tree then
                map_tree:add(f_extended, buffer(offset, 2), true)
            end
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
        if map_tree then
            map_tree:add(f_ext_length, buffer(offset, 4), byte_length)
            map_tree:add(f_ext_items, buffer(offset + 8, 4), num_items)
        end
        offset = offset + 12
    elseif offset + 4 <= buffer:len() then
        local ptr_val = buffer(offset, 4):uint()
        
        if is_dirty(ptr_val) then
            if map_tree then
                map_tree:add(f_dirty, buffer(offset, 4), true)
            end
            return 4, "{Dirty}"
        end
        
        byte_length = buffer(offset, 2):uint()
        num_items = buffer(offset + 2, 2):uint()
        if map_tree then
            map_tree:add(f_length, buffer(offset, 2), byte_length)
            map_tree:add(f_num_items, buffer(offset + 2, 2), num_items)
        end
        offset = offset + 4
    else
        return 4, "{}"
    end
    
    local items_start = offset
    
    -- Process map entries
    for i = 0, num_items - 1 do
        if offset + 4 > buffer:len() then break end
        
        local key_val = buffer(offset, 4):uint()
        local symbol, typecode, item_offset = extract_key_parts(key_val)
        local symbol_str = decode_symbol(symbol)
        
        offset = offset + 4
        
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < buffer:len() then
                -- Create hierarchical name (mimics C++ namePrefix)
                local new_prefix = name_prefix
                if new_prefix ~= "" then
                    new_prefix = new_prefix .. "." .. symbol_str:lower()
                else
                    new_prefix = "escher." .. symbol_str:lower()
                end
                
                process_value(buffer, value_offset, map_tree, typecode, symbol_str, new_prefix)
            end
        end
    end
    
    return byte_length, string.format("{%d items}", num_items)
end

-- ================= MAIN DISSECTOR =================

function escher_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end
    
    pinfo.cols.protocol = "ESCHER"
    
    -- Get message length
    local msg_len = get_message_length(buffer, 0)
    if msg_len == 0 or msg_len > length then
        return 0
    end
    
    local subtree = tree:add(escher_proto, buffer(), "ESCHER Protocol")
    
    -- Decode the message as a Map (top level is always a Map)
    local bytes_read, msg_desc = dissect_map(buffer, 0, subtree, "", "")
    
    -- Set info column with message description
    pinfo.cols.info = string.format("ESCHER Message (%d bytes)", msg_len)
    
    return bytes_read
end

-- ================= PDU LENGTH FUNCTION =================

local function get_escher_pdu_len(buffer, pinfo, offset)
    local len = get_message_length(buffer, offset)
    if len == 0 then
        return 0  -- Need more data
    end
    return len
end

-- ================= TCP DISSECTOR WRAPPER =================

local function escher_tcp_dissector(buffer, pinfo, tree)
    -- Use TCP PDU dissection for message reassembly
    -- Minimum length 8 bytes (smallest valid map)
    dissect_tcp_pdus(buffer, tree, 8, get_escher_pdu_len, escher_proto.dissector)
end

-- ================= REGISTRATION =================

local tcp_port = DissectorTable.get("tcp.port")
local udp_port = DissectorTable.get("udp.port")

-- Register on default port 1500 (from C++: DEFAULT_PORT_NUMBER = 1500)
tcp_port:add(DEFAULT_PORT, escher_proto)
udp_port:add(DEFAULT_PORT, escher_proto)

-- Also register on common test ports
tcp_port:add(5000, escher_proto)
tcp_port:add(5001, escher_proto)
udp_port:add(5000, escher_proto)
udp_port:add(5001, escher_proto)

print("ESCHER Protocol Dissector Loaded (port " .. DEFAULT_PORT .. ", generic Escher)")