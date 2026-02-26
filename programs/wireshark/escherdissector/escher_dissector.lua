-- Escher Protocol Dissector for Wireshark
-- Oracle Communications Network Charging and Control (OCNCC)
-- Eserv Structured Communications Hierarchical Encoding Rules (ESCHER)
--
-- This dissector decodes binary Escher messages used in OCNCC platform
-- Based on the cmnEscher implementation

-- Create the protocol
local escher_proto = Proto("ESCHER", "Oracle ESCHER Protocol")

-- Define protocol fields
local f_length = ProtoField.uint16("escher.length", "Message Length", base.DEC)
local f_num_items = ProtoField.uint16("escher.num_items", "Number of Items", base.DEC)
local f_extended_header = ProtoField.bool("escher.extended", "Extended Format")
local f_ext_header_id = ProtoField.uint16("escher.ext_header_id", "Extended Header ID", base.HEX)
local f_ext_length = ProtoField.uint32("escher.ext_length", "Extended Length", base.DEC)
local f_ext_num_items = ProtoField.uint32("escher.ext_num_items", "Extended Number of Items", base.DEC)

-- Type code fields
local f_type = ProtoField.uint8("escher.type", "Type Code", base.HEX, {
    [0x00] = "NULL_TYPE",
    [0x01] = "INT_TYPE", 
    [0x02] = "DATE_TYPE",
    [0x03] = "SYMBOL_TYPE",
    [0x04] = "FLOAT_TYPE",
    [0x05] = "STRING_TYPE",
    [0x06] = "ARRAY_TYPE",
    [0x07] = "MAP_TYPE",
    [0x08] = "RAW_TYPE"
})

-- Value fields
local f_null_value = ProtoField.none("escher.null", "NULL Value")
local f_int_value = ProtoField.int32("escher.int", "Integer Value", base.DEC)
local f_float_value = ProtoField.double("escher.float", "Float Value")
local f_string_value = ProtoField.string("escher.string", "String Value")
local f_string_len = ProtoField.uint16("escher.string_len", "String Length", base.DEC)
local f_date_value = ProtoField.absolute_time("escher.date", "Date Value")
local f_symbol_value = ProtoField.string("escher.symbol", "Symbol Value")
local f_raw_len = ProtoField.uint32("escher.raw_len", "Raw Data Length", base.DEC)
local f_raw_data = ProtoField.bytes("escher.raw_data", "Raw Data")

-- Map fields
local f_map = ProtoField.none("escher.map", "Map")
local f_map_key = ProtoField.uint32("escher.map.key", "Map Key", base.HEX)
local f_map_symbol = ProtoField.string("escher.map.symbol", "Key Symbol")
local f_map_entry = ProtoField.none("escher.map.entry", "Map Entry")

-- Array fields
local f_array = ProtoField.none("escher.array", "Array")
local f_array_index = ProtoField.uint16("escher.array.index", "Array Index", base.HEX)
local f_array_entry = ProtoField.none("escher.array.entry", "Array Entry")

-- Container fields
local f_dirty_flag = ProtoField.bool("escher.dirty", "Dirty Flag")
local f_ptr_value = ProtoField.uint32("escher.ptr", "Pointer Value", base.HEX)

escher_proto.fields = {
    f_length, f_num_items, f_extended_header, f_ext_header_id,
    f_ext_length, f_ext_num_items,
    f_type, f_null_value, f_int_value, f_float_value, 
    f_string_value, f_string_len, f_date_value, f_symbol_value,
    f_raw_len, f_raw_data,
    f_map, f_map_key, f_map_symbol, f_map_entry,
    f_array, f_array_index, f_array_entry,
    f_dirty_flag, f_ptr_value
}

-- Constants
local EXT_HEADER_BLOCK_ID = 0xFFFE
local NEW_DIRTY_MASK = 0x8001
local ALIGN_SIZE = 4

-- Type code enumeration
local NULL_TYPE = 0x00
local INT_TYPE = 0x01
local DATE_TYPE = 0x02
local SYMBOL_TYPE = 0x03
local FLOAT_TYPE = 0x04
local STRING_TYPE = 0x05
local ARRAY_TYPE = 0x06
local MAP_TYPE = 0x07
local RAW_TYPE = 0x08

-- Helper functions
local function align(x)
    return bit.band(x + ALIGN_SIZE - 1, bit.bnot(ALIGN_SIZE - 1))
end

local function is_dirty(x)
    return bit.band(x, NEW_DIRTY_MASK) == NEW_DIRTY_MASK
end

local function decode_symbol(val)
    -- Decode 4-byte symbol to ASCII string
    local c1 = bit.band(bit.rshift(val, 24), 0xFF)
    local c2 = bit.band(bit.rshift(val, 16), 0xFF)
    local c3 = bit.band(bit.rshift(val, 8), 0xFF)
    local c4 = bit.band(val, 0xFF)
    
    -- Convert to printable characters
    local function to_char(b)
        if b >= 32 and b < 127 then
            return string.char(b)
        else
            return string.format("\\x%02X", b)
        end
    end
    
    return to_char(c1) .. to_char(c2) .. to_char(c3) .. to_char(c4)
end

local function extract_key_parts(key)
    -- Extract symbol, type, and offset from encoded key
    -- Format: ssss ssss ssss ssss ssst tttl llll llll
    local symbol = bit.band(key, 0xffffe000)
    local typecode = bit.band(bit.rshift(key, 9), 0x0f)
    local offset = bit.lshift(bit.band(key, 0x1ff), 2)
    
    return symbol, typecode, offset
end

-- Dissector for individual values based on type
local function dissect_value(buffer, offset, tree, typecode)
    local value_tree = tree
    local bytes_consumed = 0
    
    if typecode == NULL_TYPE then
        value_tree:add(f_null_value, buffer(offset, 0))
        bytes_consumed = 0
        
    elseif typecode == INT_TYPE then
        local value = buffer(offset, 4):int()
        value_tree:add(f_int_value, buffer(offset, 4), value)
        bytes_consumed = 4
        
    elseif typecode == FLOAT_TYPE then
        local value = buffer(offset, 8):le_float64()
        value_tree:add(f_float_value, buffer(offset, 8), value)
        bytes_consumed = 8
        
    elseif typecode == STRING_TYPE then
        local strlen = buffer(offset, 1):uint()
        local str_offset = 1
        
        if bit.band(strlen, 0x80) ~= 0 then
            -- Extended length (16-bit)
            strlen = bit.band(buffer(offset, 2):uint(), 0x7fff)
            str_offset = 2
        end
        
        value_tree:add(f_string_len, buffer(offset, str_offset), strlen)
        
        if strlen > 0 and (offset + str_offset + strlen) <= buffer:len() then
            local str = buffer(offset + str_offset, strlen):string()
            value_tree:add(f_string_value, buffer(offset + str_offset, strlen), str)
        end
        
        bytes_consumed = align(str_offset + strlen)
        
    elseif typecode == DATE_TYPE then
        local timestamp = buffer(offset, 4):uint()
        value_tree:add(f_date_value, buffer(offset, 4), timestamp)
        bytes_consumed = 4
        
    elseif typecode == SYMBOL_TYPE then
        local symbol_val = buffer(offset, 4):uint()
        local symbol_str = decode_symbol(symbol_val)
        value_tree:add(f_symbol_value, buffer(offset, 4), symbol_str)
        bytes_consumed = 4
        
    elseif typecode == RAW_TYPE then
        local raw_len = buffer(offset, 4):uint()
        value_tree:add(f_raw_len, buffer(offset, 4), raw_len)
        
        if raw_len > 0 and (offset + 4 + raw_len) <= buffer:len() then
            value_tree:add(f_raw_data, buffer(offset + 4, raw_len))
        end
        
        bytes_consumed = align(4 + raw_len)
        
    elseif typecode == ARRAY_TYPE then
        local array_bytes = dissect_array(buffer, offset, value_tree)
        bytes_consumed = array_bytes
        
    elseif typecode == MAP_TYPE then
        local map_bytes = dissect_map(buffer, offset, value_tree)
        bytes_consumed = map_bytes
    end
    
    return bytes_consumed
end

-- Dissector for Arrays
function dissect_array(buffer, offset, tree)
    if offset + 4 > buffer:len() then
        return 0
    end
    
    local array_tree = tree:add(f_array, buffer(offset))
    local start_offset = offset
    
    -- Check for extended header
    local is_extended = false
    local header_offset = 0
    
    if offset + 2 <= buffer:len() then
        local header_id = buffer(offset, 2):uint()
        if header_id == EXT_HEADER_BLOCK_ID then
            is_extended = true
            array_tree:add(f_extended_header, buffer(offset, 2), true)
            array_tree:add(f_ext_header_id, buffer(offset, 2))
            header_offset = buffer(offset + 2, 1):uint() - 1
            offset = offset + 4 + header_offset
        end
    end
    
    -- Read array header
    local num_items, byte_length
    
    if is_extended and offset + 12 <= buffer:len() then
        byte_length = buffer(offset, 4):uint()
        num_items = buffer(offset + 8, 4):uint()
        array_tree:add(f_ext_length, buffer(offset, 4), byte_length)
        array_tree:add(f_ext_num_items, buffer(offset + 8, 4), num_items)
        offset = offset + 12
    elseif offset + 4 <= buffer:len() then
        local ptr_val = buffer(offset, 4):uint()
        
        if is_dirty(ptr_val) then
            array_tree:add(f_dirty_flag, buffer(offset, 4), true)
            array_tree:add(f_ptr_value, buffer(offset, 4), ptr_val)
            return 4
        end
        
        byte_length = buffer(offset, 2):uint()
        num_items = buffer(offset + 2, 2):uint()
        array_tree:add(f_length, buffer(offset, 2), byte_length)
        array_tree:add(f_num_items, buffer(offset + 2, 2), num_items)
        offset = offset + 4
    else
        return 0
    end
    
    -- Read array index and items
    local items_start = offset
    
    for i = 0, num_items - 1 do
        if offset + 2 > buffer:len() then
            break
        end
        
        local entry_tree = array_tree:add(f_array_entry, buffer(offset), 
                                          string.format("Entry [%d]", i))
        
        -- Read index entry (contains type and offset)
        local index_val = buffer(offset, 2):uint()
        entry_tree:add(f_array_index, buffer(offset, 2), index_val)
        
        local typecode = bit.band(bit.rshift(index_val, 9), 0x0f)
        local item_offset = bit.lshift(bit.band(index_val, 0x1ff), 2)
        
        entry_tree:add(f_type, buffer(offset, 2), typecode)
        
        offset = offset + 2
        
        -- Dissect the value at the calculated offset
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < buffer:len() then
                dissect_value(buffer, value_offset, entry_tree, typecode)
            end
        end
    end
    
    return byte_length
end

-- Dissector for Maps
function dissect_map(buffer, offset, tree)
    if offset + 4 > buffer:len() then
        return 0
    end
    
    local map_tree = tree:add(f_map, buffer(offset))
    local start_offset = offset
    
    -- Check for extended header
    local is_extended = false
    local header_offset = 0
    
    if offset + 2 <= buffer:len() then
        local header_id = buffer(offset, 2):uint()
        if header_id == EXT_HEADER_BLOCK_ID then
            is_extended = true
            map_tree:add(f_extended_header, buffer(offset, 2), true)
            map_tree:add(f_ext_header_id, buffer(offset, 2))
            header_offset = buffer(offset + 2, 1):uint() - 1
            offset = offset + 4 + header_offset
        end
    end
    
    -- Read map header
    local num_items, byte_length
    
    if is_extended and offset + 12 <= buffer:len() then
        byte_length = buffer(offset, 4):uint()
        num_items = buffer(offset + 8, 4):uint()
        map_tree:add(f_ext_length, buffer(offset, 4), byte_length)
        map_tree:add(f_ext_num_items, buffer(offset + 8, 4), num_items)
        offset = offset + 12
    elseif offset + 4 <= buffer:len() then
        local ptr_val = buffer(offset, 4):uint()
        
        if is_dirty(ptr_val) then
            map_tree:add(f_dirty_flag, buffer(offset, 4), true)
            map_tree:add(f_ptr_value, buffer(offset, 4), ptr_val)
            return 4
        end
        
        byte_length = buffer(offset, 2):uint()
        num_items = buffer(offset + 2, 2):uint()
        map_tree:add(f_length, buffer(offset, 2), byte_length)
        map_tree:add(f_num_items, buffer(offset + 2, 2), num_items)
        offset = offset + 4
    else
        return 0
    end
    
    -- Read map index and items
    local items_start = offset
    
    for i = 0, num_items - 1 do
        if offset + 4 > buffer:len() then
            break
        end
        
        -- Read key entry (contains symbol, type, and offset)
        local key_val = buffer(offset, 4):uint()
        
        local symbol, typecode, item_offset = extract_key_parts(key_val)
        local symbol_str = decode_symbol(symbol)
        
        local entry_tree = map_tree:add(f_map_entry, buffer(offset), 
                                        string.format("Entry '%s'", symbol_str))
        
        entry_tree:add(f_map_key, buffer(offset, 4), key_val)
        entry_tree:add(f_map_symbol, buffer(offset, 4), symbol_str)
        entry_tree:add(f_type, buffer(offset, 4), typecode)
        
        offset = offset + 4
        
        -- Dissect the value at the calculated offset
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < buffer:len() then
                dissect_value(buffer, value_offset, entry_tree, typecode)
            end
        end
    end
    
    return byte_length
end

-- Main dissector function
function escher_proto.dissector(buffer, pinfo, tree)
    -- Set protocol column
    pinfo.cols.protocol = "ESCHER"
    
    local subtree = tree:add(escher_proto, buffer(), "Oracle ESCHER Protocol")
    
    -- Dissect as a Map (messages are maps at the top level)
    local bytes_dissected = dissect_map(buffer, 0, subtree)
    
    -- Set info column with basic message info
    pinfo.cols.info = string.format("ESCHER Message (%d bytes)", buffer:len())
    
    return bytes_dissected
end

-- Register the dissector
-- You can register for specific TCP/UDP ports or use "Decode As..."
local tcp_port = DissectorTable.get("tcp.port")
local udp_port = DissectorTable.get("udp.port")

-- Register for common OCNCC ports (adjust as needed)
-- These are examples - replace with actual ports used in your environment
tcp_port:add(5000, escher_proto)
tcp_port:add(5001, escher_proto)
udp_port:add(5000, escher_proto)
udp_port:add(5001, escher_proto)

-- Also allow manual "Decode As..." selection
DissectorTable.get("tcp.port"):add(0, escher_proto)
DissectorTable.get("udp.port"):add(0, escher_proto)

print("ESCHER Protocol Dissector loaded")
