-- Oracle ESCHER Protocol Dissector (Corrected Version)

local escher_proto = Proto("ESCHER", "Oracle ESCHER Protocol")

-- ========= CONFIG =========
local USE_LITTLE_ENDIAN = true
local ALIGN_SIZE = 4
local EXT_HEADER_BLOCK_ID = 0xFFFE
local NEW_DIRTY_MASK = 0x8001

-- ========= FIELDS =========

local f_msg_len      = ProtoField.uint16("escher.msg_len", "Message Length", base.DEC)
local f_length       = ProtoField.uint16("escher.length", "Block Length", base.DEC)
local f_num_items    = ProtoField.uint16("escher.num_items", "Number of Items", base.DEC)
local f_type         = ProtoField.uint8("escher.type", "Type Code", base.HEX)
local f_map          = ProtoField.none("escher.map", "Map")
local f_map_entry    = ProtoField.none("escher.map.entry", "Map Entry")
local f_map_key      = ProtoField.uint32("escher.map.key", "Map Key", base.HEX)
local f_map_symbol   = ProtoField.string("escher.map.symbol", "Key Symbol")
local f_int_value    = ProtoField.int32("escher.int", "Integer Value", base.DEC)
local f_string_value = ProtoField.string("escher.string", "String Value")
local f_string_len   = ProtoField.uint16("escher.string_len", "String Length", base.DEC)
local f_dirty_flag   = ProtoField.bool("escher.dirty", "Dirty Pointer")

escher_proto.fields = {
    f_msg_len, f_length, f_num_items,
    f_type, f_map, f_map_entry, f_map_key,
    f_map_symbol, f_int_value,
    f_string_value, f_string_len,
    f_dirty_flag
}

-- ========= HELPERS =========

local function align(x)
    return bit.band(x + ALIGN_SIZE - 1, bit.bnot(ALIGN_SIZE - 1))
end

local function u16(buf, off)
    if USE_LITTLE_ENDIAN then
        return buf(off,2):le_uint()
    else
        return buf(off,2):uint()
    end
end

local function u32(buf, off)
    if USE_LITTLE_ENDIAN then
        return buf(off,4):le_uint()
    else
        return buf(off,4):uint()
    end
end

local function is_dirty(x)
    return bit.band(x, NEW_DIRTY_MASK) == NEW_DIRTY_MASK
end

local function decode_symbol(val)
    local c1 = bit.band(bit.rshift(val,24),0xFF)
    local c2 = bit.band(bit.rshift(val,16),0xFF)
    local c3 = bit.band(bit.rshift(val,8),0xFF)
    local c4 = bit.band(val,0xFF)
    return string.char(c1,c2,c3,c4)
end

local function extract_key_parts(key)
    local symbol = bit.band(key, 0xffffe000)
    local typecode = bit.band(bit.rshift(key, 9), 0x0f)
    local offset = bit.lshift(bit.band(key, 0x1ff), 2)
    return symbol, typecode, offset
end

-- ========= VALUE DISSECTION =========

local NULL_TYPE   = 0x00
local INT_TYPE    = 0x01
local STRING_TYPE = 0x05
local MAP_TYPE    = 0x07

local function dissect_value(buffer, base_offset, container_start, tree, typecode)

    if typecode == NULL_TYPE then
        return 0
    end

    if typecode == INT_TYPE then
        if base_offset + 4 > buffer:len() then return 0 end
        tree:add(f_int_value, buffer(base_offset,4), u32(buffer, base_offset))
        return 4
    end

    if typecode == STRING_TYPE then
        if base_offset + 1 > buffer:len() then return 0 end

        local strlen = buffer(base_offset,1):uint()
        tree:add(f_string_len, buffer(base_offset,1), strlen)

        if base_offset + 1 + strlen > buffer:len() then return 0 end

        tree:add(f_string_value,
                 buffer(base_offset+1, strlen),
                 buffer(base_offset+1, strlen):string())

        return align(1 + strlen)
    end

    if typecode == MAP_TYPE then
        return dissect_map(buffer, base_offset, tree)
    end

    return 0
end

-- ========= MAP DISSECTION =========

function dissect_map(buffer, offset, tree)

    if offset + 4 > buffer:len() then return 0 end

    local start_offset = offset

    local byte_length = u16(buffer, offset)
    local num_items   = u16(buffer, offset + 2)

    if byte_length == 0 or offset + byte_length > buffer:len() then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR,
            "Invalid ESCHER block length")
        return 0
    end

    local map_tree = tree:add(f_map,
        buffer(offset, byte_length),
        "Map (" .. num_items .. " items)")

    map_tree:add(f_length, buffer(offset,2), byte_length)
    map_tree:add(f_num_items, buffer(offset+2,2), num_items)

    offset = offset + 4
    local index_table_start = offset

    for i = 0, num_items - 1 do

        if offset + 4 > start_offset + byte_length then break end

        local key_val = u32(buffer, offset)
        local symbol, typecode, item_offset = extract_key_parts(key_val)

        local entry_tree = map_tree:add(
            f_map_entry,
            buffer(offset,4),
            "Entry ["..i.."]"
        )

        entry_tree:add(f_map_key, buffer(offset,4), key_val)
        entry_tree:add(f_map_symbol, buffer(offset,4), decode_symbol(symbol))
        entry_tree:add(f_type, buffer(offset,4), typecode)

        offset = offset + 4

        if item_offset > 0 then
            local value_offset = start_offset + item_offset
            if value_offset < start_offset + byte_length then
                dissect_value(buffer, value_offset,
                              start_offset, entry_tree, typecode)
            end
        end
    end

    return byte_length
end

-- ========= MAIN DISSECTOR =========

function escher_proto.dissector(buffer, pinfo, tree)

    pinfo.cols.protocol = "ESCHER"

    if buffer:len() < 2 then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    local msg_len = u16(buffer,0)

    if buffer:len() < msg_len then
        pinfo.desegment_len = msg_len - buffer:len()
        pinfo.desegment_offset = 0
        return
    end

    local subtree = tree:add(escher_proto,
                             buffer(0,msg_len),
                             "Oracle ESCHER Message")

    subtree:add(f_msg_len, buffer(0,2), msg_len)

    dissect_map(buffer, 0, subtree)

    pinfo.cols.info = "ESCHER Message (" .. msg_len .. " bytes)"

    return msg_len
end

-- ========= REGISTRATION =========

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(5000, escher_proto)
tcp_port:add(5001, escher_proto)

print("Corrected ESCHER Dissector Loaded")