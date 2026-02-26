-- ============================================================
-- Oracle ESCHER Protocol Dissector
-- Production Version – Full Decode
-- Designed for Offline Rolling Snoop PCAP Analysis
-- ============================================================

local escher_proto = Proto("ESCHER", "Oracle ESCHER Protocol")

-- ================= CONFIG =================

local USE_LITTLE_ENDIAN = true
local ALIGN_SIZE = 4
local EXT_HEADER_BLOCK_ID = 0xFFFE
local NEW_DIRTY_MASK = 0x8001

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

-- ================= FIELDS =================

local f_msg_len    = ProtoField.uint16("escher.msg_len", "Message Length", base.DEC)
local f_length     = ProtoField.uint32("escher.length", "Container Length", base.DEC)
local f_num_items  = ProtoField.uint32("escher.num_items", "Number of Items", base.DEC)
local f_extended   = ProtoField.bool("escher.extended", "Extended Header")
local f_dirty      = ProtoField.bool("escher.dirty", "Dirty Pointer")
local f_type       = ProtoField.uint8("escher.type", "Type Code", base.HEX)

local f_map        = ProtoField.none("escher.map", "Map")
local f_array      = ProtoField.none("escher.array", "Array")
local f_entry      = ProtoField.none("escher.entry", "Entry")

local f_key_raw    = ProtoField.uint32("escher.key.raw", "Raw Key", base.HEX)
local f_key_symbol = ProtoField.string("escher.key.symbol", "Symbol")
local f_key_offset = ProtoField.uint32("escher.key.offset", "Value Offset", base.DEC)

local f_array_index = ProtoField.uint16("escher.array.index", "Index Value", base.HEX)

local f_int        = ProtoField.int32("escher.int", "Integer Value", base.DEC)
local f_float      = ProtoField.double("escher.float", "Float Value")
local f_string_len = ProtoField.uint16("escher.string_len", "String Length", base.DEC)
local f_string     = ProtoField.string("escher.string", "String Value")
local f_date       = ProtoField.absolute_time("escher.date", "Date Value")
local f_symbol_val = ProtoField.string("escher.symbol", "Symbol Value")
local f_raw_len    = ProtoField.uint32("escher.raw_len", "Raw Length", base.DEC)
local f_raw        = ProtoField.bytes("escher.raw", "Raw Data")

escher_proto.fields = {
    f_msg_len, f_length, f_num_items,
    f_extended, f_dirty, f_type,
    f_map, f_array, f_entry,
    f_key_raw, f_key_symbol, f_key_offset,
    f_array_index,
    f_int, f_float,
    f_string_len, f_string,
    f_date, f_symbol_val,
    f_raw_len, f_raw
}

-- ================= HELPERS =================

local function align(x)
    return bit.band(x + ALIGN_SIZE - 1, bit.bnot(ALIGN_SIZE - 1))
end

local function u16(buf, off)
    return USE_LITTLE_ENDIAN and buf(off,2):le_uint()
                                or  buf(off,2):uint()
end

local function u32(buf, off)
    return USE_LITTLE_ENDIAN and buf(off,4):le_uint()
                                or  buf(off,4):uint()
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

-- ================= VALUE DISSECTION =================

local function dissect_value(buffer, value_offset, container_start, tree, typecode)

    if typecode == NULL_TYPE then
        tree:add(f_type, buffer(value_offset,0), typecode)
        return 0
    end

    if typecode == INT_TYPE then
        tree:add(f_int, buffer(value_offset,4), u32(buffer,value_offset))
        return 4
    end

    if typecode == FLOAT_TYPE then
        tree:add(f_float,
                 buffer(value_offset,8),
                 buffer(value_offset,8):le_float64())
        return 8
    end

    if typecode == STRING_TYPE then
        local strlen = buffer(value_offset,1):uint()
        tree:add(f_string_len, buffer(value_offset,1), strlen)
        tree:add(f_string,
                 buffer(value_offset+1, strlen),
                 buffer(value_offset+1, strlen):string())
        return align(1 + strlen)
    end

    if typecode == DATE_TYPE then
        local ts = u32(buffer, value_offset)
        tree:add(f_date,
                 buffer(value_offset,4),
                 NSTime(ts,0))
        return 4
    end

    if typecode == SYMBOL_TYPE then
        local sym = u32(buffer,value_offset)
        tree:add(f_symbol_val,
                 buffer(value_offset,4),
                 decode_symbol(sym))
        return 4
    end

    if typecode == RAW_TYPE then
        local raw_len = u32(buffer,value_offset)
        tree:add(f_raw_len, buffer(value_offset,4), raw_len)
        tree:add(f_raw,
                 buffer(value_offset+4, raw_len))
        return align(4 + raw_len)
    end

    if typecode == ARRAY_TYPE then
        return dissect_array(buffer, value_offset, tree)
    end

    if typecode == MAP_TYPE then
        return dissect_map(buffer, value_offset, tree)
    end

    return 0
end

-- ================= ARRAY =================

function dissect_array(buffer, offset, tree)

    local start = offset
    local byte_length = u16(buffer, offset)
    local num_items   = u16(buffer, offset+2)

    local array_tree = tree:add(f_array,
        buffer(offset, byte_length),
        "Array ("..num_items.." items)")

    array_tree:add(f_length, buffer(offset,2), byte_length)
    array_tree:add(f_num_items, buffer(offset+2,2), num_items)

    offset = offset + 4

    for i=0, num_items-1 do
        local index_val = u16(buffer, offset)
        local typecode = bit.band(bit.rshift(index_val, 9), 0x0f)
        local item_offset = bit.lshift(bit.band(index_val, 0x1ff), 2)

        local entry_tree = array_tree:add(f_entry,
            buffer(offset,2),
            "Element ["..i.."]")

        entry_tree:add(f_array_index, buffer(offset,2), index_val)
        entry_tree:add(f_type, buffer(offset,2), typecode)
        entry_tree:add(f_key_offset, buffer(offset,2), item_offset)

        offset = offset + 2

        if item_offset > 0 then
            local value_offset = start + item_offset
            dissect_value(buffer, value_offset,
                          start, entry_tree, typecode)
        end
    end

    return byte_length
end

-- ================= MAP =================

function dissect_map(buffer, offset, tree)

    local start = offset
    local byte_length = u16(buffer, offset)
    local num_items   = u16(buffer, offset+2)

    local map_tree = tree:add(f_map,
        buffer(offset, byte_length),
        "Map ("..num_items.." entries)")

    map_tree:add(f_length, buffer(offset,2), byte_length)
    map_tree:add(f_num_items, buffer(offset+2,2), num_items)

    offset = offset + 4

    for i=0, num_items-1 do

        local key_val = u32(buffer, offset)

        if is_dirty(key_val) then
            map_tree:add(f_dirty, buffer(offset,4), true)
            return byte_length
        end

        local symbol, typecode, item_offset =
            extract_key_parts(key_val)

        local entry_tree = map_tree:add(f_entry,
            buffer(offset,4),
            "Entry ["..i.."]")

        entry_tree:add(f_key_raw, buffer(offset,4), key_val)
        entry_tree:add(f_key_symbol,
                       buffer(offset,4),
                       decode_symbol(symbol))
        entry_tree:add(f_type, buffer(offset,4), typecode)
        entry_tree:add(f_key_offset,
                       buffer(offset,4), item_offset)

        offset = offset + 4

        if item_offset > 0 then
            local value_offset = start + item_offset
            dissect_value(buffer, value_offset,
                          start, entry_tree, typecode)
        end
    end

    return byte_length
end

-- ================= CONVERSATION TRACKING =================

local conversations = {}

-- ================= MAIN DISSECTOR =================

function escher_proto.dissector(buffer, pinfo, tree)

    local offset = 0
    local total_len = buffer:len()

    while offset < total_len do

        if total_len - offset < 2 then
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            pinfo.desegment_offset = offset
            return
        end

        local msg_len = u16(buffer, offset)

        if msg_len == 0 then return 0 end

        if total_len - offset < msg_len then
            pinfo.desegment_len =
                msg_len - (total_len - offset)
            pinfo.desegment_offset = offset
            return
        end

        pinfo.cols.protocol = "ESCHER"

        local subtree = tree:add(escher_proto,
            buffer(offset, msg_len),
            "Oracle ESCHER Message")

        subtree:add(f_msg_len,
            buffer(offset,2), msg_len)

        local conv_key =
            tostring(pinfo.src) .. ":" ..
            tostring(pinfo.src_port) .. "->" ..
            tostring(pinfo.dst) .. ":" ..
            tostring(pinfo.dst_port)

        if not conversations[conv_key] then
            conversations[conv_key] = 0
        end

        conversations[conv_key] =
            conversations[conv_key] + 1

        subtree:append_text(
            " [Msg #" ..
            conversations[conv_key] .. "]"
        )

        dissect_map(buffer, offset, subtree)

        offset = offset + msg_len
    end

    return total_len
end

-- ================= HEURISTIC REGISTRATION =================

escher_proto:register_heuristic("tcp",
    function(buffer,pinfo,tree)
        local consumed =
            escher_proto.dissector(buffer,pinfo,tree)
        return consumed and consumed > 0
    end)

print("Oracle ESCHER Dissector Loaded")