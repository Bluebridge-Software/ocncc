-- ============================================================
-- Oracle ESCHER/FOX Protocol Dissector
-- Expanded for FOX Protocol Semantics
-- ============================================================

local escher_proto = Proto("ESCHER_FOX", "Oracle ESCHER/FOX Protocol")

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

-- ================= FOX SYMBOL TABLE =================

local FOX_SYMBOLS = {
    [0x564E554D] = "VNUM",    -- Voucher Number
    [0x41524546] = "AREF",    -- Account Subscriber Reference
    [0x57414C54] = "WALT",    -- Wallet Identifier
    [0x41435459] = "ACTY",    -- Account Product Type
    [0x4E554D20] = "NUM",     -- Number of Units/Events
    [0x434C4920] = "CLI",     -- Calling Line Identifier
    [0x444E2020] = "DN",      -- Dialled Number
    [0x4552534C] = "ERSL",    -- Preferred Reservation Length
    [0x50524543] = "PREC",    -- Precision
    [0x44495343] = "DISC",    -- Discount Override
    [0x43445220] = "CDR",     -- CDR Array
    [0x54414720] = "TAG",     -- CDR Tag
    [0x56414C20] = "VAL",     -- CDR Value
    [0x434C5353] = "CLSS",    -- Event Class
    [0x4E414D45] = "NAME",    -- Event Name
    [0x4D415820] = "MAX",     -- Max Units/Amount
    [0x4D494E20] = "MIN",     -- Min Units/Amount
    [0x57414C52] = "WALR",    -- Wallet Reference
    [0x54504F20] = "TPO",     -- Tariff Plan Override
    [0x545A2020] = "TZ",      -- Time Zone
    [0x53504944] = "SPID",    -- Service Provider ID
    [0x55435552] = "UCUR",    -- User Currency ID
    [0x42434F52] = "BCOR",    -- Balance Cascade Override
    [0x43534320] = "CSC",     -- Charging Service Code
    [0x44415445] = "DATE",    -- Call Date
    [0x5245534E] = "RESN",    -- Reason
    [0x4C4F5754] = "LOWT",    -- Low Credit Beep Time
    [0x4C4F5741] = "LOWA",    -- Low Credit Announcement
    [0x54434F44] = "TCOD",    -- Tariff Code
    [0x544F5420] = "TOT",     -- Session Time Left
    [0x46434420] = "FCD",     -- Free Call Directive
    [0x434F4445] = "CODE",    -- Error Code
    [0x57484154] = "WHAT",    -- Error Message
    [0x42545950] = "BTYP",    -- Balance Type
    [0x42554E54] = "BUNT",    -- Balance Unit
    [0x4C494D54] = "LIMT",    -- Limit Type
    [0x53544F54] = "STOT",    -- Sum of Buckets
    [0x55544F54] = "UTOT",    -- Sum in User Currency
    [0x424B5453] = "BKTS",    -- Buckets Array
    [0x45585052] = "EXPR",    -- Expiry Date
    [0x4C555345] = "LUSE",    -- Last Use Date
    [0x53544154] = "STAT",    -- State
    [0x4D494E43] = "MINC",    -- Minimum Credit
    [0x4D415843] = "MAXC",    -- Max Concurrent Users
    [0x53435552] = "SCUR",    -- System Currency
    [0x41435456] = "ACTV",    -- Activation Date
    [0x42414C53] = "BALS",    -- Balances Array
    [0x52424141] = "RBAA",    -- Recharge Balance Array
    [0x56494E46] = "VINF",    -- Voucher Info
    [0x52424941] = "RBIA",    -- Recharge Bucket Info Array
    [0x42524550] = "BREP",    -- Balance Replace
    [0x42455850] = "BEXP",    -- Balance Expiry
    [0x42455854] = "BEXT",    -- Balance Expiry Extension
    [0x424B4944] = "BKID",    -- Bucket ID
    [0x424E4557] = "BNEW",    -- New Bucket
    [0x42504F4C] = "BPOL",    -- Balance Expiry Policy
    [0x4D42504F] = "MBPO",    -- Missing Balance Policy
    [0x56424944] = "VBID",    -- Voucher Batch ID
    [0x56434852] = "VCHR",    -- Voucher ID
    [0x41504F4C] = "APOL",    -- Wallet Expiry Policy
    [0x41455854] = "AEXT",    -- Wallet Expiry Extension
    [0x42504F4C] = "BPOL",    -- Balance Expiry Policy
    [0x4442504F] = "DBPO",    -- Default Bucket Policy
    [0x434F5354] = "COST",    -- Call Cost
    [0x52425649] = "RBVI",    -- Recharge Balance Voucher Info
    [0x4F424520] = "OBE",     -- Old Balance Expiry
    [0x4E424520] = "NBE",     -- New Balance Expiry
    [0x42564348] = "BVCH",    -- Balance Value Change
    [0x57492020] = "WI",      -- Wallet Info
    [0x434E464D] = "CNFM",    -- Confirmation Amount
    [0x52455155] = "REQU",    -- Requested Units
    [0x52535256] = "RSRV",    -- Reserved Amount
    [0x544D4C46] = "TMLF",    -- Reservation Lifetime
    [0x4455524E] = "DURN",    -- Duration
    [0x52415445] = "RATE",    -- Rate
    [0x4D415843] = "MAXC",    -- Max Charge
    [0x4E534650] = "NSFP",    -- No Sufficient Funds Policy
    [0x5043534C] = "PCSL",    -- Pre-Condition States
    [0x49574220] = "IWB",     -- Ignore Wallet Balance
    [0x414D4E54] = "AMNT",    -- Amount
    [0x42414C43] = "BALC",    -- Balance Cascade
    [0x42564D4F] = "BVMO",    -- Balance Validity Modification
    [0x57545950] = "WTYP",    -- Wallet Type
    [0x57564D4F] = "WVMO",    -- Wallet Validity Modification
    [0x434D4944] = "CMID",    -- Request Number
    [0x53564944] = "SVID",    -- Server ID
    [0x55534543] = "USEC",    -- Microseconds
    [0x56455220] = "VER",     -- Protocol Version
    [0x44555020] = "DUP",     -- Duplicate Flag
    [0x4143544E] = "ACTN",    -- Action (REQ/ACK/NACK/EXCP/ABRT)
    [0x54595045] = "TYPE",    -- Message Type (IR/SR/CR/etc.)
    [0x48454144] = "HEAD",    -- Header
    [0x424F4459] = "BODY",    -- Body
}

-- ================= FOX MESSAGE TYPE TABLE =================

local FOX_MESSAGE_TYPES = {
    ["BEG "] = "Begin",
    ["IR  "] = "Initial Reserve Seconds",
    ["SR  "] = "Subsequent Reserve Seconds",
    ["CR  "] = "Debit Seconds & Release",
    ["RR  "] = "Release Seconds",
    ["ATC "] = "Direct Debit(Credit) Seconds",
    ["INER"] = "Initial Reserve Named Event",
    ["SNER"] = "Subsequent Reserve Named Event",
    ["CNER"] = "Debit Named Event & Release",
    ["RNER"] = "Release Named Event",
    ["NE  "] = "Direct Debit(Credit) Named Event",
    ["WGR "] = "Direct Credit Amount",
    ["DA  "] = "Direct Debit(Credit) Amount",
    ["IARR"] = "Initial Reserve Amount",
    ["SARR"] = "Subsequent Reserve Amount",
    ["CARR"] = "Debit Amount & Release",
    ["RARR"] = "Release Amount",
    ["USR "] = "Rate Seconds Request",
    ["NER "] = "Rate Named Event Request",
    ["WI  "] = "Query Balance",
    ["WU  "] = "Account State Update",
    ["EXCP"] = "Exception",
    ["ABRT"] = "Abort",
}

-- ================= FOX FIELD DEFINITIONS =================

local FOX_FIELD_DEFS = {
    -- Begin Message
    ["BEG "] = {
        { name = "NAME", type = STRING_TYPE, desc = "Client Process Name" },
    },
    -- Initial Reserve Seconds (IR)
    ["IR  "] = {
        { name = "ACTY", type = INT_TYPE, desc = "Account Product Type" },
        { name = "AREF", type = INT_TYPE, desc = "Account Subscriber Reference" },
        { name = "WALT", type = INT_TYPE, desc = "Wallet Identifier" },
        { name = "NUM", type = INT_TYPE, desc = "Number of Units" },
        { name = "CLI", type = STRING_TYPE, desc = "Calling Line Identifier" },
        { name = "DN", type = STRING_TYPE, desc = "Dialled Number" },
        { name = "ERSL", type = INT_TYPE, desc = "Preferred Reservation Length" },
        { name = "PREC", type = SYMBOL_TYPE, desc = "Precision" },
        { name = "DISC", type = MAP_TYPE, desc = "Discount Override" },
        { name = "CDR", type = ARRAY_TYPE, desc = "CDR Array" },
        { name = "BCOR", type = INT_TYPE, desc = "Balance Cascade Override" },
        { name = "CSC", type = STRING_TYPE, desc = "Charging Service Code" },
        { name = "DATE", type = DATE_TYPE, desc = "Call Date" },
        { name = "TPO", type = INT_TYPE, desc = "Tariff Plan Override" },
        { name = "TZ", type = STRING_TYPE, desc = "Time Zone" },
        { name = "SPID", type = INT_TYPE, desc = "Service Provider ID" },
        { name = "UCUR", type = INT_TYPE, desc = "User Currency ID" },
        { name = "WALR", type = STRING_TYPE, desc = "Wallet Reference" },
    },
    -- Subsequent Reserve Seconds (SR)
    ["SR  "] = {
        { name = "WALT", type = INT_TYPE, desc = "Wallet Identifier" },
        { name = "NUM", type = INT_TYPE, desc = "Number of Units" },
        { name = "ERSL", type = INT_TYPE, desc = "Preferred Reservation Length" },
        { name = "DISC", type = MAP_TYPE, desc = "Discount Override" },
    },
    -- Debit Seconds & Release (CR)
    ["CR  "] = {
        { name = "WALT", type = INT_TYPE, desc = "Wallet Identifier" },
        { name = "NUM", type = INT_TYPE, desc = "Number of Units Used" },
        { name = "RESN", type = SYMBOL_TYPE, desc = "Reason" },
        { name = "DISC", type = MAP_TYPE, desc = "Discount Override" },
        { name = "CDR", type = ARRAY_TYPE, desc = "CDR Array" },
    },
    -- Direct Credit Amount (WGR)
    ["WGR "] = {
        { name = "AREF", type = INT_TYPE, desc = "Account Subscriber Reference" },
        { name = "WALT", type = INT_TYPE, desc = "Wallet Identifier" },
        { name = "AMNT", type = INT_TYPE, desc = "Amount" },
        { name = "RBAA", type = ARRAY_TYPE, desc = "Recharge Balance Array" },
        { name = "VINF", type = MAP_TYPE, desc = "Voucher Info" },
        { name = "WALR", type = STRING_TYPE, desc = "Wallet Reference" },
        { name = "UCUR", type = INT_TYPE, desc = "User Currency ID" },
        { name = "SPID", type = INT_TYPE, desc = "Service Provider ID" },
        { name = "CDR", type = ARRAY_TYPE, desc = "CDR Array" },
    },
    -- Add more FOX message types as needed...
}

-- ================= FIELDS =================

local f_msg_len    = ProtoField.uint16("escher.fox.msg_len", "Message Length", base.DEC)
local f_length     = ProtoField.uint32("escher.fox.length", "Container Length", base.DEC)
local f_num_items  = ProtoField.uint32("escher.fox.num_items", "Number of Items", base.DEC)
local f_extended   = ProtoField.bool("escher.fox.extended", "Extended Header")
local f_dirty      = ProtoField.bool("escher.fox.dirty", "Dirty Pointer")
local f_type       = ProtoField.uint8("escher.fox.type", "Type Code", base.HEX)

local f_map        = ProtoField.none("escher.fox.map", "Map")
local f_array      = ProtoField.none("escher.fox.array", "Array")
local f_entry      = ProtoField.none("escher.fox.entry", "Entry")

local f_key_raw    = ProtoField.uint32("escher.fox.key.raw", "Raw Key", base.HEX)
local f_key_symbol = ProtoField.string("escher.fox.key.symbol", "Symbol")
local f_key_name   = ProtoField.string("escher.fox.key.name", "Field Name")
local f_key_offset = ProtoField.uint32("escher.fox.key.offset", "Value Offset", base.DEC)

local f_array_index = ProtoField.uint16("escher.fox.array.index", "Index Value", base.HEX)

local f_int        = ProtoField.int32("escher.fox.int", "Integer Value", base.DEC)
local f_float      = ProtoField.double("escher.fox.float", "Float Value")
local f_string_len = ProtoField.uint16("escher.fox.string_len", "String Length", base.DEC)
local f_string     = ProtoField.string("escher.fox.string", "String Value")
local f_date       = ProtoField.absolute_time("escher.fox.date", "Date Value")
local f_symbol_val = ProtoField.string("escher.fox.symbol", "Symbol Value")
local f_raw_len    = ProtoField.uint32("escher.fox.raw_len", "Raw Length", base.DEC)
local f_raw        = ProtoField.bytes("escher.fox.raw", "Raw Data")

local f_fox_type   = ProtoField.string("escher.fox.type_name", "FOX Message Type")
local f_fox_action = ProtoField.string("escher.fox.action", "FOX Action")
local f_fox_cmid   = ProtoField.uint32("escher.fox.cmid", "Request Number (CMID)", base.DEC)
local f_fox_svid   = ProtoField.uint32("escher.fox.svid", "Server ID (SVID)", base.DEC)
local f_fox_ver    = ProtoField.uint32("escher.fox.ver", "Protocol Version (VER)", base.DEC)

escher_proto.fields = {
    f_msg_len, f_length, f_num_items,
    f_extended, f_dirty, f_type,
    f_map, f_array, f_entry,
    f_key_raw, f_key_symbol, f_key_name, f_key_offset,
    f_array_index,
    f_int, f_float,
    f_string_len, f_string,
    f_date, f_symbol_val,
    f_raw_len, f_raw,
    f_fox_type, f_fox_action, f_fox_cmid, f_fox_svid, f_fox_ver,
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

local function get_fox_field_name(symbol)
    return FOX_SYMBOLS[symbol] or decode_symbol(symbol)
end

-- ================= FOX-SPECIFIC DISSECTION =================

local function dissect_fox_header(buffer, offset, tree)
    local header_tree = tree:add(f_map, buffer(offset, 16), "FOX Header")

    local start = offset
    local byte_length = u16(buffer, offset)
    local num_items   = u16(buffer, offset+2)

    header_tree:add(f_length, buffer(offset,2), byte_length)
    header_tree:add(f_num_items, buffer(offset+2,2), num_items)

    offset = offset + 4

    for i=0, num_items-1 do
        local key_val = u32(buffer, offset)

        if is_dirty(key_val) then
            header_tree:add(f_dirty, buffer(offset,4), true)
            return byte_length
        end

        local symbol, typecode, item_offset = extract_key_parts(key_val)
        local fox_name = get_fox_field_name(symbol)

        local entry_tree = header_tree:add(f_entry,
            buffer(offset,4),
            string.format("Header Entry [%d]: [%s]", i, fox_name))

        entry_tree:add(f_key_raw, buffer(offset,4), key_val)
        entry_tree:add(f_key_name, buffer(offset,4), fox_name)
        entry_tree:add(f_type, buffer(offset,4), typecode)
        entry_tree:add(f_key_offset, buffer(offset,4), item_offset)

        offset = offset + 4

        if item_offset > 0 then
            local value_offset = start + item_offset
            if fox_name == "CMID" then
                entry_tree:add(f_fox_cmid, buffer(value_offset,4), u32(buffer, value_offset))
            elseif fox_name == "SVID" then
                entry_tree:add(f_fox_svid, buffer(value_offset,4), u32(buffer, value_offset))
            elseif fox_name == "VER" then
                entry_tree:add(f_fox_ver, buffer(value_offset,4), u32(buffer, value_offset))
            elseif fox_name == "TYPE" then
                local type_symbol = u32(buffer, value_offset)
                local type_str = decode_symbol(type_symbol)
                local type_desc = FOX_MESSAGE_TYPES[type_str] or type_str
                entry_tree:add(f_fox_type, buffer(value_offset,4), type_desc)
            elseif fox_name == "ACTN" then
                local action_symbol = u32(buffer, value_offset)
                local action_str = decode_symbol(action_symbol)
                entry_tree:add(f_fox_action, buffer(value_offset,4), action_str)
            else
                dissect_value(buffer, value_offset, start, entry_tree, typecode)
            end
        end
    end

    return byte_length
end

local function dissect_fox_body(buffer, offset, tree, msg_type)
    local body_tree = tree:add(f_map, buffer(offset, 32), string.format("FOX Body (%s)", msg_type))
    local start = offset
    local byte_length = u16(buffer, offset)
    local num_items   = u16(buffer, offset+2)

    body_tree:add(f_length, buffer(offset,2), byte_length)
    body_tree:add(f_num_items, buffer(offset+2,2), num_items)

    offset = offset + 4

    -- If this message type has a defined structure, use it
    local fox_fields = FOX_FIELD_DEFS[msg_type] or {}

    for i=0, num_items-1 do
        local key_val = u32(buffer, offset)

        if is_dirty(key_val) then
            body_tree:add(f_dirty, buffer(offset,4), true)
            return byte_length
        end

        local symbol, typecode, item_offset = extract_key_parts(key_val)
        local fox_name = get_fox_field_name(symbol)

        local entry_tree = body_tree:add(f_entry,
            buffer(offset,4),
            string.format("Body Entry [%d]: [%s]", i, fox_name))

        entry_tree:add(f_key_raw, buffer(offset,4), key_val)
        entry_tree:add(f_key_name, buffer(offset,4), fox_name)
        entry_tree:add(f_type, buffer(offset,4), typecode)
        entry_tree:add(f_key_offset, buffer(offset,4), item_offset)

        offset = offset + 4

        if item_offset > 0 then
            local value_offset = start + item_offset
            dissect_value(buffer, value_offset, start, entry_tree, typecode, fox_name, fox_fields)
        end
    end

    return byte_length
end

-- ================= VALUE DISSECTION =================

local function dissect_value(buffer, value_offset, container_start, tree, typecode, fox_name, fox_fields)
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
        local sym_str = decode_symbol(sym)
        tree:add(f_symbol_val,
                 buffer(value_offset,4),
                 sym_str)
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
        return dissect_array(buffer, value_offset, tree, fox_name, fox_fields)
    end

    if typecode == MAP_TYPE then
        return dissect_map(buffer, value_offset, tree, fox_name, fox_fields)
    end

    return 0
end

-- ================= ARRAY =================

function dissect_array(buffer, offset, tree, fox_name, fox_fields)
    local start = offset
    local byte_length = u16(buffer, offset)
    local num_items   = u16(buffer, offset+2)

    local array_tree = tree:add(f_array,
        buffer(offset, byte_length),
        string.format("Array [%s] (%d items)", fox_name or "", num_items))

    array_tree:add(f_length, buffer(offset,2), byte_length)
    array_tree:add(f_num_items, buffer(offset+2,2), num_items)

    offset = offset + 4

    for i=0, num_items-1 do
        local index_val = u16(buffer, offset)
        local typecode = bit.band(bit.rshift(index_val, 9), 0x0f)
        local item_offset = bit.lshift(bit.band(index_val, 0x1ff), 2)

        local entry_tree = array_tree:add(f_entry,
            buffer(offset,2),
            string.format("Element [%d]", i))

        entry_tree:add(f_array_index, buffer(offset,2), index_val)
        entry_tree:add(f_type, buffer(offset,2), typecode)
        entry_tree:add(f_key_offset, buffer(offset,2), item_offset)

        offset = offset + 2

        if item_offset > 0 then
            local value_offset = start + item_offset
            dissect_value(buffer, value_offset, start, entry_tree, typecode, fox_name, fox_fields)
        end
    end

    return byte_length
end

-- ================= MAP =================

function dissect_map(buffer, offset, tree, fox_name, fox_fields)
    local start = offset
    local byte_length = u16(buffer, offset)
    local num_items   = u16(buffer, offset+2)

    local map_tree = tree:add(f_map,
        buffer(offset, byte_length),
        string.format("Map [%s] (%d entries)", fox_name or "", num_items))

    map_tree:add(f_length, buffer(offset,2), byte_length)
    map_tree:add(f_num_items, buffer(offset+2,2), num_items)

    offset = offset + 4

    for i=0, num_items-1 do
        local key_val = u32(buffer, offset)

        if is_dirty(key_val) then
            map_tree:add(f_dirty, buffer(offset,4), true)
            return byte_length
        end

        local symbol, typecode, item_offset = extract_key_parts(key_val)
        local fox_field_name = get_fox_field_name(symbol)

        local entry_tree = map_tree:add(f_entry,
            buffer(offset,4),
            string.format("Entry [%d]: [%s]", i, fox_field_name))

        entry_tree:add(f_key_raw, buffer(offset,4), key_val)
        entry_tree:add(f_key_name, buffer(offset,4), fox_field_name)
        entry_tree:add(f_type, buffer(offset,4), typecode)
        entry_tree:add(f_key_offset, buffer(offset,4), item_offset)

        offset = offset + 4

        if item_offset > 0 then
            local value_offset = start + item_offset
            dissect_value(buffer, value_offset, start, entry_tree, typecode, fox_field_name, fox_fields)
        end
    end

    return byte_length
end

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
            pinfo.desegment_len = msg_len - (total_len - offset)
            pinfo.desegment_offset = offset
            return
        end

        pinfo.cols.protocol = "ESCHER_FOX"

        local subtree = tree:add(escher_proto,
            buffer(offset, msg_len),
            "Oracle ESCHER/FOX Message")

        subtree:add(f_msg_len, buffer(offset,2), msg_len)

        -- Dissect as ESCHER map (FOX message)
        local start = offset
        local byte_length = u16(buffer, offset)
        local num_items   = u16(buffer, offset+2)

        offset = offset + 4

        -- Check for FOX header and body
        local fox_type = nil
        local fox_action = nil

        for i=0, num_items-1 do
            local key_val = u32(buffer, offset)
            local symbol, typecode, item_offset = extract_key_parts(key_val)
            local fox_name = get_fox_field_name(symbol)

            if fox_name == "TYPE" and item_offset > 0 then
                local value_offset = start + item_offset
                local type_symbol = u32(buffer, value_offset)
                fox_type = decode_symbol(type_symbol)
            elseif fox_name == "ACTN" and item_offset > 0 then
                local value_offset = start + item_offset
                local action_symbol = u32(buffer, value_offset)
                fox_action = decode_symbol(action_symbol)
            end

            offset = offset + 4
        end

        -- Reset offset for full dissection
        offset = start

        -- Dissect header
        local header_len = dissect_fox_header(buffer, offset, subtree)
        offset = offset + header_len

        -- Dissect body if this is a FOX message with a body
        if fox_type and fox_action and (fox_action == "REQ" or fox_action == "ACK" or fox_action == "NACK") then
            local body_len = dissect_fox_body(buffer, offset, subtree, fox_type)
            offset = offset + body_len
        end

        return total_len
    end

    return total_len
end

-- ================= HEURISTIC REGISTRATION =================

local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(12345, escher_proto) -- Replace 12345 with the actual FOX/ESCHER port

print("Oracle ESCHER/FOX Dissector Loaded")
