-- ============================================================
-- Oracle ESCHER/FOX Protocol Dissector
-- Optimized for x86 Linux Architecture
-- ============================================================

local escher_proto = Proto("ESCHER", "Oracle ESCHER Protocol")

-- ================= CONFIG =================

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
    -- Core symbols (Network byte order on x86 = byte-swapped)
    [0x4D554E56] = "VNUM",    -- Voucher Number (byte-swapped from 0x564E554D)
    [0x46455241] = "AREF",    -- Account Reference
    [0x544C4157] = "WALT",    -- Wallet ID
    [0x59544341] = "ACTY",    -- Account Type
    [0x204D554E] = "NUM",     -- Number
    [0x20494C43] = "CLI",     -- Calling Line ID
    [0x2020204E] = "DN",      -- Dialed Number
    [0x4C535245] = "ERSL",    -- Preferred Reservation Length
    [0x43455250] = "PREC",    -- Precision
    [0x43534944] = "DISC",    -- Discount
    [0x20524443] = "CDR",     -- CDR Array
    [0x20474154] = "TAG",     -- Tag
    [0x204C4156] = "VAL",     -- Value
    [0x5353434C] = "CLSS",    -- Class
    [0x454D414E] = "NAME",    -- Name
    [0x2058414D] = "MAX",     -- Maximum
    [0x204E494D] = "MIN",     -- Minimum
    [0x524C4157] = "WALR",    -- Wallet Reference
    [0x204F5054] = "TPO",     -- Tariff Plan Override
    [0x20205A54] = "TZ",      -- Time Zone
    [0x44495053] = "SPID",    -- Service Provider ID
    [0x52554355] = "UCUR",    -- User Currency
    [0x524F4342] = "BCOR",    -- Balance Cascade Override
    [0x20435343] = "CSC",     -- Charging Service Code
    [0x45544144] = "DATE",    -- Date
    [0x4E534552] = "RESN",    -- Reason
    [0x54574F4C] = "LOWT",    -- Low Credit Beep Time
    [0x41574F4C] = "LOWA",    -- Low Credit Announcement
    [0x444F4354] = "TCOD",    -- Tariff Code
    [0x20544F54] = "TOT",     -- Time Left
    [0x20444346] = "FCD",     -- Free Call Directive
    [0x45444F43] = "CODE",    -- Error Code
    [0x54414857] = "WHAT",    -- Error Message
    [0x50595442] = "BTYP",    -- Balance Type
    [0x544E5542] = "BUNT",    -- Balance Unit
    [0x544D494C] = "LIMT",    -- Limit Type
    [0x544F5453] = "STOT",    -- Sum Total
    [0x544F5455] = "UTOT",    -- User Total
    [0x53544B42] = "BKTS",    -- Buckets
    [0x52505845] = "EXPR",    -- Expiry
    [0x4553554C] = "LUSE",    -- Last Use
    [0x54415453] = "STAT",    -- State
    [0x434E494D] = "MINC",    -- Min Credit
    [0x4358414D] = "MAXC",    -- Max Concurrent
    [0x52554353] = "SCUR",    -- System Currency
    [0x56544341] = "ACTV",    -- Activation
    [0x534C4142] = "BALS",    -- Balances
    [0x41414252] = "RBAA",    -- Recharge Balance Array
    [0x464E4956] = "VINF",    -- Voucher Info
    [0x41494252] = "RBIA",    -- Recharge Bucket Info Array
    [0x50455242] = "BREP",    -- Balance Replace
    [0x50584542] = "BEXP",    -- Balance Expiry
    [0x54584542] = "BEXT",    -- Balance Extension
    [0x44494B42] = "BKID",    -- Bucket ID
    [0x57454E42] = "BNEW",    -- New Bucket
    [0x4C4F5042] = "BPOL",    -- Balance Policy
    [0x4F50424D] = "MBPO",    -- Missing Balance Policy
    [0x44494256] = "VBID",    -- Voucher Batch ID
    [0x52484356] = "VCHR",    -- Voucher ID
    [0x4C4F5041] = "APOL",    -- Account Policy
    [0x54584541] = "AEXT",    -- Account Extension
    [0x4F505244] = "DBPO",    -- Default Bucket Policy
    [0x54534F43] = "COST",    -- Cost
    [0x49565242] = "RBVI",    -- Recharge Balance Voucher Info
    [0x2045424F] = "OBE",     -- Old Balance Expiry
    [0x2045424E] = "NBE",     -- New Balance Expiry
    [0x48435642] = "BVCH",    -- Balance Value Change
    [0x20205749] = "WI",      -- Wallet Info
    [0x4D464E43] = "CNFM",    -- Confirmation
    [0x55514552] = "REQU",    -- Requested
    [0x56525352] = "RSRV",    -- Reserved
    [0x464C4D54] = "TMLF",    -- Reservation Lifetime
    [0x4E525544] = "DURN",    -- Duration
    [0x45544152] = "RATE",    -- Rate
    [0x50465344] = "NSFP",    -- No Sufficient Funds Policy
    [0x4C534350] = "PCSL",    -- Pre-Condition States
    [0x20425749] = "IWB",     -- Ignore Wallet Balance
    [0x544E4D41] = "AMNT",    -- Amount
    [0x434C4142] = "BALC",    -- Balance Cascade
    [0x4F4D5642] = "BVMO",    -- Balance Validity Modification
    [0x50595457] = "WTYP",    -- Wallet Type
    [0x4F4D5657] = "WVMO",    -- Wallet Validity Modification
    [0x44494D43] = "CMID",    -- Request Number
    [0x44495653] = "SVID",    -- Server ID
    [0x43455355] = "USEC",    -- Microseconds
    [0x20524556] = "VER",     -- Version
    [0x20505544] = "DUP",     -- Duplicate
    [0x4E544341] = "ACTN",    -- Action
    [0x45505954] = "TYPE",    -- Type
    [0x44414548] = "HEAD",    -- Header
    [0x59444F42] = "BODY",    -- Body
    [0x4E514553] = "SEQN",    -- Sequence Number
    [0x4447534D] = "MSGD",    -- Message ID
    [0x53524556] = "VERS",    -- Version
    [0x454D4954] = "TIME",    -- Time
    [0x4C494154] = "TAIL",    -- Tail
    [0x20205649] = "ID",      -- ID
    [0x20444942] = "BID",     -- Batch ID
    [0x20444953] = "SID",     -- Server ID
    [0x534C4156] = "VALS",    -- Values Array
    [0x4D554E53] = "SNUM",    -- Serial Number
    [0x55584541] = "AEXU",    -- Account Expiry Unit
    [0x44494352] = "RCID",    -- Recharge ID
    [0x49534D49] = "IMSI",    -- IMSI
    [0x54434341] = "ACCT",    -- Account
    [0x52525543] = "CURR",    -- Currency
    [0x54414452] = "RDAT",    -- Redeem Date
    [0x49544C57] = "WLTI",    -- Wallet Info
    [0x4E454353] = "SCEN",    -- Scenario
    [0x49484356] = "VCHI",    -- Voucher Info
    [0x4E555056] = "VPUN",    -- Voucher Punch
    [0x4E544345] = "ECTN",    -- Exception
    [0x444F4345] = "ECOD",    -- Error Code
    [0x47534D45] = "EMSG",    -- Error Message
    [0x50595445] = "ETYP",    -- Error Type
    [0x4B545345] = "ESTK",    -- Error Stack
    [0x4E505352] = "RSPN",    -- Response
    [0x4154454D] = "META",    -- Metadata
    [0x48435442] = "BTCH",    -- Batch
    [0x504D4143] = "CAMP",    -- Campaign
    [0x53474154] = "TAGS",    -- Tags
    [0x4E4C5054] = "TPLN",    -- Tax Plan
    [0x434E4954] = "TINC",    -- Tax Inclusive
    [0x4D4F4354] = "TCOM",    -- Tax Components
    [0x4D414E54] = "TNAM",    -- Tax Name
    [0x4C415654] = "TVAL",    -- Tax Value
    [0x43534544] = "DESC",    -- Description
    [0x45544F4E] = "NOTE",    -- Note
    [0x4C415642] = "VBAL",    -- Voucher Balance
}

-- ================= FOX MESSAGE TYPES =================

local FOX_MESSAGE_TYPES = {
    ["BEG "] = "Begin",
    ["IR  "] = "Initial Reserve Seconds",
    ["SR  "] = "Subsequent Reserve Seconds",
    ["CR  "] = "Debit Seconds & Release",
    ["RR  "] = "Release Seconds",
    ["WGR "] = "Wallet General Recharge",
    ["WI  "] = "Wallet Info",
    ["WU  "] = "Wallet Update",
    ["VI  "] = "Voucher Info",
    ["VU  "] = "Voucher Update",
    ["VR  "] = "Voucher Reserve",
    ["CVR "] = "Commit Voucher Reservation",
    ["RVR "] = "Revoke Voucher Reservation",
    ["VTRC"] = "Voucher Type Reservation Commit",
    ["EXCP"] = "Exception",
    ["ABRT"] = "Abort",
}

-- ================= FIELD DEFINITIONS =================

local f_msg_len    = ProtoField.uint32("escher.msg_len", "Message Length", base.DEC)
local f_length     = ProtoField.uint16("escher.length", "Container Length", base.DEC)
local f_num_items  = ProtoField.uint16("escher.num_items", "Number of Items", base.DEC)
local f_ext_length = ProtoField.uint32("escher.ext_length", "Extended Length", base.DEC)
local f_ext_items  = ProtoField.uint32("escher.ext_items", "Extended Items", base.DEC)
local f_extended   = ProtoField.bool("escher.extended", "Extended Format")
local f_dirty      = ProtoField.bool("escher.dirty", "Dirty Flag")
local f_type       = ProtoField.uint8("escher.type", "Type Code", base.HEX, {
    [0x00]="NULL", [0x01]="INT", [0x02]="DATE", [0x03]="SYMBOL",
    [0x04]="FLOAT", [0x05]="STRING", [0x06]="ARRAY", [0x07]="MAP", [0x08]="RAW"
})

local f_key_raw      = ProtoField.uint32("escher.key.raw", "Raw Key", base.HEX)
local f_key_symbol   = ProtoField.string("escher.key.symbol", "Symbol")
local f_key_name     = ProtoField.string("escher.key.name", "Field Name")
local f_key_offset   = ProtoField.uint32("escher.key.offset", "Value Offset", base.DEC)
local f_array_index  = ProtoField.uint16("escher.array.index", "Index Value", base.HEX)

local f_int          = ProtoField.int32("escher.int", "Integer Value", base.DEC)
local f_float        = ProtoField.double("escher.float", "Float Value")
local f_string_len   = ProtoField.uint16("escher.string_len", "String Length", base.DEC)
local f_string       = ProtoField.string("escher.string", "String Value")
local f_date         = ProtoField.absolute_time("escher.date", "Date Value")
local f_symbol_val   = ProtoField.string("escher.symbol", "Symbol Value")
local f_raw_len      = ProtoField.uint32("escher.raw_len", "Raw Length", base.DEC)
local f_raw          = ProtoField.bytes("escher.raw", "Raw Data")

local f_fox_type     = ProtoField.string("escher.fox.type", "FOX Message Type")
local f_fox_action   = ProtoField.string("escher.fox.action", "FOX Action")

escher_proto.fields = {
    f_msg_len, f_length, f_num_items, f_ext_length, f_ext_items,
    f_extended, f_dirty, f_type,
    f_key_raw, f_key_symbol, f_key_name, f_key_offset, f_array_index,
    f_int, f_float, f_string_len, f_string, f_date, f_symbol_val,
    f_raw_len, f_raw, f_fox_type, f_fox_action,
}

-- ================= HELPERS =================

local function align(x)
    return bit.band(x + ALIGN_SIZE - 1, bit.bnot(ALIGN_SIZE - 1))
end

local function is_dirty(x)
    return bit.band(x, NEW_DIRTY_MASK) == NEW_DIRTY_MASK
end

local function decode_symbol(val)
    -- x86 is little-endian, but Escher stores symbols in network byte order
    -- So we need to byte-swap for display
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
    
    -- For x86, bytes are already in network order after reading with :uint()
    -- So we display them in the order: MSB to LSB
    return to_char(c1) .. to_char(c2) .. to_char(c3) .. to_char(c4)
end

local function extract_key_parts(key)
    -- Map key format: symbol (19 bits) | type (4 bits) | offset (9 bits)
    local symbol = bit.band(key, 0xffffe000)
    local typecode = bit.band(bit.rshift(key, 9), 0x0f)
    local offset = bit.lshift(bit.band(key, 0x1ff), 2)
    return symbol, typecode, offset
end

local function get_fox_field_name(symbol)
    return FOX_SYMBOLS[symbol] or decode_symbol(symbol)
end

-- ================= VALUE DISSECTION =================

local function dissect_value(buffer, offset, tree, typecode)
    local bytes_consumed = 0
    
    if typecode == NULL_TYPE then
        tree:add(f_type, buffer(offset, 0), typecode)
        bytes_consumed = 0
        
    elseif typecode == INT_TYPE then
        if offset + 4 > buffer:len() then return 0 end
        -- x86 reads in network byte order (big-endian)
        local value = buffer(offset, 4):int()
        tree:add(f_int, buffer(offset, 4), value)
        bytes_consumed = 4
        
    elseif typecode == FLOAT_TYPE then
        if offset + 8 > buffer:len() then return 0 end
        -- Floats are stored in network-converted format
        local value = buffer(offset, 8):le_float64()
        tree:add(f_float, buffer(offset, 8), value)
        bytes_consumed = 8
        
    elseif typecode == STRING_TYPE then
        if offset + 1 > buffer:len() then return 0 end
        local strlen = buffer(offset, 1):uint()
        local str_offset = 1
        
        if bit.band(strlen, 0x80) ~= 0 then
            if offset + 2 > buffer:len() then return 0 end
            strlen = bit.band(buffer(offset, 2):uint(), 0x7fff)
            str_offset = 2
        end
        
        tree:add(f_string_len, buffer(offset, str_offset), strlen)
        
        if strlen > 0 and (offset + str_offset + strlen) <= buffer:len() then
            local str = buffer(offset + str_offset, strlen):string()
            tree:add(f_string, buffer(offset + str_offset, strlen), str)
        end
        
        bytes_consumed = align(str_offset + strlen)
        
    elseif typecode == DATE_TYPE then
        if offset + 4 > buffer:len() then return 0 end
        local timestamp = buffer(offset, 4):uint()
        tree:add(f_date, buffer(offset, 4), timestamp)
        bytes_consumed = 4
        
    elseif typecode == SYMBOL_TYPE then
        if offset + 4 > buffer:len() then return 0 end
        local symbol_val = buffer(offset, 4):uint()
        local symbol_str = get_fox_field_name(symbol_val)
        tree:add(f_symbol_val, buffer(offset, 4), symbol_str)
        bytes_consumed = 4
        
    elseif typecode == RAW_TYPE then
        if offset + 4 > buffer:len() then return 0 end
        local raw_len = buffer(offset, 4):uint()
        tree:add(f_raw_len, buffer(offset, 4), raw_len)
        
        if raw_len > 0 and (offset + 4 + raw_len) <= buffer:len() then
            tree:add(f_raw, buffer(offset + 4, raw_len))
        end
        
        bytes_consumed = align(4 + raw_len)
        
    elseif typecode == ARRAY_TYPE then
        local array_bytes = dissect_array(buffer, offset, tree)
        bytes_consumed = array_bytes
        
    elseif typecode == MAP_TYPE then
        local map_bytes = dissect_map(buffer, offset, tree)
        bytes_consumed = map_bytes
    end
    
    return bytes_consumed
end

-- ================= ARRAY DISSECTION =================

function dissect_array(buffer, offset, tree)
    if offset + 4 > buffer:len() then return 0 end
    
    local start_offset = offset
    local array_tree = tree:add(buffer(offset), "Array")
    
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
    
    if offset + 4 > buffer:len() then return 4 end
    
    -- Read array header
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
            return 4
        end
        
        byte_length = buffer(offset, 2):uint()
        num_items = buffer(offset + 2, 2):uint()
        array_tree:add(f_length, buffer(offset, 2), byte_length)
        array_tree:add(f_num_items, buffer(offset + 2, 2), num_items)
        offset = offset + 4
    else
        return 4
    end
    
    local items_start = offset
    
    for i = 0, num_items - 1 do
        if offset + 2 > buffer:len() then break end
        
        local entry_tree = array_tree:add(buffer(offset), string.format("[%d]", i))
        
        local index_val = buffer(offset, 2):uint()
        entry_tree:add(f_array_index, buffer(offset, 2), index_val)
        
        local typecode = bit.band(bit.rshift(index_val, 9), 0x0f)
        local item_offset = bit.lshift(bit.band(index_val, 0x1ff), 2)
        
        entry_tree:add(f_type, buffer(offset, 2), typecode)
        
        offset = offset + 2
        
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < buffer:len() then
                dissect_value(buffer, value_offset, entry_tree, typecode)
            end
        end
    end
    
    return byte_length
end

-- ================= MAP DISSECTION =================

function dissect_map(buffer, offset, tree)
    if offset + 4 > buffer:len() then return 0 end
    
    local start_offset = offset
    local map_tree = tree:add(buffer(offset), "Map")
    
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
    
    if offset + 4 > buffer:len() then return 4 end
    
    -- Read map header
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
            return 4
        end
        
        byte_length = buffer(offset, 2):uint()
        num_items = buffer(offset + 2, 2):uint()
        map_tree:add(f_length, buffer(offset, 2), byte_length)
        map_tree:add(f_num_items, buffer(offset + 2, 2), num_items)
        offset = offset + 4
    else
        return 4
    end
    
    local items_start = offset
    
    for i = 0, num_items - 1 do
        if offset + 4 > buffer:len() then break end
        
        local key_val = buffer(offset, 4):uint()
        local symbol, typecode, item_offset = extract_key_parts(key_val)
        local symbol_str = get_fox_field_name(symbol)
        
        local entry_tree = map_tree:add(buffer(offset), string.format("%s", symbol_str))
        
        entry_tree:add(f_key_raw, buffer(offset, 4), key_val)
        entry_tree:add(f_key_name, buffer(offset, 4), symbol_str)
        entry_tree:add(f_type, buffer(offset, 4), typecode)
        
        offset = offset + 4
        
        if item_offset > 0 then
            local value_offset = items_start + item_offset
            if value_offset < buffer:len() then
                dissect_value(buffer, value_offset, entry_tree, typecode)
            end
        end
    end
    
    return byte_length
end

-- ================= MAIN DISSECTOR =================

function escher_proto.dissector(buffer, pinfo, tree)
    if buffer:len() < 4 then return 0 end
    
    pinfo.cols.protocol = "ESCHER"
    
    local subtree = tree:add(escher_proto, buffer(), "Oracle ESCHER Protocol")
    
    -- Decode entire message structure
    local bytes_dissected = dissect_map(buffer, 0, subtree)
    
    -- Set info column
    pinfo.cols.info = string.format("ESCHER Message (%d bytes)", buffer:len())
    
    return bytes_dissected
end

-- ================= REGISTRATION =================

local tcp_port = DissectorTable.get("tcp.port")
local udp_port = DissectorTable.get("udp.port")

tcp_port:add(5000, escher_proto)
tcp_port:add(5001, escher_proto)
udp_port:add(5000, escher_proto)
udp_port:add(5001, escher_proto)

print("Oracle ESCHER Protocol Dissector Loaded (x86 Linux Optimized)")