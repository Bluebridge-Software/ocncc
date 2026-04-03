-- ============================================================
-- ESCHER Protocol Dissector
--
-- Copyright © 2026 Blue Bridge Software Ltd. All rights reserved.
--
-- This material is the confidential property of Blue Bridge Software Ltd
-- or its licensors and may be used, reproduced, stored or transmitted
-- only in accordance with a valid Blue Bridge Software Ltd license or
-- sublicense agreement.
-- ============================================================
--
-- PROTOCOL STRUCTURE (all integers big-endian, no separate framing layer):
--
--   The entire TCP payload is a single ESCHER MAP.
--   There is NO separate framing header before the map.
--
-- ESCHER MAP (standard):
--   [0:2]  u16  total_byte_length  (including this header)
--   [2:4]  u16  num_items
--   [4:8]  u32  internal_ptr       (0x00000000 = clean/unmodified in wire data)
--   [8:]         index entries, 4 bytes each:
--                  bits [31:13]  symbol value   (19 bits, decoded as 4-char base-27 string)
--                  bits [12:9]   typecode       (4 bits)
--                  bits  [8:0]   data_offset    (9 bits, in 4-byte words from MAP START)
--
-- ESCHER MAP (extended, magic = 0xFFFE):
--   [0:2]  u16  0xFFFE             extended-map magic
--   [2:4]  u16  control_block      (bit 2 of byte[3] = extended-index flag)
--   [4:8]  u32  total_byte_length
--   [8:12] u32  num_items
--   [12:]        index entries, 4 or 8 bytes each (8 if extended index)
--
-- ESCHER ARRAY (standard):
--   [0:2]  u16  total_byte_length
--   [2:4]  u16  num_items
--   [4:8]  u32  internal_ptr
--   [8:]         2-byte index entries:
--                  bits [12:9]  typecode    (4 bits — same field positions)
--                  bits  [8:0]  data_offset (9 bits, in 4-byte words from ARRAY START)
--
-- TYPECODES (PCAP):
--   0  = NULL
--   1  = INT32    (4 bytes, big-endian signed)
--   2  = DATE     (4 bytes, unsigned unix timestamp)
--   3  = SYMBOL   (4 bytes, base-27 encoded 4-char string)
--   4  = FLOAT64  (8 bytes; byte-reversed on Linux before wire — reverse to decode)
--   5  = STRING   (1 or 2 byte length prefix + UTF-8 + 4-byte-aligned padding)
--   6  = ARRAY    (nested ESCHER ARRAY container)
--   8  = RAW      (4-byte u32 length + raw bytes + 4-byte-aligned padding)
--   9  = INT64    (8 bytes, big-endian signed — observed in PCAP)
--   12 = MAP      (nested ESCHER MAP — ESCHER_MAP_TYPE enum value is 12, NOT 7)
--
-- SYMBOL ENCODING:
--   Alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ " (A=0 ... Z=25, SPACE=26)
--   char1 = floor(val / 161243136) % 27
--   char2 = floor(val /   5971968) % 27
--   char3 = floor(val /    221184) % 27
--   char4 = floor(val /      8192) % 27
--   Trailing spaces are meaningful: "WI  ", "REQ ", "DUP " are distinct symbols.
--
-- OBSERVED MESSAGE PATTERNS (port 1500):
--   Heartbeat:  {BODY=Map{}, HEAD=Map{}, TYPE='HTBT'}
--   Request:    {ACTN='REQ ', BODY=Map{...}, HEAD=Map{CMID,DATE,DUP ,SVID,USEC,VER }, TYPE='WI  '}
--   Exception:  {ACTN='EXCP', BODY=Map{CODE,WHAT}, HEAD=Map{...}, TYPE='PROC'}
-- ============================================================

local escher_proto = Proto("ESCHER", "ESCHER Protocol")

-- ============================================================
-- Protocol fields
-- ============================================================
local f_map_total     = ProtoField.uint16("escher.map.total",       "Map Total Bytes",   base.DEC)
local f_map_ext_len   = ProtoField.uint32("escher.map.ext_len",     "Map Total Bytes",   base.DEC)
local f_map_items     = ProtoField.uint16("escher.map.items",       "Map Item Count",    base.DEC)
local f_map_ext_items = ProtoField.uint32("escher.map.ext_items",   "Map Item Count",    base.DEC)
local f_map_ptr       = ProtoField.uint32("escher.map.ptr",         "Internal Ptr",      base.HEX)
local f_ext_magic     = ProtoField.uint16("escher.map.ext_magic",   "Ext Map Magic",     base.HEX)
local f_ext_ctrl      = ProtoField.uint16("escher.map.ext_ctrl",    "Ext Control Block", base.HEX)
local f_entry_raw     = ProtoField.uint32("escher.entry.raw",       "Index Entry",       base.HEX)
local f_val_int32     = ProtoField.int32 ("escher.val.int32",       "Int32",             base.DEC)
local f_val_int64     = ProtoField.int64 ("escher.val.int64",       "Int64",             base.DEC)
local f_val_float     = ProtoField.bytes ("escher.val.float",       "Float64 (raw bytes)")
local f_val_string    = ProtoField.string("escher.val.string",      "String")
local f_val_symbol    = ProtoField.string("escher.val.symbol",      "Symbol")
local f_val_date      = ProtoField.string("escher.val.date",         "Date")
local f_val_raw       = ProtoField.bytes ("escher.val.raw",         "Raw Data")
local f_val_null      = ProtoField.string("escher.val.null",        "Null")
local f_sym           = ProtoField.string("escher.sym",             "Symbol")
local f_field_label   = ProtoField.string("escher.field_label",     "Field Label")

local fields = {
    f_map_total, f_map_ext_len, f_map_items, f_map_ext_items, f_map_ptr,
    f_ext_magic, f_ext_ctrl, f_entry_raw,
    f_val_int32, f_val_int64, f_val_float, f_val_string, f_val_symbol,
    f_val_date, f_val_raw, f_val_null,
    f_sym, f_field_label,
}
-- SYMBOL_PROTO_FIELDS is defined later but we will populate this table before the dissector runs.
-- However, since Lua script is executed top-to-bottom, we need to ensure the order is right.
-- I will move the fields registration AFTER the SYMBOL_PROTO_FIELDS definition.

-- ============================================================
-- Symbol decoder  (matches Symbol::toString in the C++ source)
-- ============================================================
local ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

local function decode_symbol(val)
    -- bit.band() returns a signed 32-bit integer in Wireshark's Lua.
    -- Symbol values >= 0x80000000 come back negative, making the divisions wrong.
    -- Adding 2^32 recovers the correct unsigned value without losing precision
    -- (Lua 5.1 numbers are IEEE-754 doubles with 53-bit mantissa, enough for u32).
    if val < 0 then val = val + 4294967296 end  -- 4294967296 = 2^32
    local r1 = math.floor(val / 161243136) % 27 + 1
    local r2 = math.floor(val /   5971968) % 27 + 1
    local r3 = math.floor(val /    221184) % 27 + 1
    local r4 = math.floor(val /      8192) % 27 + 1
    -- Return all 4 chars including trailing spaces — they are significant.
    return ALPHABET:sub(r1,r1) .. ALPHABET:sub(r2,r2)
        .. ALPHABET:sub(r3,r3) .. ALPHABET:sub(r4,r4)
end

-- ============================================================
-- Format a unix timestamp as "YYYYMMDDHHMMSS (raw_value)"
-- Computed manually - os.date is unreliable in Wireshark's Lua sandbox.
-- ============================================================
local function format_timestamp(ts)
    local days   = math.floor(ts / 86400)
    local rem    = ts % 86400
    local hh     = math.floor(rem / 3600)
    local mm     = math.floor((rem % 3600) / 60)
    local ss     = rem % 60

    -- Walk forward from 1970 to find the year
    local year = 1970
    while true do
        local leap  = (year % 4 == 0) and (year % 100 ~= 0 or year % 400 == 0)
        local ydays = leap and 366 or 365
        if days < ydays then break end
        days = days - ydays
        year = year + 1
    end

    -- Walk forward through months
    local leap  = (year % 4 == 0) and (year % 100 ~= 0 or year % 400 == 0)
    local mdays = {31, leap and 29 or 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    local month = 1
    for m = 1, 12 do
        if days < mdays[m] then month = m; break end
        days = days - mdays[m]
    end
    local day = days + 1   -- convert 0-based remainder to 1-based day

    return string.format("%04d%02d%02d%02d%02d%02d (%u)",
                         year, month, day, hh, mm, ss, ts)
end

-- ============================================================
-- Typecode name table
-- ============================================================
local TYPE_NAMES = {
    [0]  = "NULL",
    [1]  = "INT32",
    [2]  = "DATE",
    [3]  = "SYMBOL",
    [4]  = "FLOAT64",
    [5]  = "STRING",
    [6]  = "ARRAY",
    [8]  = "RAW",
    [9]  = "INT64",
    [11] = "LIST",
    [12] = "MAP",
}

-- ============================================================
-- Forward declarations (mutual recursion: map <-> array <-> value)
-- ============================================================
-- Display label lookup table: ESCHER symbol -> human-readable name
-- Derived from escherBridge.cc hf_register_info and field definitions.
-- Symbols not in this table fall back to the raw 4-char symbol name.
-- ============================================================
local FIELD_LABELS = {
    ["AASS"] = "Allow All Subscription States",
    ["ABAL"] = "Alter Balance",
    ["ABID"] = "Account Batch ID",
    ["ACFB"] = "Apply Config File Bonus",
    ["ACTN"] = "FOX Action",
    ["ACTV"] = "Activation Date",
    ["ACTY"] = "Account Type",
    ["AEXP"] = "Account Expiry",
    ["AEXT"] = "Account Expiry Extension",
    ["AEXU"] = "Account Expiry Extension Unit",
    ["AMNT"] = "Preferred Amount",
    ["APOL"] = "Account Expiry Policy",
    ["AREF"] = "Account Reference",
    ["ASWS"] = "NACK: Bad Allowed Source Wallet States",
    ["ATC "] = "Apply Tariffed Charge",
    ["AVOU"] = "NACK: Ambiguous Voucher",
    ["AXPB"] = "Acct Expiry Policy: Best",
    ["AXPC"] = "Acct Expiry Policy: Extend From Current",
    ["AXPE"] = "Acct Expiry Policy: Extension",
    ["AXPI"] = "Acct Expiry Policy: Ignore",
    ["AXPO"] = "Acct Expiry Policy: Override",
    ["AXPT"] = "Acct Expiry Policy: Extend From Today",
    ["BALC"] = "Balance Type Cascade",
    ["BALS"] = "Balances",
    ["BASE"] = "Base (currency)",
    ["BBDS"] = "NACK: Wallet Batch Disabled",
    ["BCD "] = "Batch CDR Description",
    ["BCMP"] = "Bonus Component",
    ["BCOR"] = "Balance Cascade Override",
    ["BDLT"] = "Balance Delta",
    ["BDVR"] = "NACK: Bad Recharge Attempt",
    ["BDVV"] = "NACK: Bad Voucher Value",
    ["BEXM"] = "Balance Expiry Extension Months",
    ["BEXP"] = "Balance Expiry",
    ["BEXT"] = "Balance Expiry Extension",
    ["BEXU"] = "Balance Expiry Extension Unit",
    ["BKID"] = "Bucket ID",
    ["BKOV"] = "NACK: Bucket Overflow",
    ["BKTS"] = "Buckets",
    ["BNEW"] = "New Bucket",
    ["BODY"] = "Body",
    ["BOVR"] = "Override Date",
    ["BPIN"] = "Bad PIN",
    ["BPOL"] = "Balance Expiry Policy",
    ["BQUA"] = "Bill Quanta",
    ["BREP"] = "Replace Balance",
    ["BSCN"] = "NACK: Bad Scenario",
    ["BSDE"] = "Balance Start Date Extension",
    ["BSDU"] = "Balance Start Date Extension Unit",
    ["BSWS"] = "NACK: Bad Source Wallet State",
    ["BSYM"] = "Big Unit Symbol",
    ["BTOR"] = "Balance Type Override",
    ["BTRA"] = "Balance Type Reserved Value Array",
    ["BTRV"] = "Balance Type Reserved Value",
    ["BTWS"] = "NACK: Bad Target Wallet State",
    ["BTYP"] = "Balance Type",
    ["BUNT"] = "Balance Unit",
    ["BVCH"] = "Balance Value Change",
    ["BVMD"] = "Balance Validity Date",
    ["BVMO"] = "Balance Validity Modification",
    ["BXPB"] = "Bal Expiry Policy: Best",
    ["BXPE"] = "Bal Expiry Policy: Extension",
    ["BXPI"] = "Bal Expiry Policy: Ignore",
    ["BXPO"] = "Bal Expiry Policy: Override",
    ["BXPT"] = "Bal Expiry Policy: Extend From Today",
    ["CALI"] = "Call ID",
    ["CARR"] = "Confirm Amount Reservation",
    ["CASD"] = "CASD",
    ["CDAT"] = "Call Date (GMT)",
    ["CDR "] = "Call Detail Record",
    ["CLI "] = "Calling Line Identifier",
    ["CLSS"] = "Class",
    ["CMID"] = "Request Number (CMID)",
    ["CNER"] = "Confirm Named Event Reservation",
    ["CNFM"] = "Confirmed Amount",
    ["CODE"] = "Code",
    ["COST"] = "Costs",
    ["CR  "] = "Commit Reservation",
    ["CRIS"] = "NACK: Call Restricted",
    ["CRTD"] = "Voucher State: Created",
    ["CSC "] = "Charging Service Code",
    ["CSTS"] = "Costs Array",
    ["CVR "] = "Commit Voucher Redeem",
    ["DA  "] = "Direct Amount",
    ["DATE"] = "Call Date",
    ["DBAL"] = "Delete Balance",
    ["DBKP"] = "Default Bucket Policy",
    ["DBPD"] = "Default Bucket Policy: Ignore",
    ["DDAM"] = "Direct Delta Amount",
    ["DELT"] = "Delta Amount",
    ["DISC"] = "Discount",
    ["DISO"] = "Discount Override",
    ["DLKW"] = "Delete Locked Wallet",
    ["DLRM"] = "Dont Log Remove Wallet",
    ["DLTD"] = "Voucher State: Deleted",
    ["DN  "] = "Dialled Number",
    ["DSOT"] = "Discount Type",
    ["DUP "] = "Duplicate Flag",
    ["DURN"] = "Durations",
    ["ERSL"] = "Expected Reservation Length",
    ["EVTS"] = "Named Events Array",
    ["EXCP"] = "Exception",
    ["EXPR"] = "Expiry Date",
    ["FCD "] = "Free Call Disposition",
    ["FRZN"] = "Voucher State: Frozen",
    ["GRAP"] = "Grace Period",
    ["HEAD"] = "Header",
    ["HON "] = "Free Call: Honour",
    ["HOUR"] = "Hours",
    ["HTBT"] = "Heartbeat",
    ["HUND"] = "Hundredths",
    ["IARR"] = "Initial Amount Reservation",
    ["IBWE"] = "Ignore Balance/Wallet Extension",
    ["ICDA"] = "Is Change Daemon",
    ["ID  "] = "ID",
    ["IDOT"] = "NACK: Invalid Discount Override Type",
    ["IERR"] = "NACK: Merge Wallets Internal Error",
    ["IGNR"] = "Free Call: Ignore",
    ["INCL"] = "Tax Inclusive",
    ["INER"] = "Initial Named Event Reservation",
    ["INSF"] = "NACK: Insufficient Funds",
    ["INVD"] = "NACK: Invalid Voucher Digits",
    ["IR  "] = "Initial Reservation",
    ["IWB "] = "Ignore Wallet Balance",
    ["IWS "] = "Ignore Wallet State",
    ["IXNS"] = "Ignore Not Subscribed",
    ["LDMF"] = "Reload MFile",
    ["LIFE"] = "Reservation Lifetime",
    ["LIMT"] = "Limit Type",
    ["LOCK"] = "Lock (milliseconds)",
    ["LOIU"] = "Lock Only If Unreserved",
    ["LOWA"] = "Low Balance Announcement",
    ["LOWC"] = "Low Credit",
    ["LOWT"] = "Low Threshold",
    ["LSYM"] = "Little Unit Symbol",
    ["LUPT"] = "Last Update Time",
    ["LUPU"] = "Last Update Usec",
    ["LUSE"] = "Last Use",
    ["LVOU"] = "NACK: Limited Voucher",
    ["MAX "] = "Maximum",
    ["MAXC"] = "Max Concurrent",
    ["MAXL"] = "NACK: Max Call Length Exceeded",
    ["MBEP"] = "NACK: Bad Merge Bucket Expiry Policy",
    ["MBPA"] = "Missing Balance Policy: Allow",
    ["MBPF"] = "Missing Balance Policy: Fail",
    ["MBPI"] = "Missing Balance Policy: Ignore",
    ["MBPO"] = "Missing Balance Policy",
    ["MCHG"] = "Max Charge",
    ["MFTY"] = "MFile Type",
    ["MGW "] = "Merge Wallets",
    ["MGWA"] = "Merge Wallets ACK",
    ["MIN "] = "Minimum",
    ["MINA"] = "Minimum Amount",
    ["MINC"] = "Minimum Credit",
    ["MINL"] = "Min Length",
    ["MLEN"] = "Max Length",
    ["MNTH"] = "Months",
    ["MWEP"] = "NACK: Bad Merge Wallet Expiry Policy",
    ["NACC"] = "NACK: No Account Type Entry",
    ["NACT"] = "New Account Type",
    ["NAME"] = "Name",
    ["NBAL"] = "New Balance",
    ["NBE "] = "New Balance Expiry",
    ["NBIL"] = "NACK: No Billing Periods",
    ["NBPN"] = "NACK: No Bad PIN Balance Type",
    ["NBTY"] = "NACK: No Balance Type",
    ["NCAS"] = "NACK: No Balance Type Cascade",
    ["NCNT"] = "NACK: No Context Data",
    ["NE  "] = "Named Event",
    ["NENA"] = "NACK: Named Event Not Allowed For Product Type",
    ["NER "] = "Named Event Rate",
    ["NGEO"] = "NACK: Geography Tree Not Defined",
    ["NODB"] = "NACK: Could Not Log Into DB",
    ["NOSC"] = "NACK: System Currency Not Defined",
    ["NRAT"] = "NACK: No Rate Info Entry",
    ["NRCH"] = "NACK: Balance Not Rechargeable",
    ["NSAT"] = "NACK: No Source Account Type ID",
    ["NSCI"] = "NACK: No Source Currency ID",
    ["NSCL"] = "NACK: No Source CLI",
    ["NSDI"] = "NACK: No Source Domain ID",
    ["NSFP"] = "NSF Policy",
    ["NSPI"] = "NACK: No Service Provider ID",
    ["NSSI"] = "NACK: No Source Subscriber ID",
    ["NSSW"] = "NACK: No Such Source Wallet",
    ["NSTW"] = "NACK: No Such Target Wallet",
    ["NSWT"] = "NACK: No Source Wallet Type ID",
    ["NTAR"] = "NACK: No Tariff Plan Selector Entry",
    ["NTAT"] = "NACK: No Target Account Type ID",
    ["NTDI"] = "NACK: No Target Domain ID",
    ["NTMR"] = "NACK: Nothing To Merge Or Relink",
    ["NTSI"] = "NACK: No Target Subscriber ID",
    ["NUM "] = "Number",
    ["NVOU"] = "NACK: Unknown Voucher",
    ["NWPE"] = "New WLC Period",
    ["NWPL"] = "New WLC Plan",
    ["OAMT"] = "Overdrawn Amount",
    ["OBE "] = "Old Balance Expiry",
    ["OBWV"] = "Override Balance/Wallet Value",
    ["OWPE"] = "Old WLC Period",
    ["OWPL"] = "Old WLC Plan",
    ["OWPT"] = "Old WLC Product Type",
    ["PCSL"] = "Precondition States",
    ["PINC"] = "Bad PIN Count",
    ["PLUG"] = "Plugin",
    ["PREC"] = "Precision",
    ["PROC"] = "Process",
    ["QSCN"] = "Query Scenarios",
    ["QTAG"] = "Quota Tag",
    ["QUOT"] = "Quota Array",
    ["QVAL"] = "Quota Value",
    ["RARF"] = "Recharging Account Reference",
    ["RARR"] = "Revoke Amount Reservation",
    ["RATA"] = "Rated Available",
    ["RATE"] = "Forex Rate",
    ["RBAA"] = "Recharge Balance Info Array",
    ["RBIA"] = "Recharge Bucket Info Array",
    ["RBVI"] = "Recharge Balance Voucher Info Array",
    ["RDMD"] = "Voucher State: Redeemed",
    ["REL "] = "Free Call: Release",
    ["REMC"] = "Remaining Charge",
    ["REQ "] = "Request",
    ["REQD"] = "NACK: Request Declined",
    ["RESA"] = "Reservation Available",
    ["RESN"] = "Reason",
    ["RESO"] = "Reservation Operation",
    ["RESP"] = "Response",
    ["RNER"] = "Revoke Named Event Reservation",
    ["RPO "] = "Reservation Period Override",
    ["RR  "] = "Revoke Reservation",
    ["RSRV"] = "Reserved Amount",
    ["RVI "] = "Return Voucher Info",
    ["RVR "] = "Revoke Voucher Redeem",
    ["RWAL"] = "Redeem Wallet",
    ["RWI "] = "Return Wallet Info",
    ["RWLT"] = "Redeeming Wallet ID",
    ["SARF"] = "Recharging Subscriber Reference",
    ["SARR"] = "Subsequent Amount Reservation",
    ["SATI"] = "Source Account Type ID",
    ["SCEN"] = "Scenario ID",
    ["SCID"] = "Source Currency ID",
    ["SCLI"] = "Source CLI",
    ["SCNM"] = "Scenario Name",
    ["SCPI"] = "SCP ID",
    ["SCTU"] = "System Currency Total Unreserved",
    ["SCUR"] = "System Currency",
    ["SDAT"] = "Set Date",
    ["SDID"] = "Source Domain ID",
    ["SDNF"] = "Start Date No Filter",
    ["SECS"] = "Seconds",
    ["SEPR"] = "Separator",
    ["SINV"] = "NACK: Invalid State",
    ["SNER"] = "Subsequent Named Event Reservation",
    ["SNIL"] = "NACK: State Not In List",
    ["SNUM"] = "Serial Number",
    ["SNUS"] = "Serial Number String",
    ["SPCP"] = "Suppress Periodic Charge Plugin",
    ["SPID"] = "Service Provider ID",
    ["SPLG"] = "Suppress Plugins",
    ["SR  "] = "Subsequent Reservation",
    ["SRTN"] = "Suppress RT Notifications",
    ["SSUB"] = "Source Subscriber ID",
    ["STAT"] = "State",
    ["STDT"] = "Start Date",
    ["STOT"] = "System Currency Total",
    ["SUBN"] = "Subscriber Reference",
    ["SVID"] = "BE Server ID",
    ["SWID"] = "Source Wallet ID",
    ["SWIR"] = "NACK: Source Wallet Is Reserved",
    ["SWNA"] = "NACK: Source Wallet Not Activated",
    ["SWTI"] = "Source Wallet Type ID",
    ["SYSF"] = "NACK: System Failure",
    ["TAG "] = "Tag",
    ["TATI"] = "Target Account Type ID",
    ["TAX "] = "Tax",
    ["TAXP"] = "Tax Plan",
    ["TCD "] = "Type CDR Description",
    ["TCOD"] = "Tariff Code",
    ["TDID"] = "Target Domain ID",
    ["TEN "] = "Tenths",
    ["TLNG"] = "NACK: Call Too Long",
    ["TMLF"] = "Session Time Left",
    ["TMNY"] = "NACK: Too Many Concurrent",
    ["TOT "] = "Total",
    ["TPO "] = "Tariff Plan Override",
    ["TRNC"] = "Truncated",
    ["TSUB"] = "Target Subscriber ID",
    ["TTHR"] = "Time Threshold",
    ["TUC "] = "Total Units Consumed",
    ["TWID"] = "Target Wallet ID",
    ["TWNR"] = "NACK: Target Wallet Not Rechargeable",
    ["TYPE"] = "FOX Type",
    ["TZ  "] = "Time Zone",
    ["UAVL"] = "Voucher State: Unavailable",
    ["UCTU"] = "User Currency Total Unreserved",
    ["UCUR"] = "User Currency",
    ["UDWS"] = "Update Wallet Status",
    ["ULCK"] = "Create Unlocked Voucher",
    ["UNIT"] = "Unit",
    ["URSV"] = "Uncommitted Reservations",
    ["USEC"] = "Micro Seconds",
    ["USR "] = "Unit Second Rate",
    ["UTOT"] = "User Currency Total",
    ["UTYP"] = "Unit Type",
    ["UVAL"] = "User Value",
    ["VAL "] = "Value",
    ["VALS"] = "Values",
    ["VARD"] = "NACK: Voucher Already Redeemed",
    ["VBID"] = "Voucher Batch ID",
    ["VBUA"] = "NACK: Voucher Batch Unavailable",
    ["VDEL"] = "NACK: Voucher Deleted",
    ["VER "] = "Protocol Version",
    ["VFRZ"] = "NACK: Voucher Frozen",
    ["VI  "] = "Voucher Information",
    ["VINF"] = "Voucher Info",
    ["VNME"] = "Voucher Type Name",
    ["VNUM"] = "Voucher Number",
    ["VPIN"] = "NACK: Voucher Auth Failed",
    ["VR  "] = "Voucher Redeem",
    ["VRW "] = "Voucher Redeem Wallet",
    ["VSCN"] = "Scenario List",
    ["VTHR"] = "Volume Threshold",
    ["VTID"] = "Voucher Type ID",
    ["VTR "] = "Voucher Type Recharge",
    ["VTRC"] = "Voucher Type Recharge Confirm",
    ["VTYP"] = "Voucher Type",
    ["VU  "] = "Voucher Update",
    ["WALR"] = "Wallet Reference",
    ["WALT"] = "Wallet ID",
    ["WBIN"] = "NACK: Wallet Batch Inactive",
    ["WC  "] = "Wallet Create",
    ["WD  "] = "Wallet Delete",
    ["WDIS"] = "NACK: Wallet Disabled",
    ["WGR "] = "Wallet General Recharge",
    ["WHAT"] = "Error Description",
    ["WI  "] = "Wallet Info",
    ["WLCG"] = "NACK: WLC General Charges Disabled",
    ["WLCN"] = "NACK: WLC Named Event Class Disabled",
    ["WLCR"] = "NACK: WLC General Recharges Disabled",
    ["WLCS"] = "NACK: WLC Session Charges Disabled",
    ["WLCT"] = "WLC Triggering Action",
    ["WNR "] = "NACK: Wallet Not Rechargeable",
    ["WR  "] = "Wallet Recharge",
    ["WRE "] = "Wallet Reservation End",
    ["WRI "] = "Wallet Reservation Info",
    ["WRS "] = "Wallet Reservation",
    ["WRSA"] = "Wallet Reservations",
    ["WSI "] = "Wallet State Information",
    ["WTSP"] = "Wallet Service Provider",
    ["WTYP"] = "Wallet Type",
    ["WU  "] = "Wallet Update",
    ["WUCC"] = "Wallet Update CDR Create Flag",
    ["WVMD"] = "Wallet Validity Date",
    ["WVMO"] = "Wallet Validity Modification",
    ["XBAB"] = "WGR Exception: Bad Missing Account Policy",
    ["XBAP"] = "WGR Exception: Bad Acct Expiry Ext Type",
    ["XBB "] = "WGR Exception: Bad Bucket",
    ["XBBP"] = "WGR Exception: Bad Balance Expiry Ext Type",
    ["XBES"] = "WGR Exception: Bad Balance Start Date Extension",
    ["XBMB"] = "WGR Exception: Bad Missing Balance Policy",
    ["XBSE"] = "WGR Exception: Bad Balance Start Date Ext Type",
    ["XEBI"] = "WGR Exception: Empty Bucket Info",
    ["XERI"] = "WGR Exception: Empty Recharge Info",
    ["XFU "] = "WU Exception: Failed Update",
    ["XMBI"] = "WGR Exception: Missing Bucket Info",
    ["XMRI"] = "WGR Exception: Missing Recharge Info",
    ["XNNC"] = "Exception: No Currency",
    ["XNS "] = "WU Exception: Not Subscribed",
    ["XWAF"] = "Exception: Wallet Activation Failure",
    ["XWR "] = "Exception: Wallet Reserved",
    -- VWARS symbols
    ["ACK "] = "Acknowledgement",
    ["ACTW"] = "Activate Wallet",
    ["AGGR"] = "Aggregate Buckets",
    ["ALLS"] = "All Contexts Sent",
    ["CBAL"] = "Create Balance Array",
    ["CBKT"] = "Create Bucket Array",
    ["CCXT"] = "Create Context",
    ["CDRS"] = "CDRs",
    ["CHRG"] = "Charge",
    ["CKIE"] = "Cookies",
    ["CLAS"] = "Object Class",
    ["CLID"] = "Client ID",
    ["CLUS"] = "Last Use Date Changed",
    ["CMD "] = "Command",
    ["CMDT"] = "Command Type",
    ["CREA"] = "Create",
    ["CRES"] = "Commit Reservation (VWARS)",
    ["CRPT"] = "Exception: Corrupt Message",
    ["CSDT"] = "Consolidate Balance",
    ["CSVR"] = "Create Server Route",
    ["CTXT"] = "Message Context",
    ["CVWR"] = "Create VWARS Route",
    ["DATA"] = "Exception: Bad Data",
    ["DBKT"] = "Delete Bucket Array",
    ["DEL "] = "Delete",
    ["DNRS"] = "Do Not Respond",
    ["DUPM"] = "Exception: Duplicate Message",
    ["ERES"] = "Extend Reservation",
    ["FILD"] = "Field",
    ["FREE"] = "Free Lock",
    ["FTYP"] = "Exception: Bad Field Type",
    ["MISS"] = "Exception: Missing Field",
    ["MSEQ"] = "Exception: Message Sequence",
    ["MSG "] = "Exception: Malformed Message",
    ["NACK"] = "Negative Acknowledgement",
    ["NLCK"] = "Exception: Wallet Not Locked",
    ["NRES"] = "Number of Reservations",
    ["NVRS"] = "Exception: No Voucher Reservation",
    ["NWRS"] = "Exception: No Wallet Reservation",
    ["PROV"] = "Service Provider (VWARS)",
    ["QRY "] = "Query",
    ["RALL"] = "Request All Contexts",
    ["RDAT"] = "Redeemed Date",
    ["RDMD"] = "Redeemed Flag",
    ["REF "] = "Reference",
    ["REMP"] = "Remove Empty Buckets",
    ["RES "] = "Reserve",
    ["RMCT"] = "Remove Context",
    ["RRES"] = "Revoke Reservation (VWARS)",
    ["RSVD"] = "Reserved Flag",
    ["RVWR"] = "Remove VWARS Route",
    ["SLSE"] = "Set Last Use",
    ["SRVN"] = "Server Number",
    ["STRV"] = "String Value",
    ["SUM "] = "Summarise",
    ["TAVL"] = "Total Available",
    ["TOTL"] = "Total Value",
    ["TRAN"] = "Transaction Type",
    ["UBAL"] = "Update Balance Array",
    ["UBKT"] = "Update Bucket Array",
    ["UNWN"] = "Exception: Unknown Message",
    ["UP  "] = "Update",
    ["VCHR"] = "Voucher",
    ["VRED"] = "Voucher Already Redeemed",
    ["VRES"] = "Voucher Already Reserved",
    ["VWRS"] = "VWARS Number",
    ["WFRZ"] = "Wallet Frozen",
    ["WRES"] = "Exception: Wallet Reserved (VWARS)",
    ["WSSP"] = "Wallet Suspended",
    ["WTRM"] = "Wallet Terminated",
    ["WUNU"] = "Wallet Unusable",
    -- Operations symbols
    ["AVAL"] = "Absolute Value",
    ["BAL "] = "Balance (class)",
    ["BUCK"] = "Bucket (class)",
    ["CRED"] = "Credit (limit type)",
    ["DEBT"] = "Debit (limit type)",
    ["DORM"] = "Dormant (wallet state)",
    ["FINL"] = "Final Flag",
    ["FRSV"] = "Reservation From Server",
    ["FULL"] = "Part of Full Resync",
    ["LCRD"] = "Limited Credit (limit type)",
    ["LOCL"] = "Origin: Local",
    ["NEXP"] = "Never Expires",
    ["NUSE"] = "Never Used",
    ["OPER"] = "Operation",
    ["ORIG"] = "Origin",
    ["PREU"] = "Pre-Use (wallet state)",
    ["RDM "] = "Redeemed (voucher flag)",
    ["RDMW"] = "Redeeming Wallet ID",
    ["RMTE"] = "Origin: Remote",
    ["SCXT"] = "Server Context (class)",
    ["SSEQ"] = "Server Sequence Number",
    ["STRN"] = "Sync Set Operation",
    ["SUSE"] = "Single Use (limit type)",
    ["SUSP"] = "Suspended (wallet state)",
    ["TERM"] = "Terminated (wallet state)",
    ["TRNL"] = "Transaction List",
    ["WTRN"] = "Writer Set Operation",
    -- Control symbols
    ["ALOC"] = "All Local Sent",
    ["ARES"] = "All Reservations Sent",
    ["CMMT"] = "Commit",
    ["DESC"] = "Description",
    ["DSBL"] = "Disabled (status)",
    ["FNAM"] = "Filename",
    ["GRVL"] = "Grovel",
    ["IDS "] = "IDs",
    ["LLUP"] = "Last Local Update",
    ["LRUP"] = "Last Remote Update",
    ["NSFL"] = "New Sync File",
    ["QUIE"] = "Quiesce (status)",
    ["QURY"] = "Query (Control)",
    ["RCVR"] = "Recovery (status)",
    ["REAS"] = "Reason",
    ["RSET"] = "Reset",
    ["RUN "] = "Running (status)",
    ["SET "] = "Set (action)",
    ["SRES"] = "Send All Reservations",
    ["STRT"] = "Start Session",
    ["STUP"] = "Startup (status)",
    ["SYNC"] = "Sync Number",
    ["TRYA"] = "Try Again In",
}

-- ============================================================
-- Register a ProtoField for every known symbol to allow specific filtering.
-- Filter names are "escher.<SYMBOL>" (lowercase, spaces to underscores).
-- ============================================================
local SYMBOL_PROTO_FIELDS = {}
local registered_names = {}
for sym, label in pairs(FIELD_LABELS) do
    -- Strip trailing spaces and convert to lowercase for intuitive filtering (e.g., "CLI " -> escher.cli)
    local filter_name = sym:gsub("%s+$", ""):lower():gsub(" ", "_")
    if registered_names[filter_name] then
        -- In case of collision (unlikely), fall back to exact underscores
        filter_name = sym:lower():gsub(" ", "_")
    end
    registered_names[filter_name] = true
    SYMBOL_PROTO_FIELDS[sym] = ProtoField.string("escher." .. filter_name, label)
end

-- Now finalise the fields registration
do
    for _, f in pairs(SYMBOL_PROTO_FIELDS) do
        table.insert(fields, f)
    end
    escher_proto.fields = fields
end

-- ============================================================
-- Preferences
--   Edit → Preferences → Protocols → ESCHER
-- ============================================================
escher_proto.prefs.show_friendly_names = Pref.bool(
    "Show friendly field names",   -- label in the prefs dialog
    false,                          -- default: off
    "Append the human-readable field name after the symbol, " ..
    "e.g. '[WALT] (Wallet ID)' instead of '[WALT]'."
)

-- ============================================================
-- field_label
--   Returns the display label for a map entry node.
--   When the "Show friendly field names" preference is enabled:
--     "[SYM] (Friendly Name)"  — if a friendly name exists
--     "[SYM]"                  — otherwise
--   When the preference is disabled:
--     "[SYM]"                  — always
--   The sym_name argument must be the raw 4-char symbol (with
--   trailing spaces preserved), e.g. "WALT", "WI  ", "REQ ".
-- ============================================================
local function field_label(sym_name)
    local sym_trimmed = sym_name:match("^(.-)%s*$")
    if escher_proto.prefs.show_friendly_names then
        local friendly = FIELD_LABELS[sym_name]
        if friendly then
            return string.format("[%s] (%s)", sym_trimmed, friendly)
        end
    end
    return string.format("[%s]", sym_trimmed)
end

-- ============================================================
local dissect_map, dissect_array

-- ============================================================
-- value_summary
--   Returns a compact one-line display string for any scalar
--   value, used to build the inline "[KEY] = <value>" text.
--   Returns nil for container types (MAP / ARRAY / LIST).
-- ============================================================
local function value_summary(tvb, typecode, abs_offset)
    local tlen = tvb:len()
    if typecode == 0 then
        return ""    -- NULL → show nothing after "="

    elseif typecode == 1 then   -- INT32
        if abs_offset + 4 > tlen then return nil end
        return tostring(tvb(abs_offset, 4):int())

    elseif typecode == 2 then   -- DATE
        if abs_offset + 4 > tlen then return nil end
        return "date " .. format_timestamp(tvb(abs_offset, 4):uint())

    elseif typecode == 3 then   -- SYMBOL
        if abs_offset + 4 > tlen then return nil end
        local sym = decode_symbol(tvb(abs_offset, 4):uint())
        return "'" .. sym .. "'"

    elseif typecode == 4 then   -- FLOAT64
        if abs_offset + 8 > tlen then return nil end
        return "[float64: " .. tvb(abs_offset, 8):bytes():tohex() .. "]"

    elseif typecode == 5 then   -- STRING
        if abs_offset >= tlen then return nil end
        local first   = tvb(abs_offset, 1):uint()
        local str_len, hdr_sz
        if bit.band(first, 0x80) == 0 then
            str_len = first;  hdr_sz = 1
        else
            if abs_offset + 2 > tlen then return nil end
            str_len = bit.band(tvb(abs_offset, 2):uint(), 0x7FFF)
            hdr_sz  = 2
        end
        if abs_offset + hdr_sz + str_len > tlen then return nil end
        return '"' .. tvb(abs_offset + hdr_sz, str_len):string() .. '"'

    elseif typecode == 8 then   -- RAW
        if abs_offset + 4 > tlen then return nil end
        local raw_len = tvb(abs_offset, 4):uint()
        return string.format("[%u bytes raw]", raw_len)

    elseif typecode == 9 then   -- INT64
        if abs_offset + 8 > tlen then return nil end
        return tostring(tvb(abs_offset, 8):int64())
    end

    return nil   -- container type — caller handles
end

-- ============================================================
-- dissect_value
--   Renders a single field value onto parent_tree.
--
--   For scalars the entire "[KEY] (Friendly Name) = value" line
--   is set on the parent_tree node itself (no child node is
--   created).
--
--   For MAP / ARRAY / LIST a collapsible child subtree is
--   created showing "[KEY] (Friendly Name) = Map of N elements"
--   etc., and the contents are decoded recursively inside that
--   subtree.
--
--   The hidden filterable ProtoFields are still attached so
--   that display-filter expressions continue to work.
-- ============================================================
local function dissect_value(tvb, parent_tree, typecode, abs_offset, label, depth, sym_name)
    if depth > 20 then return 0 end
    local tlen     = tvb:len()
    local spec_field = sym_name and SYMBOL_PROTO_FIELDS[sym_name]

    -- ── Scalar types ─────────────────────────────────────────
    if typecode == 0 then   -- NULL
        -- Show "[KEY] (Friendly Name) ="  with nothing after equals
        parent_tree:set_text(label .. " =")
        -- Attach a zero-length hidden node so filters still match
        local item = parent_tree:add(f_val_null, tvb(abs_offset, 0), ""):set_hidden()
        return 0

    elseif typecode == 1 then   -- INT32
        if abs_offset + 4 > tlen then return 0 end
        local val = tvb(abs_offset, 4):int()
        parent_tree:set_text(string.format("%s = %d", label, val))
        parent_tree:add(f_val_int32, tvb(abs_offset, 4)):set_hidden()
        if spec_field then
            parent_tree:add(spec_field, tvb(abs_offset, 4), tostring(val)):set_hidden()
        end
        return 4

    elseif typecode == 2 then   -- DATE
        if abs_offset + 4 > tlen then return 0 end
        local ts  = tvb(abs_offset, 4):uint()
        local fts = "date " .. format_timestamp(ts)
        parent_tree:set_text(string.format("%s = %s", label, fts))
        parent_tree:add(f_val_date, tvb(abs_offset, 4)):set_hidden()
        if spec_field then
            parent_tree:add(spec_field, tvb(abs_offset, 4), fts):set_hidden()
        end
        return 4

    elseif typecode == 3 then   -- SYMBOL
        if abs_offset + 4 > tlen then return 0 end
        local sv  = tvb(abs_offset, 4):uint()
        local sym = decode_symbol(sv)
        parent_tree:set_text(string.format("%s = '%s'", label, sym))
        parent_tree:add(f_val_symbol, tvb(abs_offset, 4)):set_hidden()
        local sym_stripped = sym:match("^%s*(.-)%s*$")
        if sym_stripped ~= sym then
            parent_tree:add(f_val_symbol, tvb(abs_offset, 4), sym_stripped):set_hidden()
        end
        if spec_field then
            parent_tree:add(spec_field, tvb(abs_offset, 4), sym):set_hidden()
            if sym_stripped ~= sym then
                parent_tree:add(spec_field, tvb(abs_offset, 4), sym_stripped):set_hidden()
            end
        end
        return 4

    elseif typecode == 4 then   -- FLOAT64
        if abs_offset + 8 > tlen then return 0 end
        local hex = tvb(abs_offset, 8):bytes():tohex()
        parent_tree:set_text(string.format("%s = [float64: %s]", label, hex))
        parent_tree:add(f_val_float, tvb(abs_offset, 8)):set_hidden()
        return 8

    elseif typecode == 5 then   -- STRING
        if abs_offset >= tlen then return 0 end
        local first = tvb(abs_offset, 1):uint()
        local str_len, hdr_sz
        if bit.band(first, 0x80) == 0 then
            str_len = first;  hdr_sz = 1
        else
            if abs_offset + 2 > tlen then return 0 end
            str_len = bit.band(tvb(abs_offset, 2):uint(), 0x7FFF)
            hdr_sz  = 2
        end
        if abs_offset + hdr_sz + str_len > tlen then return 0 end
        local sval = tvb(abs_offset + hdr_sz, str_len):string()
        parent_tree:set_text(string.format('%s = "%s"', label, sval))
        parent_tree:add(f_val_string, tvb(abs_offset + hdr_sz, str_len)):set_hidden()
        local sval_stripped = sval:match("^%s*(.-)%s*$")
        if sval_stripped ~= sval then
            parent_tree:add(f_val_string, tvb(abs_offset + hdr_sz, str_len), sval_stripped):set_hidden()
        end
        if spec_field then
            parent_tree:add(spec_field, tvb(abs_offset + hdr_sz, str_len), sval):set_hidden()
            if sval_stripped ~= sval then
                parent_tree:add(spec_field, tvb(abs_offset + hdr_sz, str_len), sval_stripped):set_hidden()
            end
        end
        return math.floor((hdr_sz + str_len + 3) / 4) * 4

    elseif typecode == 8 then   -- RAW
        if abs_offset + 4 > tlen then return 0 end
        local raw_len = tvb(abs_offset, 4):uint()
        local avail   = math.min(raw_len, tlen - abs_offset - 4)
        parent_tree:set_text(string.format("%s = [%u bytes raw]", label, raw_len))
        parent_tree:add(f_val_raw, tvb(abs_offset + 4, avail)):set_hidden()
        return math.floor((4 + raw_len + 3) / 4) * 4

    elseif typecode == 9 then   -- INT64
        if abs_offset + 8 > tlen then return 0 end
        local v64 = tostring(tvb(abs_offset, 8):int64())
        parent_tree:set_text(string.format("%s = %s", label, v64))
        parent_tree:add(f_val_int64, tvb(abs_offset, 8)):set_hidden()
        if spec_field then
            parent_tree:add(spec_field, tvb(abs_offset, 8), v64):set_hidden()
        end
        return 8

    -- ── Container types ──────────────────────────────────────
    elseif typecode == 6 or typecode == 11 then   -- ARRAY / LIST
        -- The parent node label will be updated inside dissect_array
        -- once we know the item count.  Seed it now as a placeholder.
        parent_tree:set_text(label .. " = Array")
        return dissect_array(tvb, parent_tree, abs_offset, depth + 1)

    elseif typecode == 12 then   -- MAP
        parent_tree:set_text(label .. " = Map")
        return dissect_map(tvb, parent_tree, abs_offset, depth + 1)

    else
        parent_tree:set_text(string.format("%s = [unknown typecode %d]", label, typecode))
        return 4
    end
end

-- ============================================================
-- dissect_map
--   Parses an ESCHER MAP beginning at byte `offset` in `tvb`.
--   Each field is rendered as a single "[KEY] (Friendly Name) = value"
--   node, with nested maps/arrays expanding inline.
--   All internal binary structure (header bytes, index entries) is hidden.
--   Returns the map's declared total_byte_length.
-- ============================================================
dissect_map = function(tvb, tree, offset, depth)
    depth = depth or 0
    local tlen = tvb:len()
    if offset + 4 > tlen then return 0 end

    local map_start  = offset
    local total_len, num_items, items_start, item_stride, ext_index

    local first_u16 = tvb(offset, 2):uint()

    if first_u16 == 0xFFFE then
        if offset + 12 > tlen then return 0 end
        local ctrl = tvb(offset + 3, 1):uint()
        ext_index  = bit.band(ctrl, 0x04) ~= 0
        total_len  = tvb(offset + 4, 4):uint()
        num_items  = tvb(offset + 8, 4):uint()
        -- Hidden structural fields (keep for filters / bytes pane)
        tree:add(f_ext_magic,     tvb(offset,     2)):set_hidden()
        tree:add(f_ext_ctrl,      tvb(offset + 2, 2)):set_hidden()
        tree:add(f_map_ext_len,   tvb(offset + 4, 4)):set_hidden()
        tree:add(f_map_ext_items, tvb(offset + 8, 4)):set_hidden()
        items_start = offset + 12
        item_stride = ext_index and 8 or 4
    else
        if offset + 8 > tlen then return 0 end
        total_len  = first_u16
        num_items  = tvb(offset + 2, 2):uint()
        ext_index  = false
        -- Hidden structural fields
        tree:add(f_map_total, tvb(offset,     2)):set_hidden()
        tree:add(f_map_items, tvb(offset + 2, 2)):set_hidden()
        tree:add(f_map_ptr,   tvb(offset + 4, 4)):set_hidden()
        items_start = offset + 8
        item_stride = 4
    end

    -- Update the label on the tree node that was created by the caller.
    -- For a nested map this is e.g. "[BODY] (Body) = Map of 11 elements".
    -- For the top-level root node we append the summary.
    tree:append_text(string.format(" of %d element%s",
                     num_items, num_items == 1 and "" or "s"))

    -- ---- Parse each index entry ----
    for i = 0, num_items - 1 do
        local idx_off = items_start + i * item_stride
        if idx_off + 4 > tlen then break end

        local entry_raw    = tvb(idx_off, 4):uint()
        local sym_val      = bit.band(entry_raw, 0xFFFFE000)
        local typecode     = bit.band(bit.rshift(entry_raw, 9), 0x0F)
        local sym_name     = decode_symbol(sym_val)

        local data_off_words
        if ext_index and idx_off + 8 <= tlen then
            data_off_words = tvb(idx_off + 4, 4):uint()
        else
            data_off_words = bit.band(entry_raw, 0x1FF)
        end
        local data_abs_off = map_start + data_off_words * 4

        -- Build the display label: "[SYM] (Friendly Name)" or "[SYM]"
        local label = field_label(sym_name)

        -- Determine the byte range that this entry covers in the tvb.
        -- For scalars we span the data bytes; for containers / NULL we
        -- point at the index entry itself (zero-length would confuse Wireshark).
        local entry_node
        if typecode == 0 then
            -- NULL: no data bytes, anchor to the index entry
            entry_node = tree:add(escher_proto, tvb(idx_off, item_stride), label)
        elseif typecode == 12 or typecode == 6 or typecode == 11 then
            -- Container: will fill in size once decoded; span from data start
            local span = (data_abs_off < tlen) and (tlen - data_abs_off) or 0
            entry_node = tree:add(escher_proto, tvb(data_abs_off, math.max(span, 0)), label)
        else
            -- Scalar: span the data bytes if in range
            if data_abs_off < tlen then
                entry_node = tree:add(escher_proto, tvb(data_abs_off, 0), label)
            else
                entry_node = tree:add(escher_proto, tvb(idx_off, item_stride), label)
            end
        end

        -- Add a hidden index-entry field for byte-level navigation
        entry_node:add(f_entry_raw, tvb(idx_off, 4)):set_hidden()

        -- Attach the hidden per-symbol filterable field
        entry_node:add(f_sym, tvb(idx_off, 4), sym_name):set_hidden()
        local friendly_base = FIELD_LABELS[sym_name]
        if friendly_base then
            entry_node:add(f_field_label, tvb(idx_off, 4), friendly_base):set_hidden()
        end

        -- Decode the value onto (or under) entry_node
        if typecode == 0 then
            -- NULL: "[KEY] (Friendly Name) ="  (nothing after equals)
            entry_node:set_text(label .. " =")
            entry_node:add(f_val_null, tvb(idx_off, 0), ""):set_hidden()

        elseif data_abs_off >= tlen then
            entry_node:set_text(string.format("%s = [offset out of range]", label))
            entry_node:add_expert_info(PI_MALFORMED, PI_ERROR,
                string.format("Data offset %d out of range (pkt %d bytes)",
                              data_abs_off, tlen))

        elseif typecode == 12 then
            -- MAP: "[KEY] (Friendly Name) = Map" — updated to "Map of N elements" inside
            entry_node:set_text(label .. " = Map")
            dissect_map(tvb, entry_node, data_abs_off, depth + 1)

        elseif typecode == 6 or typecode == 11 then
            -- ARRAY/LIST: "[KEY] (Friendly Name) = Array" — updated inside dissect_array
            entry_node:set_text(label .. " = Array")
            dissect_array(tvb, entry_node, data_abs_off, depth + 1)

        else
            -- Scalar: render inline on entry_node
            dissect_value(tvb, entry_node, typecode, data_abs_off,
                          label, depth, sym_name)
        end
    end

    return total_len
end

-- ============================================================
-- dissect_array
--   Parses an ESCHER ARRAY/LIST beginning at byte `offset`.
--   Each element is rendered as "[N] = value" or as a
--   collapsible "[N] = Map of M elements" subtree.
--   All internal header bytes are hidden.
--   Returns the array's declared total_byte_length.
-- ============================================================
dissect_array = function(tvb, tree, offset, depth)
    depth = depth or 0
    local tlen = tvb:len()
    if offset + 4 > tlen then return 0 end

    local arr_start = offset
    local total_len, num_items, items_start, item_stride, ext_index

    local first_u16 = tvb(offset, 2):uint()

    if first_u16 == 0xFFFE then
        if offset + 12 > tlen then return 0 end
        local ctrl = tvb(offset + 3, 1):uint()
        ext_index  = bit.band(ctrl, 0x04) ~= 0
        total_len  = tvb(offset + 4, 4):uint()
        num_items  = tvb(offset + 8, 4):uint()
        tree:add(f_ext_magic,     tvb(offset,     2)):set_hidden()
        tree:add(f_ext_ctrl,      tvb(offset + 2, 2)):set_hidden()
        tree:add(f_map_ext_len,   tvb(offset + 4, 4)):set_hidden()
        tree:add(f_map_ext_items, tvb(offset + 8, 4)):set_hidden()
        items_start = offset + 12
        item_stride = ext_index and 6 or 2
    else
        if offset + 8 > tlen then return 0 end
        total_len  = first_u16
        num_items  = tvb(offset + 2, 2):uint()
        ext_index  = false
        tree:add(f_map_total, tvb(offset,     2)):set_hidden()
        tree:add(f_map_items, tvb(offset + 2, 2)):set_hidden()
        tree:add(f_map_ptr,   tvb(offset + 4, 4)):set_hidden()
        items_start = offset + 8
        item_stride = 2
    end

    -- Update the node text: "[KEY] (Friendly Name) = Array of N elements"
    -- (tree text was pre-set to "... = Array" by the caller)
    tree:append_text(string.format(" of %d element%s",
                     num_items, num_items == 1 and "" or "s"))

    for i = 0, num_items - 1 do
        local idx_off = items_start + i * item_stride
        if idx_off + 2 > tlen then break end

        local entry_raw    = tvb(idx_off, 2):uint()
        local typecode     = bit.band(bit.rshift(entry_raw, 9), 0x0F)
        local data_off_words
        if ext_index and idx_off + 6 <= tlen then
            data_off_words = tvb(idx_off + 2, 4):uint()
        else
            data_off_words = bit.band(entry_raw, 0x1FF)
        end
        local data_abs_off = arr_start + data_off_words * 4

        -- Array elements are positional, not keyed — use numeric index label only
        local label = string.format("[%d]", i)

        -- Create child node
        local entry_node
        if typecode == 0 then
            entry_node = tree:add(escher_proto, tvb(idx_off, item_stride), label)
        elseif typecode == 12 or typecode == 6 or typecode == 11 then
            local span = (data_abs_off < tlen) and (tlen - data_abs_off) or 0
            entry_node = tree:add(escher_proto, tvb(data_abs_off, math.max(span, 0)), label)
        else
            if data_abs_off < tlen then
                entry_node = tree:add(escher_proto, tvb(data_abs_off, 0), label)
            else
                entry_node = tree:add(escher_proto, tvb(idx_off, item_stride), label)
            end
        end

        if typecode == 0 then
            entry_node:set_text(label .. " =")

        elseif data_abs_off >= tlen then
            entry_node:set_text(string.format("%s = [offset out of range]", label))
            entry_node:add_expert_info(PI_MALFORMED, PI_ERROR,
                string.format("Data offset %d out of range (pkt %d bytes)",
                              data_abs_off, tlen))

        elseif typecode == 12 then
            entry_node:set_text(label .. " = Map")
            dissect_map(tvb, entry_node, data_abs_off, depth + 1)

        elseif typecode == 6 or typecode == 11 then
            entry_node:set_text(label .. " = Array")
            dissect_array(tvb, entry_node, data_abs_off, depth + 1)

        else
            dissect_value(tvb, entry_node, typecode, data_abs_off, label, depth, nil)
        end
    end

    return total_len
end

-- ============================================================
-- Main dissector entry point
-- The entire TCP payload is an ESCHER MAP (no separate framing).
-- ============================================================
function escher_proto.dissector(tvb, pinfo, tree)
    local pkt_len = tvb:len()
    if pkt_len < 8 then return 0 end  -- minimum viable map

    pinfo.cols.protocol:set("ESCHER")

    -- Build a useful info column: try to read ACTN and TYPE symbol values
    local num_items  = tvb(2, 2):uint()
    local actn_str, type_str

    if num_items >= 1 and num_items <= 64 and pkt_len >= 8 then
        for i = 0, num_items - 1 do
            local idx_off = 8 + i * 4
            if idx_off + 4 <= pkt_len then
                local e    = tvb(idx_off, 4):uint()
                local sym  = decode_symbol(bit.band(e, 0xFFFFE000))
                local tc   = bit.band(bit.rshift(e, 9), 0x0F)
                local doff = bit.band(e, 0x1FF) * 4
                if sym == "ACTN" and tc == 3 and doff + 4 <= pkt_len then
                    -- Trim trailing spaces for cleaner info column
                    local v = decode_symbol(tvb(doff, 4):uint()):match("^(.-)%s*$")
                    actn_str = v
                elseif sym == "TYPE" and tc == 3 and doff + 4 <= pkt_len then
                    local v = decode_symbol(tvb(doff, 4):uint()):match("^(.-)%s*$")
                    type_str = v
                end
            end
        end
    end

    if actn_str or type_str then
        pinfo.cols.info:set(string.format("ESCHER  %s  %s  (%d bytes)",
            actn_str or "?", type_str or "?", pkt_len))
    else
        pinfo.cols.info:set(string.format("ESCHER  %d bytes  %d fields",
            pkt_len, num_items))
    end

    -- Dissect the top-level map under a clean root node
    local root = tree:add(escher_proto, tvb(), "ESCHER Protocol Data (© Blue Bridge Software)")
    dissect_map(tvb, root, 0, 0)

    return pkt_len
end

-- ============================================================
-- Register on TCP port 1500 (confirmed from PCAP)
-- ============================================================
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(1500, escher_proto)