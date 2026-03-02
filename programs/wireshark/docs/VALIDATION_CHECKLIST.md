# Escher Dissector Validation Checklist

## Test Coverage - OCNCC Voucher Messages

This document validates that the Escher Wireshark dissector correctly decodes all message types used in the Oracle OCNCC voucher handling system.

## Message Types Tested

### ✅ VI (Voucher Info)
- **File**: `vi_request.pcap` / `vi_ack.pcap`
- **Purpose**: Query and retrieve voucher information
- **Key Features**:
  - Request contains voucher number or type name
  - Response contains full voucher details including values array
  - Nested VALS array with balance types and values
  - Symbol fields: STAT (state), APOL (policy)
  - Date fields: EXPR (expiry date)

**Validation Points**:
- [ ] HEAD.TYPE shows 'VI  ' symbol
- [ ] BODY.VNUM shows voucher number string
- [ ] BODY.VALS array displays correctly
- [ ] Each VALS entry shows BTYP (int), VAL (int), BEXT (int)
- [ ] BODY.STAT shows state symbol (ACTV/REDM/CRTD/FROZ/DLTD)
- [ ] Date fields decode to human-readable timestamps

### ✅ VU (Voucher Update)
- **File**: `vu_request.pcap`
- **Purpose**: Update voucher state (mark as redeemed/unredeemed)
- **Key Features**:
  - Changes voucher state
  - Can update wallet association
  - Can set/unset redeem date

**Validation Points**:
- [ ] HEAD.TYPE shows 'VU  ' symbol
- [ ] BODY.STAT shows new state
- [ ] BODY.WID shows wallet ID (integer)
- [ ] BODY.RDAT shows redeem date or NULL

### ✅ VR (Voucher Reserve)
- **File**: `vr_request.pcap`
- **Purpose**: Reserve a voucher for redemption (two-phase commit start)
- **Key Features**:
  - Nested WLTI (Wallet Info) map
  - WLTI contains BALS array (balance information)
  - Multiple integer and string fields
  - Account type and scenario support

**Validation Points**:
- [ ] HEAD.TYPE shows 'VR  ' symbol
- [ ] BODY.WLTI map decodes correctly
- [ ] BODY.WLTI.BALS array shows balance entries
- [ ] Each BALS entry has BTYP, BVAL, BEXP
- [ ] BODY.AREF shows account reference string
- [ ] BODY.ACTY shows account type integer

### ✅ CVR (Commit Voucher Reservation)
- **File**: `cvr_request.pcap`
- **Purpose**: Commit a voucher reservation (two-phase commit finish)
- **Key Features**:
  - References previous VR request
  - Contains wallet info with updated balances
  - Generates CDR (Call Detail Record)
  - May include scenario information

**Validation Points**:
- [ ] HEAD.TYPE shows 'CVR ' symbol
- [ ] HEAD.MSGD shows message ID string (for CDR)
- [ ] BODY.VID shows voucher ID
- [ ] BODY.DATE shows commit timestamp
- [ ] BODY.WLTI map with BALS array present
- [ ] All balance changes reflected correctly

### ✅ RVR (Revoke Voucher Reservation)
- **File**: `rvr_request.pcap`
- **Purpose**: Rollback a voucher reservation
- **Key Features**:
  - Minimal message (voucher ID only)
  - Used for transaction rollback

**Validation Points**:
- [ ] HEAD.TYPE shows 'RVR ' symbol
- [ ] BODY.VNUM shows voucher number
- [ ] BODY.VID shows voucher ID
- [ ] Message is compact (< 100 bytes typically)

### ✅ VTRC (Voucher Type Reservation Commit)
- **File**: `vtrc_request.pcap`
- **Purpose**: Commit product type change (account type swap)
- **Key Features**:
  - Changes account type for wallet/account reference
  - Triggers replication events

**Validation Points**:
- [ ] HEAD.TYPE shows 'VTRC' symbol
- [ ] BODY.WID shows wallet ID
- [ ] BODY.AREF shows account reference
- [ ] BODY.ACTY shows new account type

### ✅ WGR (Wallet General Recharge)
- **File**: `wgr_message.pcap`
- **Purpose**: General wallet recharge operation
- **Key Features**:
  - Contains account and IMSI
  - Balance changes array
  - Currency symbol
  - Response includes status

**Validation Points**:
- [ ] HEAD.TYPE shows 'WGR ' symbol
- [ ] BODY.ACCT shows account number string
- [ ] BODY.IMSI shows IMSI string
- [ ] BODY.AMNT shows recharge amount
- [ ] BODY.CURR shows currency symbol
- [ ] BODY.BALS array with balance entries
- [ ] TAIL.STAT shows status symbol
- [ ] TAIL.CODE shows status code

### ✅ Complex Nested Message (Tax Components)
- **File**: `complex_nested.pcap`
- **Purpose**: Test deep nesting and complex structures
- **Key Features**:
  - 3-level nesting (Map → Array → Map → Array)
  - Tax components with tax plan
  - Multiple balance types with tax details
  - Metadata section

**Validation Points**:
- [ ] BODY.VALS array decodes
- [ ] Each VALS entry has TCOM (tax components) array
- [ ] TCOM entries show TNAM and TVAL
- [ ] BODY.META map with nested data
- [ ] BODY.META.TAGS array of strings

### ✅ ABORT Message
- **File**: `abort_message.pcap`
- **Purpose**: Transaction rollback/abort
- **Key Features**:
  - HEAD.ACTN = 'ABRT' symbol
  - Reason field

**Validation Points**:
- [ ] HEAD.ACTN shows 'ABRT' symbol
- [ ] BODY.RSNO shows reason string
- [ ] Message recognized as abort type

### ✅ Error Response
- **File**: `error_response.pcap`
- **Purpose**: Error handling and exceptions
- **Key Features**:
  - HEAD.ACTN = 'ERR ' symbol
  - Error code, message, type
  - Stack trace array

**Validation Points**:
- [ ] HEAD.ACTN shows 'ERR ' symbol
- [ ] BODY.ECOD shows error code (integer)
- [ ] BODY.EMSG shows error message string
- [ ] BODY.ETYP shows exception type symbol
- [ ] BODY.ESTK array shows stack entries

### ✅ Extended Format Message
- **File**: `extended_format.pcap`
- **Purpose**: Test extended format for large messages (>2KB)
- **Key Features**:
  - 0xFFFE header marker
  - 32-bit length and count fields
  - Large VALS array (100 entries)
  - Long strings

**Validation Points**:
- [ ] Wireshark shows "Extended Format" flag
- [ ] Header shows 0xFFFE marker
- [ ] 32-bit length field decoded correctly
- [ ] 32-bit item count decoded correctly
- [ ] All 100+ array entries accessible
- [ ] Large message (7852 bytes) fully decoded

## Protocol Feature Testing

### Standard Format Features
- [ ] 16-bit byte length (offset 0-1)
- [ ] 16-bit item count (offset 2-3)
- [ ] Map keys with symbol/type/offset encoding
- [ ] Array indices with type/offset encoding
- [ ] 4-byte alignment throughout

### Extended Format Features  
- [ ] 0xFFFE marker detection
- [ ] Control block length byte
- [ ] 32-bit byte length field
- [ ] 32-bit item count field
- [ ] Proper offset adjustment

### Type Decoding
- [ ] NULL_TYPE (0x00) - displays as NULL
- [ ] INT_TYPE (0x01) - shows signed 32-bit integers
- [ ] DATE_TYPE (0x02) - shows timestamps as dates
- [ ] SYMBOL_TYPE (0x03) - shows 4-char symbols
- [ ] FLOAT_TYPE (0x04) - shows 64-bit doubles
- [ ] STRING_TYPE (0x05) - shows UTF-8 strings
- [ ] ARRAY_TYPE (0x06) - shows nested arrays
- [ ] MAP_TYPE (0x07) - shows nested maps
- [ ] RAW_TYPE (0x08) - shows binary data

### String Encoding
- [ ] Short strings (<128 bytes) with 1-byte length
- [ ] Long strings (≥128 bytes) with 2-byte length + 0x8000
- [ ] Proper 4-byte alignment padding
- [ ] UTF-8 characters display correctly

### Symbol Encoding
- [ ] 4-character symbols display correctly
- [ ] Network byte order conversion
- [ ] Non-printable chars shown as escape codes
- [ ] Common symbols: 'VI  ', 'VU  ', 'VR  ', 'CVR ', etc.

### Array Features
- [ ] Index entries show type and offset
- [ ] Nested arrays decode recursively
- [ ] Mixed-type arrays work correctly
- [ ] Empty arrays handled

### Map Features
- [ ] Key symbols extracted correctly
- [ ] Map entries sorted/displayed properly
- [ ] Nested maps decode recursively
- [ ] Empty maps handled

### Dirty Flag Detection
- [ ] IS_DIRTY check (bits 15 and 0 set)
- [ ] Shows "Dirty Flag: true"
- [ ] Shows pointer value in hex
- [ ] Doesn't attempt to decode pointer

## Display Filter Testing

Test these display filters on `all_messages.pcap`:

```
escher                                  # All messages (16 packets)
escher.type == 0x01                    # Integer values
escher.type == 0x05                    # String values  
escher.type == 0x07                    # Maps
escher.map.symbol contains "VI"        # VI messages (2 packets)
escher.map.symbol contains "CVR"       # CVR messages (1 packet)
escher.map.symbol contains "REQ"       # All requests (~10 packets)
escher.map.symbol contains "ACK"       # All acknowledgments (~2 packets)
escher.extended == 1                   # Extended format (1 packet)
escher.int > 1000                      # Large integer values
escher.string contains "voucher"       # String content search
```

Expected results noted in comments above.

## Performance Testing

### Small Messages (<200 bytes)
- [ ] Decode time < 10ms
- [ ] All fields accessible
- [ ] No display artifacts

### Medium Messages (200-2000 bytes)
- [ ] Decode time < 50ms
- [ ] Nested structures work
- [ ] Scrolling responsive

### Large Messages (>2KB)
- [ ] Extended format detected
- [ ] Decode time < 200ms
- [ ] All entries accessible
- [ ] No memory issues

### Batch Testing (all_messages.pcap)
- [ ] All 16 packets decode
- [ ] No crashes or hangs
- [ ] Can scroll through all packets
- [ ] Filters work correctly

## Edge Cases

### Boundary Conditions
- [ ] Zero-length strings
- [ ] Empty arrays
- [ ] Empty maps
- [ ] NULL values
- [ ] Maximum integer values
- [ ] Very long strings (>1KB)

### Error Conditions
- [ ] Truncated messages handled gracefully
- [ ] Invalid type codes detected
- [ ] Bad offset values caught
- [ ] Alignment errors reported

### Network Conditions
- [ ] Fragmented packets (if applicable)
- [ ] Out-of-order packets (if applicable)
- [ ] Multiple messages per packet
- [ ] Incomplete messages

## Integration Testing

### Wireshark Integration
- [ ] Plugin loads without errors
- [ ] Appears in About→Plugins list
- [ ] Protocol listed in Decode As menu
- [ ] Works with tcp.port filter
- [ ] Works with manual Decode As
- [ ] Color rules apply correctly
- [ ] Export functions work

### TShark Integration
```bash
# Test command line decoding
tshark -r all_messages.pcap -Y escher -T json
tshark -r all_messages.pcap -Y escher -T fields -e escher.map.symbol
tshark -r conversation.pcap -Y escher -T fields -e frame.number -e escher.type
```

- [ ] JSON export works
- [ ] Field extraction works  
- [ ] Filters apply correctly
- [ ] No errors in output

### Conversation Analysis (conversation.pcap)
- [ ] Shows proper request→response flow
- [ ] Timestamps increment correctly
- [ ] Can follow TCP stream
- [ ] Shows VI→VR→CVR sequence
- [ ] All messages in conversation decode

## Real-World Scenarios

### Voucher Redemption Flow
Using `conversation.pcap`:
1. [ ] VI_Req: Client queries voucher info
2. [ ] VI_Ack: Server returns voucher details  
3. [ ] VR_Req: Client reserves voucher
4. [ ] VR_Ack: Server confirms reservation
5. [ ] CVR_Req: Client commits reservation
6. [ ] CVR_Ack: Server finalizes redemption

### Error Handling
Using `error_response.pcap`:
- [ ] Error message displays clearly
- [ ] Error code visible
- [ ] Stack trace readable
- [ ] Can identify error type

### Product Swap
Using `vtrc_request.pcap`:
- [ ] Account type change visible
- [ ] Wallet and account reference clear
- [ ] Message compact and efficient

## Documentation Verification

- [ ] README covers all message types
- [ ] Quick reference has all type codes
- [ ] Examples match generated messages
- [ ] Installation instructions work
- [ ] Filters documented correctly

## Sign-Off

**Dissector Version**: 1.0  
**Wireshark Version**: _________  
**Test Date**: _________  
**Tester**: _________  

**Overall Status**: ☐ PASS  ☐ FAIL  ☐ PARTIAL

**Notes**:
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________

## Known Issues

Document any issues found during testing:

1. ___________________________________________________________________________
2. ___________________________________________________________________________
3. ___________________________________________________________________________

## Recommendations

Based on testing, recommend for:
- [ ] Production use
- [ ] Further testing required
- [ ] Modifications needed

**Summary**:
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________
