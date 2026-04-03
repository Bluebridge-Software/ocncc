/* ============================================================
 * ESCHER Protocol Dissector  (C plugin)
 *
 * Copyright © 2026 Blue Bridge Software Ltd. All rights reserved.
 *
 * This material is the confidential property of Blue Bridge Software Ltd
 * or its licensors and may be used, reproduced, stored or transmitted
 * only in accordance with a valid Blue Bridge Software Ltd license or
 * sublicense agreement.
 * ============================================================
 *
 * Exactly mirrors the behaviour of escher_dissector.lua.
 *
 * PROTOCOL STRUCTURE (all integers big-endian, no framing layer):
 *
 *   The entire TCP payload is a single ESCHER MAP.
 *
 *   MAP (standard):
 *     [0:2]  u16  total_byte_length
 *     [2:4]  u16  num_items
 *     [4:8]  u32  internal_ptr  (0 on the wire)
 *     [8:]   index entries, 4 bytes each:
 *              bits [31:13]  symbol value  (masked with 0xFFFFE000)
 *              bits [12:9]   typecode      (4 bits)
 *              bits  [8:0]   data_offset   (9 bits, in 4-byte words from MAP START)
 *
 *   MAP (extended, magic = 0xFFFE):
 *     [0:2]  u16  0xFFFE
 *     [2:4]  u16  control_block  (bit 2 of byte[3] = extended-index flag)
 *     [4:8]  u32  total_byte_length
 *     [8:12] u32  num_items
 *     [12:]  index entries, 4 or 8 bytes each
 *
 *   ARRAY (standard):
 *     [0:2]  u16  total_byte_length
 *     [2:4]  u16  num_items
 *     [4:8]  u32  internal_ptr
 *     [8:]   2-byte index entries:
 *              bits [12:9]  typecode
 *              bits  [8:0]  data_offset (words from ARRAY START)
 *
 *   TYPECODES:
 *     0  NULL     1  INT32    2  DATE     3  SYMBOL
 *     4  FLOAT64  5  STRING   6  ARRAY    8  RAW
 *     9  INT64   11  LIST    12  MAP
 *
 *   SYMBOL ENCODING:
 *     alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZ " (A=0…Z=25, SPACE=26)
 *     Pass the full masked value (& 0xFFFFE000) directly — do NOT shift first.
 * ============================================================
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <stdio.h>
#include <string.h>

/* ── Compile-time guard ──────────────────────────────────────────────────── */
/* proto_item_set_hidden() was introduced in Wireshark 3.0.               */
/* For older builds the macro silently becomes a no-op.                   */
#ifndef proto_item_set_hidden
#  define proto_item_set_hidden(item)  (void)(item)
#endif

#define ESCHER_PORT    1500
#define MAX_DEPTH      20   /* recursion guard */

/* ── Protocol handle ─────────────────────────────────────────────────────── */
static int proto_escher = -1;

/* ── Header-field handles ────────────────────────────────────────────────── */
/* Structural (hidden from tree, still usable in filters / bytes pane) */
static int hf_escher_map_total     = -1;
static int hf_escher_map_ext_len   = -1;
static int hf_escher_map_items     = -1;
static int hf_escher_map_ext_items = -1;
static int hf_escher_map_ptr       = -1;
static int hf_escher_ext_magic     = -1;
static int hf_escher_ext_ctrl      = -1;
static int hf_escher_entry_raw     = -1;
/* Value fields */
static int hf_escher_val_int32     = -1;
static int hf_escher_val_int64     = -1;
static int hf_escher_val_float     = -1;
static int hf_escher_val_string    = -1;
static int hf_escher_val_symbol    = -1;
static int hf_escher_val_date      = -1;
static int hf_escher_val_raw       = -1;
static int hf_escher_val_null      = -1;

/* ── Subtree handles ─────────────────────────────────────────────────────── */
static gint ett_escher       = -1;
static gint ett_escher_map   = -1;
static gint ett_escher_array = -1;
static gint ett_escher_entry = -1;

/* ============================================================
 * Symbol decoder
 *
 * IMPORTANT: pass the full 32-bit value already masked with
 * 0xFFFFE000 — do NOT shift before calling.  The divisors
 * incorporate the lower-13-bit offset so the arithmetic works
 * on the raw masked integer exactly as in the Lua dissector.
 * ============================================================ */
static void decode_symbol(guint32 val, char out[5])
{
    static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
    out[0] = ALPHABET[(val / 161243136U) % 27];
    out[1] = ALPHABET[(val /   5971968U) % 27];
    out[2] = ALPHABET[(val /    221184U) % 27];
    out[3] = ALPHABET[(val /      8192U) % 27];
    out[4] = '\0';
}

/* ============================================================
 * Date formatter  (mirrors Lua format_timestamp)
 * Returns a static buffer "YYYYMMDDHHMMSS (unix)"
 * ============================================================ */
static const char *format_date(guint32 ts)
{
    static char buf[40];

    guint32 days = ts / 86400;
    guint32 rem  = ts % 86400;
    guint   hh   = (guint)(rem / 3600);
    guint   mm   = (guint)((rem % 3600) / 60);
    guint   ss   = (guint)(rem % 60);

    /* Walk forward from 1970 to find year */
    guint year = 1970;
    while (1) {
        gboolean leap = ((year % 4 == 0) &&
                         (year % 100 != 0 || year % 400 == 0));
        guint32 ydays = leap ? 366 : 365;
        if (days < ydays) break;
        days -= ydays;
        year++;
    }

    /* Walk through months */
    static const guint mdays_common[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    static const guint mdays_leap[]   = {31,29,31,30,31,30,31,31,30,31,30,31};
    gboolean leap = ((year % 4 == 0) && (year % 100 != 0 || year % 400 == 0));
    const guint *mdays = leap ? mdays_leap : mdays_common;
    guint month = 1;
    for (guint m = 0; m < 12; m++) {
        if (days < mdays[m]) { month = m + 1; break; }
        days -= mdays[m];
    }
    guint day = (guint)days + 1;

    g_snprintf(buf, sizeof(buf), "%04u%02u%02u%02u%02u%02u (%u)",
               year, month, day, hh, mm, ss, (guint)ts);
    return buf;
}

/* ============================================================
 * Forward declarations (mutual recursion)
 * ============================================================ */
static void dissect_escher_map  (tvbuff_t *tvb, proto_tree *tree,
                                  guint map_start, int depth);
static void dissect_escher_array(tvbuff_t *tvb, proto_tree *tree,
                                  guint arr_start, int depth);

/* ============================================================
 * dissect_escher_value
 *
 * Renders a single typed value onto parent_item / parent_tree.
 * Scalar types set the text on parent_item directly (clean
 * "[KEY] = value" line).  Container types recurse.
 * ============================================================ */
static void dissect_escher_value(tvbuff_t *tvb,
                                  proto_item *parent_item,
                                  proto_tree *parent_tree,
                                  guint typecode,
                                  guint abs_off,
                                  const char *label,
                                  int depth)
{
    guint tlen = tvb_reported_length(tvb);
    if (abs_off >= tlen) return;

    switch (typecode) {

    case 0: /* NULL — "[KEY] =" with nothing after */
    {
        proto_item *ni = proto_tree_add_string(parent_tree,
                             hf_escher_val_null, tvb, abs_off, 0, "");
        proto_item_set_text(parent_item, "%s =", label);
        proto_item_set_hidden(ni);
        break;
    }

    case 1: /* INT32 */
    {
        if (abs_off + 4 > tlen) break;
        gint32 v = tvb_get_ntohl(tvb, abs_off);
        proto_item *ni = proto_tree_add_int(parent_tree,
                             hf_escher_val_int32, tvb, abs_off, 4, v);
        proto_item_set_text(parent_item, "%s = %d", label, v);
        proto_item_set_hidden(ni);
        break;
    }

    case 2: /* DATE — format as "YYYYMMDDHHMMSS (unix)" */
    {
        if (abs_off + 4 > tlen) break;
        guint32 ts  = tvb_get_ntohl(tvb, abs_off);
        const char *fts = format_date(ts);
        proto_item *ni = proto_tree_add_string(parent_tree,
                             hf_escher_val_date, tvb, abs_off, 4, fts);
        proto_item_set_text(parent_item, "%s = date %s", label, fts);
        proto_item_set_hidden(ni);
        break;
    }

    case 3: /* SYMBOL — single-quoted */
    {
        if (abs_off + 4 > tlen) break;
        guint32 sv = tvb_get_ntohl(tvb, abs_off);
        char sym[5];
        decode_symbol(sv, sym);
        proto_item *ni = proto_tree_add_string(parent_tree,
                             hf_escher_val_symbol, tvb, abs_off, 4, sym);
        proto_item_set_text(parent_item, "%s = '%s'", label, sym);
        proto_item_set_hidden(ni);
        break;
    }

    case 4: /* FLOAT64 — byte-reversed on Linux wire; show raw hex */
    {
        if (abs_off + 8 > tlen) break;
        proto_item *ni = proto_tree_add_item(parent_tree,
                             hf_escher_val_float, tvb, abs_off, 8, ENC_NA);
        /* Build hex string for display */
        char hex[20];
        for (int b = 0; b < 8; b++)
            g_snprintf(hex + b*2, 3, "%02x",
                       tvb_get_guint8(tvb, abs_off + b));
        proto_item_set_text(parent_item, "%s = [float64: %s]", label, hex);
        proto_item_set_hidden(ni);
        break;
    }

    case 5: /* STRING — double-quoted */
    {
        if (abs_off >= tlen) break;
        guint8  first = tvb_get_guint8(tvb, abs_off);
        guint   str_len, hdr_sz;
        if ((first & 0x80) == 0) {
            str_len = first;  hdr_sz = 1;
        } else {
            if (abs_off + 2 > tlen) break;
            str_len = tvb_get_ntohs(tvb, abs_off) & 0x7FFF;
            hdr_sz  = 2;
        }
        if (abs_off + hdr_sz + str_len > tlen) break;
        /* Extract string value for the label */
        char *sval = (char *)wmem_alloc(wmem_packet_scope(), str_len + 1);
        tvb_memcpy(tvb, sval, abs_off + hdr_sz, str_len);
        sval[str_len] = '\0';
        proto_item *ni = proto_tree_add_string(parent_tree,
                             hf_escher_val_string, tvb,
                             abs_off + hdr_sz, str_len, sval);
        proto_item_set_text(parent_item, "%s = \"%s\"", label, sval);
        proto_item_set_hidden(ni);
        break;
    }

    case 6:  /* ARRAY */
    case 11: /* LIST  (same wire format as ARRAY) */
    {
        proto_item_set_text(parent_item, "%s = Array", label);
        dissect_escher_array(tvb, parent_tree, abs_off, depth + 1);
        break;
    }

    case 8: /* RAW */
    {
        if (abs_off + 4 > tlen) break;
        guint32 raw_len = tvb_get_ntohl(tvb, abs_off);
        guint   avail   = tlen - abs_off - 4;
        if (raw_len > avail) raw_len = avail;
        proto_item *ni = proto_tree_add_item(parent_tree,
                             hf_escher_val_raw, tvb,
                             abs_off + 4, raw_len, ENC_NA);
        proto_item_set_text(parent_item, "%s = [%u bytes raw]",
                            label, raw_len);
        proto_item_set_hidden(ni);
        break;
    }

    case 9: /* INT64 */
    {
        if (abs_off + 8 > tlen) break;
        gint64 v64 = tvb_get_ntoh64(tvb, abs_off);
        proto_item *ni = proto_tree_add_int64(parent_tree,
                             hf_escher_val_int64, tvb, abs_off, 8, v64);
        proto_item_set_text(parent_item, "%s = %" G_GINT64_FORMAT,
                            label, v64);
        proto_item_set_hidden(ni);
        break;
    }

    case 12: /* MAP */
    {
        proto_item_set_text(parent_item, "%s = Map", label);
        dissect_escher_map(tvb, parent_tree, abs_off, depth + 1);
        break;
    }

    default:
        proto_item_set_text(parent_item, "%s = [unknown typecode %u]",
                            label, typecode);
        break;
    }
}

/* ============================================================
 * dissect_escher_map
 *
 * Parses an ESCHER MAP starting at map_start.
 * Renders "[KEY] = value" nodes directly on tree.
 * All structural header nodes are hidden.
 * ============================================================ */
static void dissect_escher_map(tvbuff_t *tvb, proto_tree *tree,
                                guint map_start, int depth)
{
    if (depth > MAX_DEPTH) return;

    guint tlen = tvb_reported_length(tvb);
    if (map_start + 4 > tlen) return;

    guint32 num_items   = 0;
    guint   items_start = 0;
    guint   item_stride = 4;
    gboolean ext_index  = FALSE;

    guint16 first_u16 = tvb_get_ntohs(tvb, map_start);

    if (first_u16 == 0xFFFE) {
        /* Extended map header */
        if (map_start + 12 > tlen) return;
        guint8 ctrl = tvb_get_guint8(tvb, map_start + 3);
        ext_index   = (ctrl & 0x04) != 0;
        num_items   = tvb_get_ntohl(tvb, map_start + 8);
        items_start = map_start + 12;
        item_stride = ext_index ? 8 : 4;
        /* Hidden structural fields */
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_ext_magic,
                              tvb, map_start,     2, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_ext_ctrl,
                              tvb, map_start + 2, 2, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_map_ext_len,
                              tvb, map_start + 4, 4, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_uint(tree, hf_escher_map_ext_items,
                              tvb, map_start + 8, 4, num_items));
    } else {
        /* Standard map header */
        if (map_start + 8 > tlen) return;
        num_items   = tvb_get_ntohs(tvb, map_start + 2);
        items_start = map_start + 8;
        item_stride = 4;
        /* Hidden structural fields */
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_map_total,
                              tvb, map_start,     2, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_map_items,
                              tvb, map_start + 2, 2, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_map_ptr,
                              tvb, map_start + 4, 4, ENC_BIG_ENDIAN));
    }

    /* Append element count to the parent node text */
    proto_item_append_text(proto_tree_get_parent(tree), " of %u element%s",
                           num_items, num_items == 1 ? "" : "s");

    /* Iterate index entries */
    for (guint32 i = 0; i < num_items; i++) {
        guint idx_off = items_start + i * item_stride;
        if (idx_off + 4 > tlen) break;

        guint32 entry_raw = tvb_get_ntohl(tvb, idx_off);

        /* BUG FIX 1: sym_val must be the raw masked value, not shifted.
         * The divisors in decode_symbol already account for the lower 13 bits. */
        guint32 sym_val        = entry_raw & 0xFFFFE000U;
        guint   typecode       = (entry_raw >> 9) & 0x0F;
        guint32 data_off_words = 0;

        if (ext_index && idx_off + 8 <= tlen) {
            data_off_words = tvb_get_ntohl(tvb, idx_off + 4);
        } else {
            data_off_words = entry_raw & 0x1FF;
        }

        char sym_name[5];
        decode_symbol(sym_val, sym_name);

        /* Trim trailing spaces for display label */
        char sym_trimmed[5];
        g_strlcpy(sym_trimmed, sym_name, sizeof(sym_trimmed));
        {
            int k = (int)strlen(sym_trimmed) - 1;
            while (k >= 0 && sym_trimmed[k] == ' ') sym_trimmed[k--] = '\0';
        }
        char label[12];
        g_snprintf(label, sizeof(label), "[%s]", sym_trimmed);

        /* Absolute data offset from the map start */
        guint abs_off = map_start + data_off_words * 4;

        /* Create the entry node — text will be set below */
        proto_item *entry_item = proto_tree_add_item(tree, hf_escher_entry_raw,
                                     tvb, idx_off, item_stride, ENC_NA);
        proto_item_set_text(entry_item, "%s", label);
        proto_tree *entry_tree = proto_item_add_subtree(entry_item, ett_escher_entry);

        /* Hidden per-field raw index entry (byte-level navigation) */
        proto_item_set_hidden(proto_tree_add_item(entry_tree, hf_escher_entry_raw,
                              tvb, idx_off, 4, ENC_BIG_ENDIAN));

        if (typecode == 0) {
            /* NULL — "[KEY] =" */
            proto_item_set_text(entry_item, "%s =", label);
            proto_item_set_hidden(proto_tree_add_string(entry_tree,
                                  hf_escher_val_null, tvb, idx_off, 0, ""));
        } else if (abs_off >= tlen) {
            proto_item_set_text(entry_item,
                                "%s = [offset out of range]", label);
            proto_item_append_text(entry_item,
                                   " (offset %u >= %u)", abs_off, tlen);
        } else if (typecode == 12) {
            /* MAP — recurse */
            proto_item_set_text(entry_item, "%s = Map", label);
            dissect_escher_map(tvb, entry_tree, abs_off, depth + 1);
        } else if (typecode == 6 || typecode == 11) {
            /* ARRAY / LIST — recurse */
            proto_item_set_text(entry_item, "%s = Array", label);
            dissect_escher_array(tvb, entry_tree, abs_off, depth + 1);
        } else {
            dissect_escher_value(tvb, entry_item, entry_tree,
                                  typecode, abs_off, label, depth);
        }
    }
}

/* ============================================================
 * dissect_escher_array
 *
 * Parses an ESCHER ARRAY/LIST starting at arr_start.
 * Each element rendered as "[N] = value".
 * ============================================================ */
static void dissect_escher_array(tvbuff_t *tvb, proto_tree *tree,
                                  guint arr_start, int depth)
{
    if (depth > MAX_DEPTH) return;

    guint tlen = tvb_reported_length(tvb);
    if (arr_start + 4 > tlen) return;

    guint32  num_items   = 0;
    guint    items_start = 0;
    guint    item_stride = 2;
    gboolean ext_index   = FALSE;

    guint16 first_u16 = tvb_get_ntohs(tvb, arr_start);

    if (first_u16 == 0xFFFE) {
        /* Extended array */
        if (arr_start + 12 > tlen) return;
        guint8 ctrl = tvb_get_guint8(tvb, arr_start + 3);
        ext_index   = (ctrl & 0x04) != 0;
        num_items   = tvb_get_ntohl(tvb, arr_start + 8);
        items_start = arr_start + 12;
        item_stride = ext_index ? 6 : 2;
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_ext_magic,
                              tvb, arr_start,     2, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_ext_ctrl,
                              tvb, arr_start + 2, 2, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_map_ext_len,
                              tvb, arr_start + 4, 4, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_uint(tree, hf_escher_map_ext_items,
                              tvb, arr_start + 8, 4, num_items));
    } else {
        /* Standard array: [u16 total][u16 n][u32 ptr][2-byte entries...] */
        if (arr_start + 8 > tlen) return;
        num_items   = tvb_get_ntohs(tvb, arr_start + 2);
        items_start = arr_start + 8;
        item_stride = 2;
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_map_total,
                              tvb, arr_start,     2, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_map_items,
                              tvb, arr_start + 2, 2, ENC_BIG_ENDIAN));
        proto_item_set_hidden(proto_tree_add_item(tree, hf_escher_map_ptr,
                              tvb, arr_start + 4, 4, ENC_BIG_ENDIAN));
    }

    /* Append count to the parent node text set by the caller */
    proto_item_append_text(proto_tree_get_parent(tree), " of %u element%s",
                           num_items, num_items == 1 ? "" : "s");

    for (guint32 i = 0; i < num_items; i++) {
        guint idx_off = items_start + i * item_stride;
        if (idx_off + 2 > tlen) break;

        guint16  entry_raw     = tvb_get_ntohs(tvb, idx_off);
        guint    typecode      = (entry_raw >> 9) & 0x0F;
        guint32  data_off_words;

        if (ext_index && idx_off + 6 <= tlen) {
            data_off_words = tvb_get_ntohl(tvb, idx_off + 2);
        } else {
            data_off_words = entry_raw & 0x1FF;
        }

        guint abs_off = arr_start + data_off_words * 4;

        char label[10];
        g_snprintf(label, sizeof(label), "[%u]", i);

        proto_item *elem_item = proto_tree_add_item(tree, hf_escher_entry_raw,
                                    tvb, idx_off, item_stride, ENC_NA);
        proto_item_set_text(elem_item, "%s", label);
        proto_tree *elem_tree = proto_item_add_subtree(elem_item, ett_escher_entry);

        if (typecode == 0) {
            proto_item_set_text(elem_item, "%s =", label);
        } else if (abs_off >= tlen) {
            proto_item_set_text(elem_item,
                                "%s = [offset out of range]", label);
        } else if (typecode == 12) {
            proto_item_set_text(elem_item, "%s = Map", label);
            dissect_escher_map(tvb, elem_tree, abs_off, depth + 1);
        } else if (typecode == 6 || typecode == 11) {
            proto_item_set_text(elem_item, "%s = Array", label);
            dissect_escher_array(tvb, elem_tree, abs_off, depth + 1);
        } else {
            dissect_escher_value(tvb, elem_item, elem_tree,
                                  typecode, abs_off, label, depth);
        }
    }
}

/* ============================================================
 * Top-level dissector
 * ============================================================ */
static int dissect_escher(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, void *data _U_)
{
    guint pkt_len = tvb_reported_length(tvb);
    if (pkt_len < 8) return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESCHER");
    col_clear  (pinfo->cinfo, COL_INFO);

    /* --- Quick scan for ACTN and TYPE to build a useful info column --- */
    guint16 first_u16  = tvb_get_ntohs(tvb, 0);
    guint32 num_items  = 0;
    guint   idx_start  = 0;

    if (first_u16 == 0xFFFE) {
        num_items = tvb_get_ntohl(tvb, 8);
        idx_start = 12;
    } else {
        num_items = tvb_get_ntohs(tvb, 2);
        idx_start = 8;
    }

    char actn_str[5] = "";
    char type_str[5] = "";
    if (num_items <= 64) {
        for (guint32 i = 0; i < num_items; i++) {
            guint ioff = idx_start + i * 4;
            if (ioff + 4 > pkt_len) break;
            guint32 e      = tvb_get_ntohl(tvb, ioff);
            guint32 sv     = e & 0xFFFFE000U;
            guint   tc     = (e >> 9) & 0x0F;
            guint   doff   = (e & 0x1FF) * 4;
            char    sym[5];
            decode_symbol(sv, sym);
            if (strcmp(sym, "ACTN") == 0 && tc == 3 && doff + 4 <= pkt_len) {
                decode_symbol(tvb_get_ntohl(tvb, doff), actn_str);
                /* Trim trailing spaces */
                int k = (int)strlen(actn_str)-1;
                while (k >= 0 && actn_str[k] == ' ') actn_str[k--] = '\0';
            } else if (strcmp(sym, "TYPE") == 0 && tc == 3 && doff + 4 <= pkt_len) {
                decode_symbol(tvb_get_ntohl(tvb, doff), type_str);
                int k = (int)strlen(type_str)-1;
                while (k >= 0 && type_str[k] == ' ') type_str[k--] = '\0';
            }
        }
    }

    if (actn_str[0] || type_str[0]) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "ESCHER  %s  %s  (%u bytes)",
                     actn_str[0] ? actn_str : "?",
                     type_str[0] ? type_str : "?",
                     pkt_len);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "ESCHER  %u bytes  %u fields",
                     pkt_len, num_items);
    }

    /* --- Build the root tree node --- */
    proto_item *ti   = proto_tree_add_item(tree, proto_escher, tvb, 0, -1, ENC_NA);
    proto_item_set_text(ti, "ESCHER Protocol Data");
    proto_tree *root = proto_item_add_subtree(ti, ett_escher);

    dissect_escher_map(tvb, root, 0, 0);

    return (int)pkt_len;
}

/* ============================================================
 * Registration
 * ============================================================ */
void proto_register_escher(void)
{
    static hf_register_info hf[] = {
        /* Structural fields (hidden from tree; used for byte highlighting) */
        { &hf_escher_map_total,
          { "Map Total Bytes",     "escher.map.total",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_map_items,
          { "Map Item Count",      "escher.map.items",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_map_ext_len,
          { "Map Total Bytes (Ext)", "escher.map.ext_len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_map_ext_items,
          { "Map Item Count (Ext)", "escher.map.ext_items",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_map_ptr,
          { "Internal Ptr",        "escher.map.ptr",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_ext_magic,
          { "Ext Map Magic",       "escher.map.ext_magic",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_ext_ctrl,
          { "Ext Control Block",   "escher.map.ext_ctrl",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_entry_raw,
          { "Index Entry",         "escher.entry.raw",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        /* Value fields */
        { &hf_escher_val_int32,
          { "Int32",   "escher.val.int32",
            FT_INT32,  BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_val_int64,
          { "Int64",   "escher.val.int64",
            FT_INT64,  BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_val_float,
          { "Float64 (raw bytes)", "escher.val.float",
            FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_val_string,
          { "String",  "escher.val.string",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_val_symbol,
          { "Symbol",  "escher.val.symbol",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_val_date,
          { "Date",    "escher.val.date",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_val_raw,
          { "Raw Data","escher.val.raw",
            FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_escher_val_null,
          { "Null",    "escher.val.null",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_escher,
        &ett_escher_map,
        &ett_escher_array,
        &ett_escher_entry,
    };

    proto_escher = proto_register_protocol(
                       "ESCHER Protocol", "ESCHER", "escher");
    proto_register_field_array (proto_escher, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_escher(void)
{
    dissector_handle_t h = create_dissector_handle(dissect_escher, proto_escher);
    dissector_add_uint("tcp.port", ESCHER_PORT, h);
}