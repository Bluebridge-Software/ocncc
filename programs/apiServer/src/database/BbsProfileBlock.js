'use strict';

/**
 * =============================================================================
 * BbsProfileBlock - JavaScript port of bbsProfileBlock PL/SQL package
 * =============================================================================
 *
 * High-performance encoder/decoder for profile blocks containing tag-value
 * pairs stored as binary LONG RAW data (received from Oracle as Base64 or Buffer).
 *
 * PROFILE WIRE FORMAT (mirrors PL/SQL package):
 *   Index Header:
 *     Bytes 0-3:   Number of tags (uint32 big-endian)
 *     Bytes 4+:    Sorted index entries, each 8 bytes:
 *                    [tagId: 4 bytes][dataOffset: 4 bytes]
 *
 *   Data Block (immediately after the index):
 *     For each tag:
 *       Bytes 0-3:  Data length (uint32 big-endian)
 *       Bytes 4+:   Data content (raw bytes)
 *
 *   Offsets are absolute from byte 0 of the profile buffer.
 *
 * USAGE:
 *   const parser = new BbsProfileBlock({ debug: false });
 *
 *   // Optionally load tag metadata for friendly names:
 *   await parser.loadTagMeta(fetchFn, { forceRefresh: false });
 *
 *   // Decode a full profile (base64 string or Buffer):
 *   const profile = parser.decodeProfile(base64OrBuffer);
 *
 *   // Find a single tag:
 *   const val = parser.findTag(base64OrBuffer, '0000A1B2');
 *
 *   // Modify and re-encode:
 *   const newBuf = parser.upsertTag(buf, '0000A1B2', Buffer.from('hello'));
 * =============================================================================
 */

// ---------------------------------------------------------------------------
// Custom error types
// ---------------------------------------------------------------------------

class ProfileError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'ProfileError';
        this.code = code;
    }
}

const ERR = {
    INVALID_PROFILE: 'INVALID_PROFILE',
    TAG_NOT_FOUND: 'TAG_NOT_FOUND',
    TAG_EXISTS: 'TAG_EXISTS',
    INVALID_OFFSET: 'INVALID_OFFSET',
    INVALID_TAG_FORMAT: 'INVALID_TAG_FORMAT',
    MEMORY_EXCEEDED: 'MEMORY_EXCEEDED',
};

// ---------------------------------------------------------------------------
// Constants (mirror PL/SQL package constants)
// ---------------------------------------------------------------------------

const MAX_PROFILE_SIZE = 1_000_000;   // 1 MB
const INDEX_ENTRY_SIZE = 8;           // tagId(4) + offset(4)
const DATA_LENGTH_SIZE = 4;           // uint32 length prefix per data block
const HEADER_SIZE = 4;           // uint32 tag count

// ---------------------------------------------------------------------------
// BbsProfileBlock class
// ---------------------------------------------------------------------------

class BbsProfileBlock {

    /**
     * @param {object} [opts]
     * @param {boolean} [opts.debug=false]  Print debug lines to console
     */
    constructor(opts = {}) {
        this.debug = opts.debug === true;
        this._tagMeta = null;   // flat Map: tagId (hex8) -> { name, type, parentTagId, isInputParameter }
        this._tagTree = null;   // hierarchical array
    }

    // =========================================================================
    // DEBUG
    // =========================================================================

    _log(...args) {
        if (this.debug) console.log('[BbsProfileBlock]', ...args);
    }

    setDebug(enabled) {
        this.debug = !!enabled;
    }

    // =========================================================================
    // TAG METADATA (friendly names)
    // =========================================================================

    /**
     * Load tag metadata (name, type, hierarchy) from a supplier function or
     * an Express-style router endpoint, with optional Redis caching.
     *
     * The supplier must return (or resolve) an object shaped like the
     * /profile-tags route response:
     *   { data: [ { tagId, name, type, parentTagId, isInputParameter } ], tree }
     *
     * @param {Function|string} source
     *   - If a function: called as source({ forceRefresh })
     *   - If a string:   treated as a URL and fetched with fetch()
     * @param {object}   [opts]
     * @param {boolean}  [opts.forceRefresh=false]  Bypass any cache layer
     * @param {object}   [opts.redisClient]          ioredis / node-redis client
     * @param {string}   [opts.cacheKey='bbs:profileTags']
     * @param {number}   [opts.cacheTTL=3600]        Seconds
     */
    async loadTagMeta(source, opts = {}) {
        const {
            forceRefresh = false,
            redisClient = null,
            cacheKey = 'bbs:profileTags',
            cacheTTL = 3600,
        } = opts;

        let payload = null;

        // ---- Try Redis cache first (unless forceRefresh) -------------------
        if (redisClient && !forceRefresh) {
            try {
                const cached = await redisClient.get(cacheKey);
                if (cached) {
                    this._log('loadTagMeta: cache hit');
                    payload = JSON.parse(cached);
                }
            } catch (e) {
                this._log('loadTagMeta: redis get error', e.message);
            }
        }

        // ---- Fetch from source if not cached --------------------------------
        if (!payload) {
            if (typeof source === 'function') {
                payload = await source({ forceRefresh });
            } else if (typeof source === 'string') {
                const resp = await fetch(source);
                if (!resp.ok) throw new Error(`loadTagMeta: HTTP ${resp.status} from ${source}`);
                payload = await resp.json();
            } else {
                throw new TypeError('loadTagMeta: source must be a function or URL string');
            }

            // ---- Write back to Redis ----------------------------------------
            if (redisClient && payload) {
                try {
                    await redisClient.set(cacheKey, JSON.stringify(payload), 'EX', cacheTTL);
                    this._log('loadTagMeta: written to cache, TTL', cacheTTL);
                } catch (e) {
                    this._log('loadTagMeta: redis set error', e.message);
                }
            }
        }

        // ---- Store locally ---------------------------------------------------
        this._tagMeta = new Map();
        if (payload && Array.isArray(payload.data)) {
            for (const t of payload.data) {
                this._tagMeta.set(t.tagId.toUpperCase(), t);
            }
        }
        this._tagTree = payload ? payload.tree : null;

        this._log('loadTagMeta: loaded', this._tagMeta.size, 'tags');
        return this;
    }

    /**
     * Look up friendly name for a tag ID (if metadata loaded).
     * @param {string} tagId  8-char hex string
     * @returns {{ name, type, parentTagId, isInputParameter } | null}
     */
    getTagInfo(tagId) {
        if (!this._tagMeta) return null;
        return this._tagMeta.get(this._normalizeTagId(tagId)) || null;
    }

    // =========================================================================
    // INPUT NORMALISATION
    // =========================================================================

    /**
     * Accept a profile as:
     *   - Buffer / Uint8Array
     *   - Base64 string (as returned by node-oracledb for LONG RAW)
     *   - hex string (even length, [0-9a-fA-F]+)
     * Returns a Buffer.
     */
    _toBuffer(input) {
        if (Buffer.isBuffer(input)) return input;
        if (input instanceof Uint8Array) return Buffer.from(input);
        if (typeof input === 'string') {
            // Heuristic: hex strings are always even-length all-hex
            if (/^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0) {
                return Buffer.from(input, 'hex');
            }
            // Otherwise assume base64
            return Buffer.from(input, 'base64');
        }
        throw new ProfileError(ERR.INVALID_PROFILE, 'Profile input must be Buffer, Uint8Array, or string');
    }

    /**
     * Normalise a tag ID to an 8-char uppercase hex string.
     * Accepts '1A2B', '00001A2B', 6731, etc.
     */
    _normalizeTagId(tagId) {
        let s;
        if (typeof tagId === 'number') {
            s = tagId.toString(16).toUpperCase().padStart(8, '0');
        } else if (typeof tagId === 'string') {
            s = tagId.toUpperCase().padStart(8, '0');
        } else {
            throw new ProfileError(ERR.INVALID_TAG_FORMAT, `Invalid tagId type: ${typeof tagId}`);
        }
        if (s.length > 8) {
            throw new ProfileError(ERR.INVALID_TAG_FORMAT, `Tag ID too long: ${tagId}`);
        }
        if (!/^[0-9A-F]{8}$/.test(s)) {
            throw new ProfileError(ERR.INVALID_TAG_FORMAT, `Tag ID not valid hex: ${tagId}`);
        }
        return s;
    }

    /** Convert 8-char hex tag ID to uint32 for comparisons */
    _tagIdToNumber(tagId) {
        return parseInt(this._normalizeTagId(tagId), 16);
    }

    // =========================================================================
    // LOW-LEVEL BUFFER HELPERS
    // =========================================================================

    /** Read uint32 big-endian from buf at byte offset */
    _readUint32(buf, byteOffset) {
        if (byteOffset + 4 > buf.length) {
            throw new ProfileError(ERR.INVALID_OFFSET, `Offset ${byteOffset} out of bounds (buf=${buf.length})`);
        }
        return buf.readUInt32BE(byteOffset);
    }

    /** Write uint32 big-endian and return a 4-byte Buffer */
    _uint32ToBuffer(value) {
        const b = Buffer.allocUnsafe(4);
        b.writeUInt32BE(value >>> 0, 0);
        return b;
    }

    // =========================================================================
    // INDEX ACCESSORS  (mirror GetTagIdAtIndex / GetDataOffsetAtIndex)
    // =========================================================================

    /** Byte offset (in profile buf) of the i-th index entry's tagId field */
    _indexEntryOffset(i) {
        return HEADER_SIZE + i * INDEX_ENTRY_SIZE;
    }

    /** Read tag ID at index position i (returns 8-char hex string) */
    _getTagIdAtIndex(buf, i) {
        const off = this._indexEntryOffset(i);
        return buf.slice(off, off + 4).toString('hex').toUpperCase();
    }

    /** Read data offset stored at index position i */
    _getDataOffsetAtIndex(buf, i) {
        const off = this._indexEntryOffset(i) + 4;
        return this._readUint32(buf, off);
    }

    /** Read data length stored at a data offset */
    _getDataLengthAtOffset(buf, dataOffset) {
        return this._readUint32(buf, dataOffset);
    }

    /** Read raw data bytes for a tag given its data offset */
    _getDataBytesAtOffset(buf, dataOffset) {
        const len = this._getDataLengthAtOffset(buf, dataOffset);
        const start = dataOffset + DATA_LENGTH_SIZE;
        if (start + len > buf.length) {
            throw new ProfileError(ERR.INVALID_OFFSET, `Data region overflows buffer`);
        }
        return buf.slice(start, start + len);
    }

    // =========================================================================
    // VALIDATION
    // =========================================================================

    /**
     * Validate profile structure.
     * @param {Buffer} buf
     * @param {boolean} [strict=false]  Also verify every offset
     * @returns {boolean}
     */
    validateProfile(buf, strict = false) {
        if (!buf || buf.length < HEADER_SIZE) return false;
        if (buf.length > MAX_PROFILE_SIZE) return false;
        const tagCount = this._readUint32(buf, 0);
        const minSize = HEADER_SIZE + tagCount * INDEX_ENTRY_SIZE;
        if (buf.length < minSize) return false;
        if (strict) {
            for (let i = 0; i < tagCount; i++) {
                try { this._getDataOffsetAtIndex(buf, i); } catch { return false; }
            }
        }
        return true;
    }

    _assertValid(buf) {
        if (!this.validateProfile(buf)) {
            throw new ProfileError(ERR.INVALID_PROFILE, 'Invalid profile structure');
        }
    }

    // =========================================================================
    // TAG COUNT / EMPTY PROFILE
    // =========================================================================

    /** Return the number of tags in a profile */
    tagCount(input) {
        const buf = this._toBuffer(input);
        if (!buf || buf.length < HEADER_SIZE) return 0;
        return this._readUint32(buf, 0);
    }

    /** Create and return an empty profile Buffer (4 zero bytes) */
    makeEmptyProfile() {
        return this._uint32ToBuffer(0);
    }

    // =========================================================================
    // BINARY SEARCH  (O(log n))
    // =========================================================================

    /**
     * Binary search for tagId in sorted index.
     * @returns {number} index position, or -1 if not found
     */
    _binarySearchTag(buf, tagId) {
        const count = this._readUint32(buf, 0);
        if (count === 0) return -1;

        const target = this._tagIdToNumber(tagId);
        let low = 0, high = count - 1;

        while (low <= high) {
            const mid = (low + high) >>> 1;
            const midTagN = parseInt(this._getTagIdAtIndex(buf, mid), 16);
            if (midTagN === target) return mid;
            if (midTagN < target) low = mid + 1;
            else high = mid - 1;
        }
        return -1;
    }

    // =========================================================================
    // TAG LOOKUP
    // =========================================================================

    /**
     * Check if a tag exists (O(log n)).
     * @param {Buffer|string} input
     * @param {string|number} tagId
     * @returns {boolean}
     */
    tagExists(input, tagId) {
        const buf = this._toBuffer(input);
        this._assertValid(buf);
        return this._binarySearchTag(buf, tagId) >= 0;
    }

    /**
     * Find and return raw data Buffer for a tag (O(log n)).
     * @throws {ProfileError} TAG_NOT_FOUND
     */
    findTagRaw(input, tagId) {
        const buf = this._toBuffer(input);
        this._assertValid(buf);
        const idx = this._binarySearchTag(buf, tagId);
        if (idx < 0) {
            throw new ProfileError(ERR.TAG_NOT_FOUND, `Tag not found: ${tagId}`);
        }
        const dataOffset = this._getDataOffsetAtIndex(buf, idx);
        return this._getDataBytesAtOffset(buf, dataOffset);
    }

    /**
     * Find tag and return value:
     *   - hex string  if the data looks non-printable
     *   - UTF-8 string otherwise
     * Returns null if not found (does not throw).
     */
    findTag(input, tagId) {
        try {
            const raw = this.findTagRaw(input, tagId);
            return this._rawToValue(raw);
        } catch (e) {
            if (e.code === ERR.TAG_NOT_FOUND) return null;
            throw e;
        }
    }

    /**
     * Find tag by zero-based index position.
     * @returns {{ tagId: string, value: string, raw: Buffer } | null}
     */
    findByIndex(input, index) {
        const buf = this._toBuffer(input);
        this._assertValid(buf);
        const count = this._readUint32(buf, 0);
        if (index < 0 || index >= count) return null;

        const tagId = this._getTagIdAtIndex(buf, index);
        const dataOffset = this._getDataOffsetAtIndex(buf, index);
        const raw = this._getDataBytesAtOffset(buf, dataOffset);

        return { tagId, value: this._rawToValue(raw), raw };
    }

    /**
     * Get offset and length metadata for a tag.
     * @returns {{ offset: number, length: number }}
     */
    getTagMetadata(input, tagId) {
        const buf = this._toBuffer(input);
        this._assertValid(buf);
        const idx = this._binarySearchTag(buf, tagId);
        if (idx < 0) throw new ProfileError(ERR.TAG_NOT_FOUND, `Tag not found: ${tagId}`);
        const offset = this._getDataOffsetAtIndex(buf, idx);
        const length = this._getDataLengthAtOffset(buf, offset);
        return { offset, length };
    }

    // =========================================================================
    // VALUE CONVERSION
    // =========================================================================

    /**
     * Convert raw bytes to a usable JavaScript value.
     * - If all bytes are printable ASCII → UTF-8 string
     * - Otherwise → uppercase hex string (e.g. "00000001")
     */
    _rawToValue(raw) {
        if (!raw || raw.length === 0) return '';
        const isPrintable = [...raw].every(b => b >= 0x20 && b <= 0x7e);
        return isPrintable ? raw.toString('utf8') : raw.toString('hex').toUpperCase();
    }

    /**
     * Interpret raw bytes in a type-aware way using tag metadata.
     *
     * Supported PROFILE_TAG_TYPE values from ACS_PROFILE_DETAILS:
     *   INT   → uint32 big-endian number
     *   BOOL  → 0/1 byte → false/true
     *   STR   → UTF-8 string
     *   RAW   → hex string (fallback)
     *
     * @param {Buffer} raw
     * @param {string|null} [type]   Type string from tag metadata
     * @returns {{ value: string|number|boolean, display: string, hex: string }}
     */
    _interpretRaw(raw, type) {
        if (!raw || raw.length === 0) {
            return { value: null, display: '', hex: '' };
        }

        const hex = [...raw].map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
        const t = (type || '').toUpperCase();

        if (t === 'BOOL') {
            const v = raw[0] !== 0;
            return { value: v, display: v ? 'TRUE' : 'FALSE', hex };
        }

        if (t === 'INT') {
            if (raw.length === 4) {
                const v = raw.readUInt32BE(0);
                return { value: v, display: String(v), hex };
            }
            if (raw.length === 2) {
                const v = raw.readUInt16BE(0);
                return { value: v, display: String(v), hex };
            }
            if (raw.length === 1) {
                const v = raw[0];
                return { value: v, display: String(v), hex };
            }
        }

        if (t === 'STR') {
            const v = raw.toString('utf8');
            return { value: v, display: v, hex };
        }

        // Fallback: printable ASCII or hex
        const isPrintable = [...raw].every(b => b >= 0x20 && b <= 0x7e);
        if (isPrintable) {
            const v = raw.toString('utf8');
            return { value: v, display: v, hex };
        }
        const hexCompact = raw.toString('hex').toUpperCase();
        return { value: hexCompact, display: hexCompact, hex };
    }

    /**
     * Convert a JavaScript value to a raw Buffer for storage.
     * Accepts: Buffer, Uint8Array, number (stored as uint32 BE), string (UTF-8).
     */
    _valueToBuffer(value) {
        if (Buffer.isBuffer(value)) return value;
        if (value instanceof Uint8Array) return Buffer.from(value);
        if (typeof value === 'number') return this._uint32ToBuffer(value);
        if (typeof value === 'string') return Buffer.from(value, 'utf8');
        throw new TypeError(`Cannot convert value type ${typeof value} to Buffer`);
    }

    // =========================================================================
    // PROFILE REBUILD HELPER
    // =========================================================================

    /**
     * Build a new profile Buffer from an array of { tagId: string, data: Buffer }.
     * The array MUST already be sorted ascending by tagId.
     */
    _buildProfile(entries) {
        const count = entries.length;
        // Compute where the data block starts
        const dataBlockStart = HEADER_SIZE + count * INDEX_ENTRY_SIZE;

        // Calculate total size
        let totalSize = dataBlockStart;
        for (const e of entries) totalSize += DATA_LENGTH_SIZE + e.data.length;

        const buf = Buffer.allocUnsafe(totalSize);

        // Write tag count
        buf.writeUInt32BE(count, 0);

        // Write index and data in two passes
        let indexPos = HEADER_SIZE;
        let dataPos = dataBlockStart;

        for (const e of entries) {
            // Tag ID
            const tagNum = parseInt(e.tagId, 16);
            buf.writeUInt32BE(tagNum, indexPos);
            indexPos += 4;
            // Offset (absolute, pointing at the length prefix)
            buf.writeUInt32BE(dataPos, indexPos);
            indexPos += 4;
            // Length prefix
            buf.writeUInt32BE(e.data.length, dataPos);
            dataPos += 4;
            // Data
            e.data.copy(buf, dataPos);
            dataPos += e.data.length;
        }

        return buf;
    }

    // =========================================================================
    // TAG MODIFICATION
    // =========================================================================

    /**
     * Read all existing entries from a profile into an array.
     */
    _readAllEntries(buf) {
        const count = this._readUint32(buf, 0);
        const entries = [];
        for (let i = 0; i < count; i++) {
            const tagId = this._getTagIdAtIndex(buf, i);
            const dataOffset = this._getDataOffsetAtIndex(buf, i);
            const data = this._getDataBytesAtOffset(buf, dataOffset);
            entries.push({ tagId, data: Buffer.from(data) });   // copy
        }
        return entries;
    }

    /**
     * Add or update a tag in the profile, maintaining sorted order.
     * Mirrors UpsertTag.
     * @param {Buffer|string} input
     * @param {string|number} tagId
     * @param {Buffer|string|number} value
     * @returns {Buffer}
     */
    upsertTag(input, tagId, value) {
        const buf = input ? this._toBuffer(input) : this.makeEmptyProfile();
        this._assertValid(buf);

        const normTag = this._normalizeTagId(tagId);
        const normNum = parseInt(normTag, 16);
        const data = this._valueToBuffer(value);

        const entries = this._readAllEntries(buf);

        // Binary-search insert position / replacement
        let lo = 0, hi = entries.length - 1, found = -1;
        while (lo <= hi) {
            const mid = (lo + hi) >>> 1;
            const midNum = parseInt(entries[mid].tagId, 16);
            if (midNum === normNum) { found = mid; break; }
            if (midNum < normNum) lo = mid + 1;
            else hi = mid - 1;
        }

        if (found >= 0) {
            entries[found].data = data;
        } else {
            // Insert at lo (keeps sort order)
            entries.splice(lo, 0, { tagId: normTag, data });
        }

        return this._buildProfile(entries);
    }

    /**
     * Add a new tag. Throws TAG_EXISTS if already present.
     */
    addTag(input, tagId, value) {
        const buf = this._toBuffer(input);
        if (this.tagExists(buf, tagId)) {
            throw new ProfileError(ERR.TAG_EXISTS, `Tag already exists: ${tagId}`);
        }
        return this.upsertTag(buf, tagId, value);
    }

    /**
     * Update existing tag. Throws TAG_NOT_FOUND if absent.
     */
    updateTag(input, tagId, value) {
        const buf = this._toBuffer(input);
        if (!this.tagExists(buf, tagId)) {
            throw new ProfileError(ERR.TAG_NOT_FOUND, `Tag not found: ${tagId}`);
        }
        return this.upsertTag(buf, tagId, value);
    }

    /**
     * Remove a tag. Silent no-op if tag doesn't exist.
     * @returns {Buffer}
     */
    removeTag(input, tagId) {
        const buf = this._toBuffer(input);
        this._assertValid(buf);

        const normTag = this._normalizeTagId(tagId);
        const entries = this._readAllEntries(buf).filter(e => e.tagId !== normTag);

        if (entries.length === this._readUint32(buf, 0)) {
            return buf;   // nothing removed
        }
        return this._buildProfile(entries);
    }

    /** Remove all tags, return empty profile */
    clearAllTags() {
        return this.makeEmptyProfile();
    }

    // =========================================================================
    // PROFILE STATISTICS
    // =========================================================================

    /**
     * Return statistics about a profile.
     * @returns {{ tagCount, totalSize, indexSize, dataSize }}
     */
    getProfileStats(input) {
        const buf = this._toBuffer(input);
        const tagCount = buf.length >= HEADER_SIZE ? this._readUint32(buf, 0) : 0;
        const indexSize = HEADER_SIZE + tagCount * INDEX_ENTRY_SIZE;
        return {
            tagCount,
            totalSize: buf.length,
            indexSize,
            dataSize: buf.length - indexSize,
        };
    }

    // =========================================================================
    // PROFILE COMPARISON  (O(n+m) merge)
    // =========================================================================

    /** Return true if two profiles are byte-identical */
    profilesMatch(input1, input2) {
        const b1 = this._toBuffer(input1);
        const b2 = this._toBuffer(input2);
        return b1.equals(b2);
    }

    /**
     * Compute differences between two profiles using a merge walk.
     * Returns an array of:
     *   { tagId, originalValue: string|null, newValue: string|null,
     *     tagInfo: { name, type, ... } | null }
     */
    profileDiff(input1, input2) {
        const b1 = this._toBuffer(input1);
        const b2 = this._toBuffer(input2);

        if (b1.equals(b2)) return [];

        const count1 = this._readUint32(b1, 0);
        const count2 = this._readUint32(b2, 0);
        const diffs = [];
        let i1 = 0, i2 = 0;

        while (i1 < count1 || i2 < count2) {
            const tag1Num = i1 < count1 ? parseInt(this._getTagIdAtIndex(b1, i1), 16) : Infinity;
            const tag2Num = i2 < count2 ? parseInt(this._getTagIdAtIndex(b2, i2), 16) : Infinity;

            if (tag1Num < tag2Num) {
                // Tag removed in profile 2
                const tagId = this._getTagIdAtIndex(b1, i1);
                diffs.push({
                    tagId,
                    tagInfo: this.getTagInfo(tagId),
                    originalValue: this._rawToValue(this._getDataBytesAtOffset(b1, this._getDataOffsetAtIndex(b1, i1))),
                    newValue: null,
                    changeType: 'removed',
                });
                i1++;
            } else if (tag2Num < tag1Num) {
                // Tag added in profile 2
                const tagId = this._getTagIdAtIndex(b2, i2);
                diffs.push({
                    tagId,
                    tagInfo: this.getTagInfo(tagId),
                    originalValue: null,
                    newValue: this._rawToValue(this._getDataBytesAtOffset(b2, this._getDataOffsetAtIndex(b2, i2))),
                    changeType: 'added',
                });
                i2++;
            } else {
                // Same tag in both - compare values
                const tagId = this._getTagIdAtIndex(b1, i1);
                const raw1 = this._getDataBytesAtOffset(b1, this._getDataOffsetAtIndex(b1, i1));
                const raw2 = this._getDataBytesAtOffset(b2, this._getDataOffsetAtIndex(b2, i2));
                if (!raw1.equals(raw2)) {
                    diffs.push({
                        tagId,
                        tagInfo: this.getTagInfo(tagId),
                        originalValue: this._rawToValue(raw1),
                        newValue: this._rawToValue(raw2),
                        changeType: 'changed',
                    });
                }
                i1++; i2++;
            }
        }
        return diffs;
    }

    /** Formatted string version of profileDiff (for logging) */
    profileDiffAsString(input1, input2) {
        return this.profileDiff(input1, input2)
            .map(d => `[${d.changeType.toUpperCase()}] ${d.tagId}` +
                (d.tagInfo ? ` (${d.tagInfo.name})` : '') +
                ` | was: ${d.originalValue ?? '(none)'}` +
                ` | now: ${d.newValue ?? '(none)'}`)
            .join('\n');
    }

    // =========================================================================
    // BULK OPERATIONS
    // =========================================================================

    /**
     * Merge two profiles. Tags in profile2 override profile1.
     */
    mergeProfiles(input1, input2) {
        const b1 = this._toBuffer(input1);
        const b2 = this._toBuffer(input2);
        this._assertValid(b1);
        this._assertValid(b2);

        // Start from entries of b1, then upsert all from b2
        const map = new Map();
        for (const e of this._readAllEntries(b1)) map.set(e.tagId, e);
        for (const e of this._readAllEntries(b2)) map.set(e.tagId, e);  // overrides

        const entries = [...map.values()].sort((a, b) =>
            parseInt(a.tagId, 16) - parseInt(b.tagId, 16));

        return this._buildProfile(entries);
    }

    /**
     * Subtract profile2 from profile1 (remove any tags that appear in profile2).
     */
    subtractProfiles(input1, input2) {
        const b1 = this._toBuffer(input1);
        const b2 = this._toBuffer(input2);
        this._assertValid(b1);
        this._assertValid(b2);

        const remove = new Set(this._readAllEntries(b2).map(e => e.tagId));
        const entries = this._readAllEntries(b1).filter(e => !remove.has(e.tagId));
        return this._buildProfile(entries);
    }

    /**
     * Keep only tags whose IDs are in the provided list.
     * @param {Buffer|string} input
     * @param {string[]} tagIds  Array of tag ID strings
     */
    filterTags(input, tagIds) {
        const buf = this._toBuffer(input);
        this._assertValid(buf);
        const keep = new Set(tagIds.map(id => this._normalizeTagId(id)));
        const entries = this._readAllEntries(buf).filter(e => keep.has(e.tagId));
        return this._buildProfile(entries);
    }

    // =========================================================================
    // FULL DECODE  (parseProfile / decodeProfile)
    // =========================================================================

    /**
     * Decode the entire profile and return a JSON-friendly structure.
     *
     * @param {Buffer|string} input   Base64 / Buffer / hex string
     * @param {object} [opts]
     * @param {boolean} [opts.friendlyNames=true]   Enrich with tag metadata if loaded
     * @param {boolean} [opts.includeRaw=false]     Include raw hex per tag
     * @param {boolean} [opts.includeStats=false]   Include profile statistics
     *
     * @returns {{
     *   valid: boolean,
     *   tagCount: number,
     *   stats?: object,
     *   tags: Array<{
     *     tagId: string,
     *     value: string,
     *     rawHex?: string,
     *     name?: string,
     *     type?: string,
     *     parentTagId?: string,
     *     isInputParameter?: boolean
     *   }>
     * }}
     */
    decodeProfile(input, opts = {}) {
        const {
            friendlyNames = true,
            includeRaw = false,
            includeStats = false,
        } = opts;

        let buf;
        try {
            buf = this._toBuffer(input);
        } catch {
            return { valid: false, tagCount: 0, tags: [], error: 'Cannot parse input' };
        }

        if (!this.validateProfile(buf)) {
            return { valid: false, tagCount: 0, tags: [], error: 'Invalid profile structure' };
        }

        const count = this._readUint32(buf, 0);
        const tags = [];

        for (let i = 0; i < count; i++) {
            const tagId = this._getTagIdAtIndex(buf, i);
            const dataOffset = this._getDataOffsetAtIndex(buf, i);
            let raw, value;

            try {
                raw = this._getDataBytesAtOffset(buf, dataOffset);
                value = this._rawToValue(raw);
            } catch (e) {
                value = `<error: ${e.message}>`;
                raw = Buffer.alloc(0);
            }

            // Enrich with tag metadata to enable type-aware value interpretation
            const info = (friendlyNames && this._tagMeta) ? this.getTagInfo(tagId) : null;
            const type = info ? info.type : null;
            const interpreted = this._interpretRaw(raw, type);

            const entry = {
                tagId,
                value: interpreted.value ?? value,   // typed when type is known
                display: interpreted.display,           // always a human-readable string
            };

            if (includeRaw) {
                entry.rawHex = raw.toString('hex').toUpperCase();
                entry.hexDump = interpreted.hex;        // e.g. "00 00 00 01"
            }

            if (info) {
                entry.name = info.name;
                entry.type = info.type;
                entry.parentTagId = info.parentTagId;
                entry.isInputParameter = info.isInputParameter;
            } else {
                // Always include these fields so every tag has a consistent
                // shape regardless of whether metadata is loaded.
                // Unknown tags still decode correctly — name just shows the hex ID.
                entry.name = null;
                entry.type = null;
                entry.parentTagId = null;
                entry.isInputParameter = null;
            }

            tags.push(entry);
        }

        const result = {
            valid: true,
            tagCount: count,
            metadataLoaded: !!(this._tagMeta && this._tagMeta.size > 0),
            tags,
        };
        if (includeStats) result.stats = this.getProfileStats(buf);
        return result;
    }

    /**
     * Alias used in the existing subscriber query handler.
     * Identical to decodeProfile().
     */
    parseProfile(input, opts) {
        return this.decodeProfile(input, opts);
    }

    // =========================================================================
    // DUMP / INTROSPECTION
    // =========================================================================

    /**
     * Return a human-readable dump of the profile (for debugging).
     */
    dumpProfile(input) {
        let buf;
        try { buf = this._toBuffer(input); } catch { return 'INVALID INPUT'; }
        if (!this.validateProfile(buf)) return 'INVALID PROFILE';

        const count = this._readUint32(buf, 0);
        const lines = [`Profile Dump (tags=${count}, bytes=${buf.length})`];
        lines.push('='.repeat(50));

        for (let i = 0; i < count; i++) {
            try {
                const tagId = this._getTagIdAtIndex(buf, i);
                const dataOffset = this._getDataOffsetAtIndex(buf, i);
                const raw = this._getDataBytesAtOffset(buf, dataOffset);
                const value = this._rawToValue(raw);
                const info = this.getTagInfo(tagId);
                const label = info ? ` (${info.name})` : '';
                lines.push(`Tag[${i}]: ${tagId}${label} = ${String(value).slice(0, 60)} [${raw.length} bytes]`);
            } catch (e) {
                lines.push(`Tag[${i}]: ERROR - ${e.message}`);
            }
        }
        return lines.join('\n');
    }

    /**
     * Compare two profiles and return a detailed text report.
     */
    compareProfiles(input1, input2) {
        const lines = ['Profile Comparison Report', '='.repeat(40)];

        if (this.profilesMatch(input1, input2)) {
            lines.push('Status: PROFILES MATCH');
            return lines.join('\n');
        }

        const diffs = this.profileDiff(input1, input2);
        lines.push(`Status: PROFILES DIFFER (${diffs.length} difference(s))`);
        lines.push('');

        diffs.forEach((d, i) => {
            lines.push(`Difference ${i + 1}:`);
            lines.push(`  Tag ID    : ${d.tagId}${d.tagInfo ? ` (${d.tagInfo.name})` : ''}`);
            lines.push(`  Change    : ${d.changeType}`);
            lines.push(`  Original  : ${d.originalValue ?? '(none)'}`);
            lines.push(`  New       : ${d.newValue ?? '(none)'}`);
            lines.push('');
        });

        return lines.join('\n');
    }

    // =========================================================================
    // =========================================================================
    // FORMATTED TABLE OUTPUT
    // =========================================================================

    /**
     * Format a decoded profile as a human-readable table matching the legacy
     * Oracle report layout:
     *
     *   Profile is (148 bytes) and (9 tags).
     *   Tag      Desc                                               Len  HexData...
     *   -------------------------------------------------------------------------
     *   0x000025 Language                                           4    00 00 00 01
     *     1
     *
     * @param {Buffer|string} input
     * @param {object} [opts]
     * @param {boolean} [opts.friendlyNames=true]
     * @returns {string}
     */
    dumpTable(input, opts = {}) {
        const { friendlyNames = true } = opts;
        let buf;
        try { buf = this._toBuffer(input); } catch { return 'INVALID INPUT'; }
        if (!this.validateProfile(buf)) return 'INVALID PROFILE';

        const count = this._readUint32(buf, 0);
        const totalSize = buf.length;
        const lines = [];

        lines.push(`Profile is (${totalSize} bytes) and (${count} tags).`);
        lines.push('');
        lines.push('Tag      Desc                                               Len  HexData...');
        lines.push('-'.repeat(75));

        for (let i = 0; i < count; i++) {
            try {
                const tagId = this._getTagIdAtIndex(buf, i);
                const dataOffset = this._getDataOffsetAtIndex(buf, i);
                const raw = this._getDataBytesAtOffset(buf, dataOffset);
                const tagNum = parseInt(tagId, 16);
                const tagHex = '0x' + tagNum.toString(16).toUpperCase().padStart(6, '0');
                const info = (friendlyNames && this._tagMeta) ? this.getTagInfo(tagId) : null;
                const name = info ? info.name : tagId;
                const interpreted = this._interpretRaw(raw, info ? info.type : null);

                const col1 = tagHex.padEnd(9);
                const col2 = name.padEnd(48);
                const col3 = String(raw.length).padEnd(5);
                lines.push(`${col1}${col2}${col3}${interpreted.hex}`);
                lines.push(`  ${interpreted.display}`);
            } catch (e) {
                lines.push(`  Tag[${i}]: ERROR - ${e.message}`);
            }
        }

        lines.push('');
        lines.push(`Total Size: ${totalSize}`);
        return lines.join('\n');
    }

    // ENCODE (return Base64 — for storing back via oracledb)
    // =========================================================================

    /**
     * Encode a Buffer profile to Base64 (ready to bind back to Oracle LONG RAW).
     */
    encodeProfileToBase64(buf) {
        return buf.toString('base64');
    }

    /**
     * Encode a Buffer profile to hex string.
     */
    encodeProfileToHex(buf) {
        return buf.toString('hex').toUpperCase();
    }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = { BbsProfileBlock, ProfileError, ERR };