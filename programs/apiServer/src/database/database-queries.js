/**
 * OCNCC Master Database Queries.
 * All Oracle queries in one place — callable internally or via the API layer.
 * Results are cached in Redis when configured.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const getRedisClient = require('../services/redis-client.js');

// ---------------------------------------------------------------------------
// Cache TTL constants (seconds)
// ---------------------------------------------------------------------------
const TTL = {
    PROFILE_TAGS: 3600,       // 1 hour  – static reference data
    SUBSCRIBER: 30,           // 30 s    – live account data, short TTL
    VWS_NODES: 300,           // 5 mins  – node topology, refreshed by engine config loop
};

// Cache key builders
const KEYS = {
    profileTags: () => 'db:profileTags',
    subscriber: (cli) => `db:subscriber:${cli}`,
    vwsNodes: () => 'db:vwsNodes',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Attempt a Redis GET.  Returns parsed JSON or null on any failure.
 * @param  redis
 * @param {string} key
 */
async function cacheGet(redis, key) {
    if (!redis) return null;
    try {
        const raw = await redis.get(key);
        return raw ? JSON.parse(raw) : null;
    } catch (e) {
        console.warn('[DB-Queries] Redis GET failed:', key, e.message);
        return null;
    }
}

/**
 * Attempt a Redis SET with EX TTL.  Silent on failure.
 * @param {import('ioredis').Redis|null} redis
 * @param {string} key
 * @param {*} value
 * @param {number} ttlSeconds
 */
async function cacheSet(redis, key, value, ttlSeconds) {
    if (!redis) return;
    try {
        await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
    } catch (e) {
        console.warn('[DB-Queries] Redis SET failed:', key, e.message);
    }
}

// ---------------------------------------------------------------------------
// buildTagPayload  (shared normalisation used by getProfileTags + profileParser)
// ---------------------------------------------------------------------------

/**
 * Normalise raw ACS_PROFILE_DETAILS rows into the shape used by both the
 * API response and BbsProfileBlock.loadTagMeta().
 *
 * @param {object[]} rows
 * @returns {{ count: number, data: object[], tree: object[] }}
 */
function buildTagPayload(rows) {
    const mappings = rows.map(row => {
        const tagId = Number(row.PROFILE_TAG)
            .toString(16).toUpperCase().padStart(8, '0');

        const parentTagId = row.PARENT_PROFILE_TAG != null
            ? Number(row.PARENT_PROFILE_TAG).toString(16).toUpperCase().padStart(8, '0')
            : null;

        return {
            tagId,
            name: row.PROFILE_TAG_NAME,
            type: row.PROFILE_TAG_TYPE,   // 'INT', 'BOOL', 'STR', …
            parentTagId,
            isInputParameter: row.IS_AN_INPUT_PARAMETER === 'Y',
            children: [],
        };
    });

    // Build hierarchy
    const tagMap = Object.fromEntries(mappings.map(t => [t.tagId, t]));
    const tree = [];
    for (const tag of mappings) {
        if (tag.parentTagId && tagMap[tag.parentTagId]) {
            tagMap[tag.parentTagId].children.push(tag);
        } else {
            tree.push(tag);
        }
    }

    return { count: mappings.length, data: mappings, tree };
}

// ---------------------------------------------------------------------------
// Query: getProfileTags
// ---------------------------------------------------------------------------

/**
 * Fetch all profile tag definitions from ACS_PROFILE_DETAILS.
 * Result is cached in Redis (TTL: 1 hour) unless forceRefresh is set.
 *
 * Used by:
 *   - GET /db/profile-tags  (API layer)
 *   - BbsProfileBlock.loadTagMeta() supplier function (startup + refresh)
 *
 * @param {import('../oracle-connector')} db
 * @param {import('ioredis').Redis|null}  redis
 * @param {object}  [opts]
 * @param {boolean} [opts.forceRefresh=false]
 * @returns {Promise<{ count: number, data: object[], tree: object[] }>}
 */
async function getProfileTags(db, redis, opts = {}) {
    const { forceRefresh = false } = opts;
    const cacheKey = KEYS.profileTags();

    // ---- Cache read --------------------------------------------------------
    if (redis) {
        if (!forceRefresh) {
            const cached = await cacheGet(redis, cacheKey);
            if (cached) {
                return cached;
            }
        }
    }

    console.log('[DB-Queries] getProfileTags: cache miss');
    // ---- Database read -----------------------------------------------------
    const rows = await db.executeQuery(`
        SELECT
            PROFILE_TAG_NAME,
            PROFILE_TAG_TYPE,
            PROFILE_TAG,
            PARENT_PROFILE_TAG,
            IS_AN_INPUT_PARAMETER
        FROM ACS_PROFILE_DETAILS
        ORDER BY PROFILE_TAG
    `);

    if (!rows || rows.length === 0) {
        console.log('[DB-Queries] getProfileTags: no tags found');
        return { count: 0, data: [], tree: [] };
    }

    const payload = buildTagPayload(rows);
    console.log(`[DB-Queries] getProfileTags: built payload with ${payload.count} tags`);

    // ---- Cache write -------------------------------------------------------
    await cacheSet(redis, cacheKey, payload, TTL.PROFILE_TAGS);
    console.log(`[DB-Queries] getProfileTags: loaded ${payload.count} tags from DB`);

    return payload;
}

// ---------------------------------------------------------------------------
// Query: getSubscriberByCli
// ---------------------------------------------------------------------------

/**
 * Fetch a subscriber record from CCS_ACCT_REFERENCE by CLI.
 * The raw PROFILE Buffer is preserved as-is (not serialised) so the caller
 * (API layer or internal code) can pass it directly to BbsProfileBlock.
 *
 * NOTE: We cache only the base64-encoded profile string, not the Buffer,
 * because Redis values are strings.  The API layer converts back to Buffer
 * if needed.
 *
 * @param {import('../oracle-connector')} db
 * @param {import('ioredis').Redis|null}  redis
 * @param {string}  cli
 * @param {object}  [opts]
 * @param {boolean} [opts.forceRefresh=false]
 * @param {boolean} [opts.decodeProfile=false]   If true, attach decoded profile
 * @param {import('../BbsProfileBlock').BbsProfileBlock|null} [opts.profileParser]
 * @returns {Promise<{ count: number, data: object[] }>}
 */
async function getSubscriberByCli(db, redis, cli, opts = {}) {
    const { forceRefresh = false, decodeProfile = false, profileParser = null } = opts;
    const cacheKey = KEYS.subscriber(cli);

    // Warn early if the caller wants decoded profiles but the parser has no
    // tag metadata yet — decoding will still work but tags will have no
    // friendly names (name/type will be null).
    if (decodeProfile && profileParser && (!profileParser._tagMeta || profileParser._tagMeta.size === 0)) {
        console.warn('[DB-Queries] getSubscriberByCli: profileParser has no tag metadata loaded — ' +
            'decoded tags will lack friendly names. Check loadProfileTags() ran at startup.');
    }

    // ---- Cache read --------------------------------------------------------
    if (!forceRefresh) {
        const cached = await cacheGet(redis, cacheKey);
        if (cached) {
            console.log(`[DB-Queries] getSubscriberByCli(${cli}): cache hit`);
            // Decode is always done live (never cached) so friendly names
            // reflect whatever metadata is loaded at call time.
            if (decodeProfile && profileParser) {
                cached.data = cached.data.map(row => ({
                    ...row,
                    decodedProfile: profileParser.decodeProfile(row.profile, { friendlyNames: true }),
                }));
            }
            return cached;
        }
    }

    // ---- Database read -----------------------------------------------------
    const rows = await db.executeQuery(
        `SELECT
                car.id as customer_reference_id,
                car.private_secret as private_secret,
                car.profile as profile,
                car.auth_hash_fn_id as auth_hash_fn_id,
                car.acs_cust_id as customer_id,
                ac.name as customer_name,
                cwt.id as wallet_type_id,
                cwt.name as wallet_type_name,
                caar.account as account,
                caar.account_type as account_type,
                cat.name as account_type_name,
                ca.charging_engine_id as charging_engine_id,
                ca.external_wallet_reference as external_wallet_reference,
                cd.domain_type_id as charging_domain_type_id,
                cdt.type as charging_domain_type_name,
                to_char(car.change_date, 'YYYYMMDDHH24MISS') as change_date,
                NVL(ca.tracker_engine_id,0) as tracker_engine_id,
                NVL(ca.currency,0) as currency,
                NVL(cur.code,'000') as currency_code,
                NVL(cur.big_symbol,'*') as currency_big_symbol,
                NVL(cur.little_symbol,'*') as currency_little_symbol,
                NVL(cur.separator,'.') as currency_separator,
                NVL(cur.name,'*') as currency_name,
                NVL(ab.state,'A') as account_batch_state
            FROM
                acs_customer ac,
                ccs_acct_reference car,
                ccs_wallet_type cwt,
                ccs_acct_acct_references caar,
                ccs_acct ca,
                ccs_acct_type cat,
                ccs_currency cur,
                ccs_domain cd,
                ccs_domain td,
                ccs_domain_type cdt,
                ccs_account_batch ab
            WHERE
                car.cli = :cli AND
                cwt.acs_cust_id = car.acs_cust_id AND
                caar.acs_cust_id = car.acs_cust_id AND
                ca.acs_cust_id = car.acs_cust_id AND
                ac.id = car.acs_cust_id AND
                cwt.default_type = 'Y' AND
                caar.acct_reference = car.id AND
                caar.account_type = cat.id AND
                caar.wallet_type = cwt.id AND
                cur.id = ca.currency AND
                ca.be_acct_id = caar.account AND
                ca.charging_engine_id = cd.domain_id AND
                cdt.domain_type_id = cd.domain_type_id AND
                ca.tracker_engine_id = td.domain_id(+) AND
                car.account_batch_id = ab.id (+)`,
        { cli }
    );

    if (!rows || rows.length === 0) {
        return { count: 0, data: [] };
    }

    const processed = rows.map(row => {
        // Oracle LONG RAW arrives as a Buffer — convert to base64 string immediately.
        // Keeping it as a Buffer would cause JSON.stringify to produce
        // { type: "Buffer", data: [...] } which _toBuffer cannot recover from.
        const profileBase64 = (row.PROFILE && Buffer.isBuffer(row.PROFILE))
            ? row.PROFILE.toString('base64')
            : (typeof row.PROFILE === 'string' ? row.PROFILE : null);

        const result = {
            customer_reference_id: row.CUSTOMER_REFERENCE_ID,
            private_secret: row.PRIVATE_SECRET,
            profile: profileBase64,  // always a base64 string from here onwards
            auth_hash_fn_id: row.AUTH_HASH_FN_ID,
            customer_id: row.CUSTOMER_ID,
            customer_name: row.CUSTOMER_NAME,
            wallet_type_id: row.WALLET_TYPE_ID,
            wallet_type_name: row.WALLET_TYPE_NAME,
            account: row.ACCOUNT,
            account_type: row.ACCOUNT_TYPE,
            account_type_name: row.ACCOUNT_TYPE_NAME,
            charging_engine_id: row.CHARGING_ENGINE_ID,
            external_wallet_reference: row.EXTERNAL_WALLET_REFERENCE,
            charging_domain_type_id: row.CHARGING_DOMAIN_TYPE_ID,
            charging_domain_type_name: row.CHARGING_DOMAIN_TYPE_NAME,
            change_date: row.CHANGE_DATE,
            tracker_engine_id: (row.TRACKER_ENGINE_ID === 0) ? null : row.TRACKER_ENGINE_ID,
            currency: (row.CURRENCY === 0) ? null : row.CURRENCY,
            currency_big_symbol: (row.CURRENCY_BIG_SYMBOL === '*') ? null : row.CURRENCY_BIG_SYMBOL,
            currency_little_symbol: (row.CURRENCY_LITTLE_SYMBOL === '*') ? null : row.CURRENCY_LITTLE_SYMBOL,
            currency_separator: (row.CURRENCY_SEPARATOR === '.') ? null : row.CURRENCY_SEPARATOR,
            currency_name: (row.CURRENCY_NAME === '*') ? null : row.CURRENCY_NAME,
            currency_code: (row.CURRENCY_CODE === '000') ? null : row.CURRENCY_CODE,
            account_batch_state: row.ACCOUNT_BATCH_STATE,
        };

        if (decodeProfile && profileParser && profileBase64) {
            result.decodedProfile = profileParser.decodeProfile(profileBase64, { friendlyNames: true });
        }

        return result;
    });

    const payload = { count: processed.length, data: processed };

    // ---- Cache write -------------------------------------------------------
    // Never cache decodedProfile — it depends on _tagMeta which can change.
    // The raw base64 profile string is stable and safe to cache.
    const forCache = {
        count: processed.length,
        data: processed.map(({ decodedProfile, ...rest }) => rest),  // eslint-disable-line no-unused-vars
    };
    await cacheSet(redis, cacheKey, forCache, TTL.SUBSCRIBER);

    return payload;
}

// ---------------------------------------------------------------------------
// Cache invalidation helpers
// ---------------------------------------------------------------------------

/**
 * Invalidate the profile tags cache (e.g. after a manual DB update).
 * @param {import('ioredis').Redis|null} redis
 */
async function invalidateProfileTagsCache(redis) {
    if (!redis) return;
    try {
        await redis.del(KEYS.profileTags());
        console.log('[DB-Queries] invalidateProfileTagsCache: done');
    } catch (e) {
        console.warn('[DB-Queries] invalidateProfileTagsCache failed:', e.message);
    }
}

/**
 * Invalidate the cached record for a specific CLI.
 * @param {import('ioredis').Redis|null} redis
 * @param {string} cli
 */
async function invalidateSubscriberCache(redis, cli) {
    if (!redis) return;
    try {
        await redis.del(KEYS.subscriber(cli));
        console.log(`[DB-Queries] invalidateSubscriberCache(${cli}): done`);
    } catch (e) {
        console.warn('[DB-Queries] invalidateSubscriberCache failed:', e.message);
    }
}

// ---------------------------------------------------------------------------
// Query: getVWSNodes
// ---------------------------------------------------------------------------

/**
 * Fetch all VWS nodes from CCS_DOMAIN_*.
 * Result is cached in Redis (TTL: 1 hour) unless forceRefresh is set.
 *
 * @param {import('../oracle-connector')} db
 * @param {import('ioredis').Redis|null}  redis
 * @param {object}  [opts]
 * @param {boolean} [opts.forceRefresh=false]
 * @returns {Promise<{ count: number, data: object[], tree: object[] }>}
 */
async function getVWSNodes(db, redis, opts = {}) {
    const { forceRefresh = false } = opts;
    const cacheKey = KEYS.vwsNodes();

    // ---- Cache read --------------------------------------------------------
    if (redis) {
        if (!forceRefresh) {
            const cached = await cacheGet(redis, cacheKey);
            if (cached) {
                return cached;
            }
        }
    }

    // ---- Database read -----------------------------------------------------
    const rows = await db.executeQuery(`
        SELECT  cd.domain_id,
                cdn.node_number,
                cdn.name,
                cdn.comm_address,
                cdn.client_port
        FROM    ccs_domain cd,
                ccs_domain_nodes cdn,
                ccs_domain_type cdt
        WHERE   cdt.type = 'UBE' AND
                cd.domain_type_id = cdt.domain_type_id AND
                cdn.domain_id = cd.domain_id
        GROUP BY cdn.domain_id,
        cd.domain_id,
                cdn.node_number,
                cdn.name,
                cdn.comm_address,
                cdn.client_port
        ORDER BY cdn.node_number
    `);

    if (!rows || rows.length === 0) {
        console.log('[DB-Queries] No VWS nodes found');
        return { count: 0, data: [] };
    }

    const structuredNodes = {};

    // rows is array of objects from db.executeQuery
    // Build tree structure
    rows.forEach(row => {
        const domainId = row.DOMAIN_ID;
        const nodeNumber = row.NODE_NUMBER;

        if (!structuredNodes[domainId]) {
            structuredNodes[domainId] = [];
        }

        structuredNodes[domainId].push({
            nodeNumber,
            name: row.NAME,
            commAddress: row.COMM_ADDRESS,
            clientPort: row.CLIENT_PORT,
        });
    });

    const count = rows.length;
    console.log(`[DB-Queries] ${count} VWS nodes structured by domain`);

    // ---- Cache write -------------------------------------------------------
    // cacheSet calls JSON.stringify internally — do NOT pre-stringify here or
    // the cache will store a string-of-a-string and deserialise to garbage.
    await cacheSet(redis, cacheKey, structuredNodes, TTL.VWS_NODES);

    return structuredNodes;
}

/**
 * Convert VWS nodes from DB into string format for BeClient
 *
 * Input example:
 * {
 *   '12': [
 *     { nodeNumber: 351, name: 'VWS01', commAddress: '192.168.127.42', clientPort: 1500 },
 *     { nodeNumber: 352, name: 'VWS02', commAddress: '192.168.127.47', clientPort: 1500 }
 *   ]
 * }
 *
 * Output example:
 * {
 *   '12': '12:192.168.127.42:1500:192.168.127.47:1500'
 * }
 */
function formatVWSNodes(dbRowsByDomain) {
    const result = [];

    // Guard: if the value is somehow still a string (e.g. stale double-serialised
    // cache entry), parse it rather than silently iterating over characters.
    if (typeof dbRowsByDomain === 'string') {
        try {
            dbRowsByDomain = JSON.parse(dbRowsByDomain);
        } catch (e) {
            console.error('[DB-Queries] formatVWSNodes: received unparseable string — returning empty config');
            return result;
        }
    }

    if (!dbRowsByDomain || typeof dbRowsByDomain !== 'object') {
        console.error('[DB-Queries] formatVWSNodes: invalid input — returning empty config');
        return result;
    }

    for (const [domainId, nodes] of Object.entries(dbRowsByDomain)) {
        if (!nodes || nodes.length === 0) continue;

        const domainObj = {
            id: Number(domainId),
            primary: nodes[0] ? { ip: nodes[0].commAddress, port: nodes[0].clientPort } : null,
            secondary: nodes[1] ? { ip: nodes[1].commAddress, port: nodes[1].clientPort } : null,
        };

        result.push(domainObj);
    }

    return result;
}


// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
    // Queries
    getProfileTags,
    getSubscriberByCli,
    getVWSNodes,

    // Helpers (for internal use)
    buildTagPayload,
    invalidateProfileTagsCache,
    invalidateSubscriberCache,
    formatVWSNodes,

    // Constants (for tests / other callers)
    TTL,
    KEYS,
};