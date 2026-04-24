/**
 * OCNCC Master Database API Router.
 * Handles all subscriber and profile metadata queries against Oracle.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const express = require('express');
const {
    getProfileTags,
    getSubscriberByCli,
    invalidateProfileTagsCache,
    invalidateSubscriberCache,
} = require('../database/database-queries');

const logger = require('../utils/logger');

/**
 * Create the database API router.
 *
 * @param {import('../oracle-connector')}                       db
 * @param {import('../BbsProfileBlock').BbsProfileBlock}        profileParser
 * @param {import('ioredis').Redis|null}                        redis
 * @returns {express.Router}
 */
function createDatabaseRouter(db, profileParser, redis) {
    const router = express.Router();

    // -------------------------------------------------------------------------
    // GET /db/subscriber?cli=447XXXXXXXXX[&decode=true][&refresh=true]
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /db/subscriber:
     *   get:
     *     tags: [Subscriber]
     *     summary: Look up a subscriber by CLI
     */
    router.get('/subscriber', async (req, res) => {
        const { cli, decode, refresh } = req.query;

        if (!cli) {
            return res.status(400).json({ error: 'Missing required parameter: cli' });
        }

        try {
            const result = await getSubscriberByCli(db, redis, cli, {
                forceRefresh: refresh === 'true' || refresh === '1',
                decodeProfile: decode === 'true' || decode === '1',
                profileParser: profileParser,
            });

            if (result.count === 0) {
                return res.status(404).json({ message: 'Subscriber not found' });
            }

            res.json(result);
        } catch (err) {
            logger.error('[DB-API] GET /subscriber error:', err);
            res.status(500).json({ error: 'Internal server error', details: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // GET /db/subscriber/:cli/profile?decode=true
    // Convenience route — returns just the profile (raw base64 or decoded JSON)
    // -------------------------------------------------------------------------
    router.get('/subscriber/:cli/profile', async (req, res) => {
        const { cli } = req.params;
        const decode = req.query.decode !== 'false';   // default: true

        try {
            const result = await getSubscriberByCli(db, redis, cli, {
                decodeProfile: decode,
                profileParser: profileParser,
            });

            if (result.count === 0) {
                return res.status(404).json({ message: 'Subscriber not found' });
            }
            //car.cli, car.service_state, car.profile, caar.account, 
            //caar.wallet_type, ca.be_acct_id, ca.be_acct_engine_id, cat.name, ac.name
            const row = result.data[0];
            res.json({
                cli: row.cli,
                profile: decode ? row.decodedProfile : row.profile,
            });
        } catch (err) {
            logger.error('[DB-API] GET /subscriber/:cli/profile error:', err);
            res.status(500).json({ error: 'Internal server error', details: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // DELETE /db/subscriber/:cli/cache
    // Force invalidation of a cached subscriber record
    // -------------------------------------------------------------------------
    router.delete('/subscriber/:cli/cache', async (req, res) => {
        try {
            await invalidateSubscriberCache(redis, req.params.cli);
            res.json({ message: `Cache invalidated for CLI ${req.params.cli}` });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // GET /db/profile-tags[?refresh=true]
    // Returns flat list + hierarchy tree of all profile tag definitions
    // -------------------------------------------------------------------------
    router.get('/profile-tags', async (req, res) => {
        const forceRefresh = req.query.refresh === 'true' || req.query.refresh === '1';

        try {
            const payload = await getProfileTags(db, redis, { forceRefresh });

            if (payload.count === 0) {
                return res.status(404).json({ message: 'No profile tag mappings found' });
            }

            // If refresh was requested, also reload profileParser metadata
            if (forceRefresh) {
                profileParser._tagMeta = new Map(payload.data.map(t => [t.tagId, t]));
                profileParser._tagTree = payload.tree;
                logger.info('[DB-API] profileParser tag metadata refreshed');
            }

            res.json(payload);
        } catch (err) {
            logger.error('[DB-API] GET /profile-tags error:', err);
            res.status(500).json({ error: 'Internal server error', details: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // DELETE /db/profile-tags/cache
    // Force Redis eviction — next call to /profile-tags will re-read DB
    // -------------------------------------------------------------------------
    router.delete('/profile-tags/cache', async (req, res) => {
        try {
            await invalidateProfileTagsCache(redis);
            res.json({ message: 'Profile tags cache invalidated' });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // GET /db/profile-tags/status
    // Show whether tag metadata is loaded in the parser and when it was cached
    // -------------------------------------------------------------------------
    router.get('/profile-tags/status', async (req, res) => {
        const loaded = !!(profileParser && profileParser._tagMeta);
        const tagCount = loaded ? profileParser._tagMeta.size : 0;

        let cachedAt = null;
        if (redis) {
            try {
                const ttl = await redis.ttl('db:profileTags');
                if (ttl > 0) {
                    // Approximate: loaded TTL.PROFILE_TAGS - remaining = age
                    const { TTL: TTL_CONSTS } = require('./database-queries');
                    cachedAt = new Date(Date.now() - (TTL_CONSTS.PROFILE_TAGS - ttl) * 1000).toISOString();
                }
            } catch { /* non-fatal */ }
        }

        res.json({
            parserLoaded: loaded,
            tagCount,
            cachedAt,
            redisEnabled: !!redis,
        });
    });

    return router;
}

module.exports = createDatabaseRouter;