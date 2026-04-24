/**
 * OCNCC Profile Management API Router.
 * Exposes BbsProfileBlock operations as REST endpoints for decode, inspect,
 * modify, compare, and bulk profile operations.
 *
 * All routes accept a profile as:
 *   - base64 string (as returned by Oracle LONG RAW / database-api)
 *   - hex string (even-length, [0-9a-fA-F]+)
 *
 * All write operations (upsert, add, update, remove, merge, subtract, filter)
 * return the modified profile as base64 so it can be round-tripped back to
 * Oracle via the subscriber update flow.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const express = require('express');
const { ProfileError, ERR } = require('../database/BbsProfileBlock.js');

/**
 * Create the profile management API router.
 *
 * @param {import('../database/BbsProfileBlock').BbsProfileBlock}  profileParser
 * @returns {express.Router}
 */
function createProfileRouter(profileParser) {
    const router = express.Router();

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Map a ProfileError code to an appropriate HTTP status code.
     */
    function profileErrStatus(err) {
        if (!(err instanceof ProfileError)) return 500;
        switch (err.code) {
            case ERR.TAG_NOT_FOUND: return 404;
            case ERR.TAG_EXISTS: return 409;
            case ERR.INVALID_PROFILE: return 400;
            case ERR.INVALID_TAG_FORMAT: return 400;
            case ERR.INVALID_OFFSET: return 400;
            case ERR.MEMORY_EXCEEDED: return 413;
            default: return 400;
        }
    }

    /**
     * Centralised error handler for profile routes.
     * Preserves the ProfileError code in the response so clients can branch on it.
     */
    function handleProfileError(res, err, context) {
        const status = profileErrStatus(err);
        console.error(`[Profile-API] ${context}:`, err.message);
        res.status(status).json({
            error: err.message,
            code: err instanceof ProfileError ? err.code : 'INTERNAL_ERROR',
            context,
        });
    }

    /**
     * Extract and validate the `profile` field from req.body.
     * Returns null and sends 400 if missing.
     */
    function requireProfile(res, body, field = 'profile') {
        const val = body?.[field];
        if (!val || typeof val !== 'string') {
            res.status(400).json({
                error: `Missing or invalid field: '${field}' (base64 or hex string required)`,
                code: 'MISSING_FIELD',
            });
            return null;
        }
        return val;
    }

    // =========================================================================
    // DECODE / INSPECT
    // =========================================================================

    // -------------------------------------------------------------------------
    // POST /profile/decode
    // Full decode of a profile blob — returns all tags with friendly names,
    // typed values, and optionally raw hex and statistics.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/decode:
     *   post:
     *     tags: [Profile]
     *     summary: Decode a full profile blob into typed tag values
     *     description: >
     *       Decodes a base64 or hex-encoded profile block, returning all
     *       tags with friendly names (if tag metadata is loaded), typed values,
     *       and optional raw hex bytes and profile statistics.
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile]
     *             properties:
     *               profile:
     *                 type: string
     *                 description: Base64 or hex-encoded profile blob
     *               friendlyNames:
     *                 type: boolean
     *                 default: true
     *                 description: Enrich tags with name/type from loaded metadata
     *               includeRaw:
     *                 type: boolean
     *                 default: false
     *                 description: Include rawHex and hexDump per tag
     *               includeStats:
     *                 type: boolean
     *                 default: false
     *                 description: Include profile size and index statistics
     *     responses:
     *       200:
     *         description: Decoded profile
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 valid: { type: boolean }
     *                 tagCount: { type: integer }
     *                 metadataLoaded: { type: boolean }
     *                 tags:
     *                   type: array
     *                   items:
     *                     type: object
     *                     properties:
     *                       tagId:             { type: string }
     *                       value:             {}
     *                       display:           { type: string }
     *                       rawHex:            { type: string }
     *                       name:              { type: string }
     *                       type:              { type: string }
     *                       parentTagId:       { type: string }
     *                       isInputParameter:  { type: boolean }
     *       400:
     *         description: Invalid profile input
     */
    router.post('/decode', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const {
            friendlyNames = true,
            includeRaw = false,
            includeStats = false,
        } = req.body;

        try {
            const result = profileParser.decodeProfile(profile, {
                friendlyNames,
                includeRaw,
                includeStats,
            });
            if (!result.valid) {
                return res.status(400).json({ error: result.error || 'Invalid profile structure', code: ERR.INVALID_PROFILE });
            }
            res.json(result);
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/decode');
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/validate
    // Lightweight structural validation — does not fully decode.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/validate:
     *   post:
     *     tags: [Profile]
     *     summary: Validate profile structure without full decode
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile]
     *             properties:
     *               profile:
     *                 type: string
     *               strict:
     *                 type: boolean
     *                 default: false
     *                 description: Also verify every data offset (slower)
     *     responses:
     *       200:
     *         description: Validation result
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 valid:    { type: boolean }
     *                 tagCount: { type: integer }
     *                 stats:
     *                   type: object
     *                   properties:
     *                     totalSize:  { type: integer }
     *                     indexSize:  { type: integer }
     *                     dataSize:   { type: integer }
     *       400:
     *         description: Missing profile field
     */
    router.post('/validate', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { strict = false } = req.body;

        try {
            const buf = profileParser._toBuffer(profile);
            const valid = profileParser.validateProfile(buf, strict);
            const stats = valid ? profileParser.getProfileStats(buf) : null;
            res.json({ valid, tagCount: stats?.tagCount ?? 0, stats });
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/validate');
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/stats
    // Return size and index statistics for a profile.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/stats:
     *   post:
     *     tags: [Profile]
     *     summary: Return profile size and index statistics
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile]
     *             properties:
     *               profile: { type: string }
     *     responses:
     *       200:
     *         description: Profile statistics
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 tagCount:   { type: integer }
     *                 totalSize:  { type: integer }
     *                 indexSize:  { type: integer }
     *                 dataSize:   { type: integer }
     */
    router.post('/stats', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        try {
            const stats = profileParser.getProfileStats(profile);
            res.json(stats);
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/stats');
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/dump
    // Human-readable text dump (mirrors legacy Oracle report format).
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/dump:
     *   post:
     *     tags: [Profile]
     *     summary: Return a human-readable text dump of the profile
     *     description: >
     *       Formats the profile as a table matching the legacy Oracle report layout:
     *       Tag / Desc / Len / HexData. Useful for debugging and support tickets.
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile]
     *             properties:
     *               profile:       { type: string }
     *               friendlyNames: { type: boolean, default: true }
     *               format:
     *                 type: string
     *                 enum: [table, raw]
     *                 default: table
     *                 description: >
     *                   table = legacy Oracle report format,
     *                   raw = internal debug dump
     *     responses:
     *       200:
     *         description: Text dump
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 dump: { type: string }
     */
    router.post('/dump', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { friendlyNames = true, format = 'table' } = req.body;

        try {
            const dump = format === 'raw'
                ? profileParser.dumpProfile(profile)
                : profileParser.dumpTable(profile, { friendlyNames });
            res.json({ dump });
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/dump');
        }
    });

    // =========================================================================
    // TAG LOOKUP
    // =========================================================================

    // -------------------------------------------------------------------------
    // POST /profile/tag
    // Find a single tag by ID — returns typed value with metadata.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/tag:
     *   post:
     *     tags: [Profile]
     *     summary: Find a single tag by ID
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile, tagId]
     *             properties:
     *               profile:    { type: string }
     *               tagId:
     *                 type: string
     *                 description: 8-char hex tag ID, e.g. "0000001A"
     *               includeRaw: { type: boolean, default: false }
     *     responses:
     *       200:
     *         description: Tag found
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 tagId:            { type: string }
     *                 value:            {}
     *                 display:          { type: string }
     *                 rawHex:           { type: string }
     *                 name:             { type: string }
     *                 type:             { type: string }
     *                 parentTagId:      { type: string }
     *                 isInputParameter: { type: boolean }
     *                 found:            { type: boolean }
     *       400:
     *         description: Missing field or invalid tag format
     *       404:
     *         description: Tag not found in profile
     */
    router.post('/tag', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { tagId, includeRaw = false } = req.body;
        if (!tagId) {
            return res.status(400).json({ error: "Missing required field: 'tagId'", code: 'MISSING_FIELD' });
        }

        try {
            const raw = profileParser.findTagRaw(profile, tagId);
            const info = profileParser.getTagInfo(tagId);
            const interpreted = profileParser._interpretRaw(raw, info?.type ?? null);

            const result = {
                found: true,
                tagId: profileParser._normalizeTagId(tagId),
                value: interpreted.value,
                display: interpreted.display,
                name: info?.name ?? null,
                type: info?.type ?? null,
                parentTagId: info?.parentTagId ?? null,
                isInputParameter: info?.isInputParameter ?? null,
            };
            if (includeRaw) {
                result.rawHex = raw.toString('hex').toUpperCase();
                result.hexDump = interpreted.hex;
            }

            res.json(result);
        } catch (err) {
            handleProfileError(res, err, `POST /profile/tag [tagId=${tagId}]`);
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/tag/exists
    // Lightweight existence check — no full decode.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/tag/exists:
     *   post:
     *     tags: [Profile]
     *     summary: Check whether a tag exists in the profile
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile, tagId]
     *             properties:
     *               profile: { type: string }
     *               tagId:   { type: string }
     *     responses:
     *       200:
     *         description: Existence check result
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 tagId:  { type: string }
     *                 exists: { type: boolean }
     */
    router.post('/tag/exists', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { tagId } = req.body;
        if (!tagId) {
            return res.status(400).json({ error: "Missing required field: 'tagId'", code: 'MISSING_FIELD' });
        }

        try {
            const exists = profileParser.tagExists(profile, tagId);
            res.json({ tagId: profileParser._normalizeTagId(tagId), exists });
        } catch (err) {
            handleProfileError(res, err, `POST /profile/tag/exists [tagId=${tagId}]`);
        }
    });

    // =========================================================================
    // TAG MODIFICATION
    // All write routes return the modified profile as base64.
    // =========================================================================

    // -------------------------------------------------------------------------
    // POST /profile/tag/upsert
    // Add or update a tag. Maintains sorted order. Safe for existing or new tags.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/tag/upsert:
     *   post:
     *     tags: [Profile]
     *     summary: Add or update a tag (upsert)
     *     description: >
     *       Inserts the tag if absent, updates if present. Maintains the sorted
     *       index order required by the format.
     *       Returns the modified profile as base64.
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile, tagId, value]
     *             properties:
     *               profile: { type: string }
     *               tagId:   { type: string }
     *               value:
     *                 description: >
     *                   String (UTF-8), integer, or base64/hex raw bytes.
     *                   Integers are stored as uint32 big-endian.
     *     responses:
     *       200:
     *         description: Modified profile
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 profile:  { type: string, description: Base64-encoded modified profile }
     *                 tagId:    { type: string }
     *                 operation: { type: string, enum: [upserted] }
     *       400:
     *         description: Invalid input
     */
    router.post('/tag/upsert', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { tagId, value } = req.body;
        if (!tagId) return res.status(400).json({ error: "Missing required field: 'tagId'", code: 'MISSING_FIELD' });
        if (value === undefined) return res.status(400).json({ error: "Missing required field: 'value'", code: 'MISSING_FIELD' });

        try {
            const modified = profileParser.upsertTag(profile, tagId, value);
            res.json({
                profile: profileParser.encodeProfileToBase64(modified),
                tagId: profileParser._normalizeTagId(tagId),
                operation: 'upserted',
            });
        } catch (err) {
            handleProfileError(res, err, `POST /profile/tag/upsert [tagId=${tagId}]`);
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/tag/add
    // Add a new tag — returns 409 Conflict if the tag already exists.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/tag/add:
     *   post:
     *     tags: [Profile]
     *     summary: Add a new tag (fails if already exists)
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile, tagId, value]
     *             properties:
     *               profile: { type: string }
     *               tagId:   { type: string }
     *               value:   {}
     *     responses:
     *       200:
     *         description: Profile with new tag added
     *       409:
     *         description: Tag already exists
     */
    router.post('/tag/add', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { tagId, value } = req.body;
        if (!tagId) return res.status(400).json({ error: "Missing required field: 'tagId'", code: 'MISSING_FIELD' });
        if (value === undefined) return res.status(400).json({ error: "Missing required field: 'value'", code: 'MISSING_FIELD' });

        try {
            const modified = profileParser.addTag(profile, tagId, value);
            res.json({
                profile: profileParser.encodeProfileToBase64(modified),
                tagId: profileParser._normalizeTagId(tagId),
                operation: 'added',
            });
        } catch (err) {
            handleProfileError(res, err, `POST /profile/tag/add [tagId=${tagId}]`);
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/tag/update
    // Update existing tag — returns 404 if the tag does not exist.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/tag/update:
     *   post:
     *     tags: [Profile]
     *     summary: Update an existing tag (fails if not found)
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile, tagId, value]
     *             properties:
     *               profile: { type: string }
     *               tagId:   { type: string }
     *               value:   {}
     *     responses:
     *       200:
     *         description: Profile with tag updated
     *       404:
     *         description: Tag not found
     */
    router.post('/tag/update', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { tagId, value } = req.body;
        if (!tagId) return res.status(400).json({ error: "Missing required field: 'tagId'", code: 'MISSING_FIELD' });
        if (value === undefined) return res.status(400).json({ error: "Missing required field: 'value'", code: 'MISSING_FIELD' });

        try {
            const modified = profileParser.updateTag(profile, tagId, value);
            res.json({
                profile: profileParser.encodeProfileToBase64(modified),
                tagId: profileParser._normalizeTagId(tagId),
                operation: 'updated',
            });
        } catch (err) {
            handleProfileError(res, err, `POST /profile/tag/update [tagId=${tagId}]`);
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/tag/remove
    // Remove a tag. Silent no-op if the tag does not exist.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/tag/remove:
     *   post:
     *     tags: [Profile]
     *     summary: Remove a tag from the profile
     *     description: Silent no-op if the tag is not present.
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile, tagId]
     *             properties:
     *               profile: { type: string }
     *               tagId:   { type: string }
     *     responses:
     *       200:
     *         description: Profile with tag removed (or unchanged if not present)
     */
    router.post('/tag/remove', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { tagId } = req.body;
        if (!tagId) return res.status(400).json({ error: "Missing required field: 'tagId'", code: 'MISSING_FIELD' });

        try {
            const modified = profileParser.removeTag(profile, tagId);
            res.json({
                profile: profileParser.encodeProfileToBase64(modified),
                tagId: profileParser._normalizeTagId(tagId),
                operation: 'removed',
            });
        } catch (err) {
            handleProfileError(res, err, `POST /profile/tag/remove [tagId=${tagId}]`);
        }
    });

    // =========================================================================
    // PROFILE COMPARISON
    // =========================================================================

    // -------------------------------------------------------------------------
    // POST /profile/compare
    // Structural diff between two profiles — returns changed/added/removed tags.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/compare:
     *   post:
     *     tags: [Profile]
     *     summary: Compare two profiles and return tag-level differences
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile1, profile2]
     *             properties:
     *               profile1:   { type: string, description: Original profile (base64 or hex) }
     *               profile2:   { type: string, description: New profile (base64 or hex) }
     *               textReport: { type: boolean, default: false, description: Also return a formatted text report }
     *     responses:
     *       200:
     *         description: Diff result
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 identical:  { type: boolean }
     *                 diffCount:  { type: integer }
     *                 diffs:
     *                   type: array
     *                   items:
     *                     type: object
     *                     properties:
     *                       tagId:         { type: string }
     *                       changeType:    { type: string, enum: [added, removed, changed] }
     *                       originalValue: {}
     *                       newValue:      {}
     *                       tagInfo:
     *                         type: object
     *                         properties:
     *                           name: { type: string }
     *                           type: { type: string }
     *                 report: { type: string, description: Text report (if textReport=true) }
     */
    router.post('/compare', (req, res) => {
        const profile1 = requireProfile(res, req.body, 'profile1');
        if (!profile1) return;
        const profile2 = requireProfile(res, req.body, 'profile2');
        if (!profile2) return;

        const { textReport = false } = req.body;

        try {
            const identical = profileParser.profilesMatch(profile1, profile2);
            const diffs = identical ? [] : profileParser.profileDiff(profile1, profile2);

            const result = { identical, diffCount: diffs.length, diffs };
            if (textReport) {
                result.report = identical
                    ? profileParser.compareProfiles(profile1, profile2)
                    : profileParser.profileDiffAsString(profile1, profile2);
            }
            res.json(result);
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/compare');
        }
    });

    // =========================================================================
    // BULK OPERATIONS
    // =========================================================================

    // -------------------------------------------------------------------------
    // POST /profile/merge
    // Merge two profiles. Tags in profile2 override profile1.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/merge:
     *   post:
     *     tags: [Profile]
     *     summary: Merge two profiles (profile2 overrides profile1)
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile1, profile2]
     *             properties:
     *               profile1: { type: string }
     *               profile2: { type: string }
     *     responses:
     *       200:
     *         description: Merged profile
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 profile:  { type: string }
     *                 tagCount: { type: integer }
     *                 operation: { type: string, enum: [merged] }
     */
    router.post('/merge', (req, res) => {
        const profile1 = requireProfile(res, req.body, 'profile1');
        if (!profile1) return;
        const profile2 = requireProfile(res, req.body, 'profile2');
        if (!profile2) return;

        try {
            const merged = profileParser.mergeProfiles(profile1, profile2);
            res.json({
                profile: profileParser.encodeProfileToBase64(merged),
                tagCount: profileParser.tagCount(merged),
                operation: 'merged',
            });
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/merge');
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/subtract
    // Subtract profile2 from profile1 — removes any tags that appear in profile2.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/subtract:
     *   post:
     *     tags: [Profile]
     *     summary: Subtract profile2 from profile1 (remove matching tags)
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile1, profile2]
     *             properties:
     *               profile1: { type: string, description: Base profile }
     *               profile2: { type: string, description: Tags to remove }
     *     responses:
     *       200:
     *         description: Reduced profile
     */
    router.post('/subtract', (req, res) => {
        const profile1 = requireProfile(res, req.body, 'profile1');
        if (!profile1) return;
        const profile2 = requireProfile(res, req.body, 'profile2');
        if (!profile2) return;

        try {
            const result = profileParser.subtractProfiles(profile1, profile2);
            res.json({
                profile: profileParser.encodeProfileToBase64(result),
                tagCount: profileParser.tagCount(result),
                operation: 'subtracted',
            });
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/subtract');
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/filter
    // Keep only the specified tags, discard all others.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/filter:
     *   post:
     *     tags: [Profile]
     *     summary: Keep only specified tags, remove all others
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile, tagIds]
     *             properties:
     *               profile: { type: string }
     *               tagIds:
     *                 type: array
     *                 items: { type: string }
     *                 description: Array of tag IDs to keep
     *     responses:
     *       200:
     *         description: Filtered profile
     */
    router.post('/filter', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        const { tagIds } = req.body;
        if (!Array.isArray(tagIds) || tagIds.length === 0) {
            return res.status(400).json({ error: "Field 'tagIds' must be a non-empty array of tag ID strings", code: 'MISSING_FIELD' });
        }

        try {
            const filtered = profileParser.filterTags(profile, tagIds);
            res.json({
                profile: profileParser.encodeProfileToBase64(filtered),
                tagCount: profileParser.tagCount(filtered),
                requestedTags: tagIds.length,
                operation: 'filtered',
            });
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/filter');
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/clear
    // Remove all tags — returns an empty profile (4-byte header).
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/clear:
     *   post:
     *     tags: [Profile]
     *     summary: Clear all tags and return an empty profile
     *     description: >
     *       Returns the minimal valid empty profile (4-byte zero header).
     *       No request body needed — the profile field is ignored.
     *     requestBody:
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             properties:
     *               profile: { type: string, description: Ignored }
     *     responses:
     *       200:
     *         description: Empty profile
     */
    router.post('/clear', (_req, res) => {
        const empty = profileParser.clearAllTags();
        res.json({
            profile: profileParser.encodeProfileToBase64(empty),
            tagCount: 0,
            operation: 'cleared',
        });
    });

    // =========================================================================
    // ENCODING UTILITIES
    // =========================================================================

    // -------------------------------------------------------------------------
    // POST /profile/encode/base64
    // Re-encode a profile to base64 (e.g. after receiving it as hex).
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/encode/base64:
     *   post:
     *     tags: [Profile]
     *     summary: Re-encode a profile to base64
     *     description: Accepts hex or base64 input, always returns base64.
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile]
     *             properties:
     *               profile: { type: string }
     *     responses:
     *       200:
     *         description: Base64-encoded profile
     */
    router.post('/encode/base64', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        try {
            const buf = profileParser._toBuffer(profile);
            res.json({ profile: profileParser.encodeProfileToBase64(buf) });
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/encode/base64');
        }
    });

    // -------------------------------------------------------------------------
    // POST /profile/encode/hex
    // Re-encode a profile to hex (useful for debugging or Wireshark input).
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/encode/hex:
     *   post:
     *     tags: [Profile]
     *     summary: Re-encode a profile to uppercase hex
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [profile]
     *             properties:
     *               profile: { type: string }
     *     responses:
     *       200:
     *         description: Hex-encoded profile
     */
    router.post('/encode/hex', (req, res) => {
        const profile = requireProfile(res, req.body);
        if (!profile) return;

        try {
            const buf = profileParser._toBuffer(profile);
            res.json({ profile: profileParser.encodeProfileToHex(buf) });
        } catch (err) {
            handleProfileError(res, err, 'POST /profile/encode/hex');
        }
    });

    // =========================================================================
    // METADATA STATUS
    // =========================================================================

    // -------------------------------------------------------------------------
    // GET /profile/metadata/status
    // Show whether tag metadata is loaded in the parser.
    // Matches the pattern of GET /db/profile-tags/status in database-api.js.
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/metadata/status:
     *   get:
     *     tags: [Profile]
     *     summary: Report whether profile tag metadata is loaded in the parser
     *     responses:
     *       200:
     *         description: Metadata status
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 metadataLoaded: { type: boolean }
     *                 tagCount:       { type: integer }
     *                 treeLoaded:     { type: boolean }
     */
    router.get('/metadata/status', (_req, res) => {
        const loaded = !!(profileParser && profileParser._tagMeta);
        const tagCount = loaded ? profileParser._tagMeta.size : 0;
        const treeLoaded = !!(profileParser && profileParser._tagTree);

        res.json({ metadataLoaded: loaded, tagCount, treeLoaded });
    });

    // -------------------------------------------------------------------------
    // GET /profile/metadata/tag/:tagId
    // Look up friendly name/type info for a single tag ID (no profile needed).
    // -------------------------------------------------------------------------
    /**
     * @swagger
     * /profile/metadata/tag/{tagId}:
     *   get:
     *     tags: [Profile]
     *     summary: Look up metadata for a tag ID (no profile needed)
     *     parameters:
     *       - in: path
     *         name: tagId
     *         required: true
     *         schema: { type: string }
     *         description: 8-char hex tag ID, e.g. "0000001A"
     *     responses:
     *       200:
     *         description: Tag metadata
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 tagId:            { type: string }
     *                 name:             { type: string }
     *                 type:             { type: string }
     *                 parentTagId:      { type: string }
     *                 isInputParameter: { type: boolean }
     *                 found:            { type: boolean }
     *       404:
     *         description: Tag ID not found in loaded metadata
     */
    router.get('/metadata/tag/:tagId', (req, res) => {
        const { tagId } = req.params;

        try {
            const info = profileParser.getTagInfo(tagId);
            if (!info) {
                return res.status(404).json({
                    error: `Tag ID '${tagId}' not found in loaded metadata`,
                    code: ERR.TAG_NOT_FOUND,
                    found: false,
                });
            }
            res.json({ ...info, found: true });
        } catch (err) {
            handleProfileError(res, err, `GET /profile/metadata/tag/${tagId}`);
        }
    });

    return router;
}

module.exports = createProfileRouter;