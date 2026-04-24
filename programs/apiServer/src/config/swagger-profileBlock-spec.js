/**
 * OCNCC Profile Management API — OpenAPI Specification.
 * Separate spec for the BbsProfileBlock encode/decode/modify endpoints.
 * Merged into the main spec by server.js at startup.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

/**
 * Returns the paths, tags, and component additions for the profile API.
 * The result is merged into the main swagger spec object in server.js.
 *
 * @returns {{ tags: object[], paths: object, components: object }}
 */
function buildProfileSpec() {
    return {

        // -----------------------------------------------------------------------
        // Tags (appended to the main spec's tags array)
        // -----------------------------------------------------------------------
        tags: [
            { name: 'Profile — Decode / Inspect', description: 'Decode, validate, inspect, and dump profile blobs'         },
            { name: 'Profile — Tag Lookup',        description: 'Read individual tags from a profile'                        },
            { name: 'Profile — Tag Modification',  description: 'Write operations: add, update, upsert, remove tags'        },
            { name: 'Profile — Comparison',        description: 'Diff and match two profiles'                                },
            { name: 'Profile — Bulk Operations',   description: 'Merge, subtract, filter, and clear profile tag sets'       },
            { name: 'Profile — Encoding',          description: 'Re-encode a profile between base64 and hex representations' },
            { name: 'Profile — Metadata',          description: 'Tag metadata status and per-tag lookup'                    },
        ],

        // -----------------------------------------------------------------------
        // Paths (merged into the main spec's paths object)
        // -----------------------------------------------------------------------
        paths: {

            // ==================================================================
            // DECODE / INSPECT
            // ==================================================================

            '/profile/decode': {
                post: {
                    tags       : ['Profile — Decode / Inspect'],
                    summary    : 'Decode a full profile blob into typed tag values',
                    description: 'Decodes a base64 or hex-encoded profile block, returning all tags ' +
                                 'with friendly names (when tag metadata is loaded), typed values, ' +
                                 'and optional raw hex bytes and profile statistics.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileDecodeRequest' },
                                example: {
                                    profile     : 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...',
                                    friendlyNames: true,
                                    includeRaw  : false,
                                    includeStats: false,
                                },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Decoded profile',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/DecodedProfileResponse' },
                                    example: {
                                        valid          : true,
                                        tagCount       : 3,
                                        metadataLoaded : true,
                                        tags: [
                                            { tagId: '00000025', value: 1,    display: '1',     name: 'Language',                type: 'INT'  },
                                            { tagId: '0000002C', value: true, display: 'TRUE',  name: 'Outgoing BA List Ignore', type: 'BOOL' },
                                            { tagId: '0000004C', value: 'UK', display: 'UK',    name: 'Country Code',            type: 'STR'  },
                                        ],
                                    },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            '/profile/validate': {
                post: {
                    tags       : ['Profile — Decode / Inspect'],
                    summary    : 'Validate profile structure without full decode',
                    description: 'Performs a lightweight structural validation of the profile index ' +
                                 'and data section. Pass `strict=true` to also verify every data offset ' +
                                 '(slower but catches deeper corruption).',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : {
                                    type      : 'object',
                                    required  : ['profile'],
                                    properties: {
                                        profile: { $ref: '#/components/schemas/ProfileInput' },
                                        strict : { type: 'boolean', default: false, description: 'Also verify every data offset (slower)' },
                                    },
                                },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...', strict: false },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Validation result',
                            content: {
                                'application/json': {
                                    schema: {
                                        type      : 'object',
                                        properties: {
                                            valid   : { type: 'boolean' },
                                            tagCount: { type: 'integer' },
                                            stats   : { $ref: '#/components/schemas/ProfileStats', nullable: true },
                                        },
                                    },
                                    example: { valid: true, tagCount: 9, stats: { totalSize: 64, indexSize: 40, dataSize: 20, tagCount: 9 } },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            '/profile/stats': {
                post: {
                    tags       : ['Profile — Decode / Inspect'],
                    summary    : 'Return profile size and index statistics',
                    description: 'Returns byte-level statistics for the profile: total size, index ' +
                                 'section size, data section size, and tag count.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileOnlyRequest' },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...' },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Profile statistics',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/ProfileStats' },
                                    example: { tagCount: 9, totalSize: 64, indexSize: 40, dataSize: 20 },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            '/profile/dump': {
                post: {
                    tags       : ['Profile — Decode / Inspect'],
                    summary    : 'Return a human-readable text dump of the profile',
                    description: 'Formats the profile as a table matching the legacy Oracle report ' +
                                 'layout: Tag / Desc / Len / HexData. Useful for debugging and ' +
                                 'support tickets.\n\n' +
                                 '`format=table` (default) produces the legacy tabular layout. ' +
                                 '`format=raw` produces the internal debug dump.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema: {
                                    type      : 'object',
                                    required  : ['profile'],
                                    properties: {
                                        profile      : { $ref: '#/components/schemas/ProfileInput' },
                                        friendlyNames: { type: 'boolean', default: true },
                                        format       : { type: 'string', enum: ['table', 'raw'], default: 'table' },
                                    },
                                },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...', friendlyNames: true, format: 'table' },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Text dump',
                            content: {
                                'application/json': {
                                    schema : { type: 'object', properties: { dump: { type: 'string' } } },
                                    example: { dump: 'Tag       Desc                     Len  HexData\n00000025  Language                 4    00000001\n...' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            // ==================================================================
            // TAG LOOKUP
            // ==================================================================

            '/profile/tag': {
                post: {
                    tags       : ['Profile — Tag Lookup'],
                    summary    : 'Find a single tag by ID',
                    description: 'Looks up a tag by its 8-char hex tag ID and returns its typed ' +
                                 'value with metadata (name, type, parent). Pass `includeRaw=true` ' +
                                 'to also receive the raw hex bytes and a hex dump.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileTagRequest' },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...', tagId: '00000025', includeRaw: false },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Tag found',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/TagResult' },
                                    example: {
                                        found           : true,
                                        tagId           : '00000025',
                                        value           : 1,
                                        display         : '1',
                                        name            : 'Language',
                                        type            : 'INT',
                                        parentTagId     : null,
                                        isInputParameter: true,
                                    },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                        404: { $ref: '#/components/responses/ProfileError404' },
                    },
                },
            },

            '/profile/tag/exists': {
                post: {
                    tags       : ['Profile — Tag Lookup'],
                    summary    : 'Check whether a tag exists in the profile',
                    description: 'Lightweight existence check — avoids a full decode when you only ' +
                                 'need to know whether a specific tag is present.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : {
                                    type      : 'object',
                                    required  : ['profile', 'tagId'],
                                    properties: {
                                        profile: { $ref: '#/components/schemas/ProfileInput' },
                                        tagId  : { $ref: '#/components/schemas/TagId' },
                                    },
                                },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...', tagId: '00000025' },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Existence check result',
                            content: {
                                'application/json': {
                                    schema : {
                                        type      : 'object',
                                        properties: {
                                            tagId : { type: 'string' },
                                            exists: { type: 'boolean' },
                                        },
                                    },
                                    example: { tagId: '00000025', exists: true },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            // ==================================================================
            // TAG MODIFICATION
            // ==================================================================

            '/profile/tag/upsert': {
                post: {
                    tags       : ['Profile — Tag Modification'],
                    summary    : 'Add or update a tag (upsert)',
                    description: 'Inserts the tag if absent, or updates the value if the tag already ' +
                                 'exists. Maintains the sorted index order required by the format. ' +
                                 'Returns the modified profile as base64.\n\n' +
                                 '`value` may be a UTF-8 string, an integer (stored as uint32 BE), ' +
                                 'or a base64/hex raw byte sequence.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileTagValueRequest' },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...', tagId: '00000025', value: 2 },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Modified profile',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/ProfileWriteResponse' },
                                    example: { profile: 'AAAACQAAACUA...', tagId: '00000025', operation: 'upserted' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                        413: { $ref: '#/components/responses/ProfileError413' },
                    },
                },
            },

            '/profile/tag/add': {
                post: {
                    tags       : ['Profile — Tag Modification'],
                    summary    : 'Add a new tag (fails if already exists)',
                    description: 'Inserts the tag and value into the profile. Returns `409 Conflict` ' +
                                 'if the tag ID is already present — use `/profile/tag/upsert` if ' +
                                 'you want insert-or-replace behaviour.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileTagValueRequest' },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...', tagId: '0000004C', value: 'UK' },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Profile with new tag added',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/ProfileWriteResponse' },
                                    example: { profile: 'AAAACQ...', tagId: '0000004C', operation: 'added' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                        409: { $ref: '#/components/responses/ProfileError409' },
                        413: { $ref: '#/components/responses/ProfileError413' },
                    },
                },
            },

            '/profile/tag/update': {
                post: {
                    tags       : ['Profile — Tag Modification'],
                    summary    : 'Update an existing tag (fails if not found)',
                    description: 'Updates the value of a tag that must already be present in the ' +
                                 'profile. Returns `404` if the tag is not found — use ' +
                                 '`/profile/tag/upsert` if you want insert-or-replace behaviour.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileTagValueRequest' },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...', tagId: '00000025', value: 3 },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Profile with tag updated',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/ProfileWriteResponse' },
                                    example: { profile: 'AAAACQ...', tagId: '00000025', operation: 'updated' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                        404: { $ref: '#/components/responses/ProfileError404' },
                        413: { $ref: '#/components/responses/ProfileError413' },
                    },
                },
            },

            '/profile/tag/remove': {
                post: {
                    tags       : ['Profile — Tag Modification'],
                    summary    : 'Remove a tag from the profile',
                    description: 'Removes the specified tag. This is a silent no-op if the tag is ' +
                                 'not present — the modified (or unchanged) profile is always returned.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : {
                                    type      : 'object',
                                    required  : ['profile', 'tagId'],
                                    properties: {
                                        profile: { $ref: '#/components/schemas/ProfileInput' },
                                        tagId  : { $ref: '#/components/schemas/TagId' },
                                    },
                                },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...', tagId: '0000004C' },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Profile with tag removed (or unchanged if tag was not present)',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/ProfileWriteResponse' },
                                    example: { profile: 'AAAACQ...', tagId: '0000004C', operation: 'removed' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            // ==================================================================
            // PROFILE COMPARISON
            // ==================================================================

            '/profile/compare': {
                post: {
                    tags       : ['Profile — Comparison'],
                    summary    : 'Compare two profiles and return tag-level differences',
                    description: 'Performs a structural diff between `profile1` (original) and ' +
                                 '`profile2` (new), returning a list of added, removed, and changed ' +
                                 'tags. Pass `textReport=true` to also receive a formatted text report ' +
                                 'suitable for logging or support tickets.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileTwoRequest' },
                                example: {
                                    profile1  : 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...',
                                    profile2  : 'AAAACQAAACUAAABMAAAALAAAAFwAAAAu...',
                                    textReport: false,
                                },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Diff result',
                            content: {
                                'application/json': {
                                    schema: {
                                        type      : 'object',
                                        properties: {
                                            identical : { type: 'boolean' },
                                            diffCount : { type: 'integer' },
                                            diffs     : {
                                                type : 'array',
                                                items: { $ref: '#/components/schemas/ProfileDiff' },
                                            },
                                            report: { type: 'string', nullable: true, description: 'Text report (if textReport=true)' },
                                        },
                                    },
                                    example: {
                                        identical: false,
                                        diffCount: 1,
                                        diffs    : [
                                            { tagId: '00000025', changeType: 'changed', originalValue: 1, newValue: 2, tagInfo: { name: 'Language', type: 'INT' } },
                                        ],
                                    },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            // ==================================================================
            // BULK OPERATIONS
            // ==================================================================

            '/profile/merge': {
                post: {
                    tags       : ['Profile — Bulk Operations'],
                    summary    : 'Merge two profiles (profile2 overrides profile1)',
                    description: 'Combines all tags from both profiles. Where the same tag ID exists ' +
                                 'in both, the value from `profile2` wins. Returns the merged profile ' +
                                 'as base64.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileTwoRequest' },
                                example: {
                                    profile1: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...',
                                    profile2: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAu...',
                                },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Merged profile',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/ProfileBulkResponse' },
                                    example: { profile: 'AAAACQ...', tagCount: 12, operation: 'merged' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                        413: { $ref: '#/components/responses/ProfileError413' },
                    },
                },
            },

            '/profile/subtract': {
                post: {
                    tags       : ['Profile — Bulk Operations'],
                    summary    : 'Subtract profile2 from profile1 (remove matching tags)',
                    description: 'Removes from `profile1` any tag IDs that appear in `profile2`. ' +
                                 'Tag values in `profile2` are ignored — only the tag IDs are used ' +
                                 'for matching. Returns the reduced profile as base64.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema: {
                                    type      : 'object',
                                    required  : ['profile1', 'profile2'],
                                    properties: {
                                        profile1: { $ref: '#/components/schemas/ProfileInput', description: 'Base profile to subtract from' },
                                        profile2: { $ref: '#/components/schemas/ProfileInput', description: 'Profile whose tags will be removed from profile1' },
                                    },
                                },
                                example: {
                                    profile1: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...',
                                    profile2: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAu...',
                                },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Reduced profile',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/ProfileBulkResponse' },
                                    example: { profile: 'AAAACQ...', tagCount: 6, operation: 'subtracted' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            '/profile/filter': {
                post: {
                    tags       : ['Profile — Bulk Operations'],
                    summary    : 'Keep only specified tags, remove all others',
                    description: 'Retains only the tags whose IDs appear in `tagIds`, discarding ' +
                                 'everything else. Returns the filtered profile as base64.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema: {
                                    type      : 'object',
                                    required  : ['profile', 'tagIds'],
                                    properties: {
                                        profile: { $ref: '#/components/schemas/ProfileInput' },
                                        tagIds : {
                                            type       : 'array',
                                            items      : { type: 'string' },
                                            description: 'Tag IDs to keep',
                                            example    : ['00000025', '0000002C'],
                                        },
                                    },
                                },
                                example: {
                                    profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...',
                                    tagIds : ['00000025', '0000002C'],
                                },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Filtered profile',
                            content: {
                                'application/json': {
                                    schema: {
                                        type      : 'object',
                                        properties: {
                                            profile      : { type: 'string' },
                                            tagCount     : { type: 'integer' },
                                            requestedTags: { type: 'integer' },
                                            operation    : { type: 'string', enum: ['filtered'] },
                                        },
                                    },
                                    example: { profile: 'AAAACQ...', tagCount: 2, requestedTags: 2, operation: 'filtered' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            '/profile/clear': {
                post: {
                    tags       : ['Profile — Bulk Operations'],
                    summary    : 'Clear all tags and return an empty profile',
                    description: 'Returns the minimal valid empty profile (4-byte zero header). ' +
                                 'The `profile` field in the request body is ignored — no input ' +
                                 'profile is required.',
                    requestBody: {
                        content: {
                            'application/json': {
                                schema : {
                                    type      : 'object',
                                    properties: {
                                        profile: { type: 'string', description: 'Ignored — included only for API consistency' },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Empty profile',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/ProfileBulkResponse' },
                                    example: { profile: 'AAAAAA==', tagCount: 0, operation: 'cleared' },
                                },
                            },
                        },
                    },
                },
            },

            // ==================================================================
            // ENCODING UTILITIES
            // ==================================================================

            '/profile/encode/base64': {
                post: {
                    tags       : ['Profile — Encoding'],
                    summary    : 'Re-encode a profile to base64',
                    description: 'Accepts a profile as either base64 or hex and always returns ' +
                                 'base64. Useful when a downstream system (e.g. Oracle LONG RAW ' +
                                 'insert) requires base64 but you received the profile as hex.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileOnlyRequest' },
                                example: { profile: '0000000900000025...' },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Base64-encoded profile',
                            content: {
                                'application/json': {
                                    schema : { type: 'object', properties: { profile: { type: 'string', description: 'Base64-encoded profile' } } },
                                    example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            '/profile/encode/hex': {
                post: {
                    tags       : ['Profile — Encoding'],
                    summary    : 'Re-encode a profile to uppercase hex',
                    description: 'Accepts a profile as either base64 or hex and always returns ' +
                                 'uppercase hex. Useful for debugging, Wireshark input, or any ' +
                                 'tool that prefers hex over base64.',
                    requestBody: {
                        required: true,
                        content : {
                            'application/json': {
                                schema : { $ref: '#/components/schemas/ProfileOnlyRequest' },
                                example: { profile: 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...' },
                            },
                        },
                    },
                    responses: {
                        200: {
                            description: 'Hex-encoded profile',
                            content: {
                                'application/json': {
                                    schema : { type: 'object', properties: { profile: { type: 'string', description: 'Uppercase hex-encoded profile' } } },
                                    example: { profile: '0000000900000025000000250000004C...' },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/ProfileError400' },
                    },
                },
            },

            // ==================================================================
            // METADATA
            // ==================================================================

            '/profile/metadata/status': {
                get: {
                    tags       : ['Profile — Metadata'],
                    summary    : 'Report whether profile tag metadata is loaded in the parser',
                    description: 'Shows whether `BbsProfileBlock` has tag definitions loaded ' +
                                 '(populated from `ACS_PROFILE_DETAILS` via `/db/profile-tags`), ' +
                                 'how many tags are known, and whether the hierarchy tree is available.',
                    responses: {
                        200: {
                            description: 'Metadata status',
                            content: {
                                'application/json': {
                                    schema: {
                                        type      : 'object',
                                        properties: {
                                            metadataLoaded: { type: 'boolean' },
                                            tagCount      : { type: 'integer' },
                                            treeLoaded    : { type: 'boolean' },
                                        },
                                    },
                                    example: { metadataLoaded: true, tagCount: 124, treeLoaded: true },
                                },
                            },
                        },
                    },
                },
            },

            '/profile/metadata/tag/{tagId}': {
                get: {
                    tags       : ['Profile — Metadata'],
                    summary    : 'Look up metadata for a tag ID (no profile needed)',
                    description: 'Returns the friendly name, data type, parent tag, and input-parameter ' +
                                 'flag for a single tag ID. No profile blob is required — this queries ' +
                                 'the in-process metadata map loaded from `ACS_PROFILE_DETAILS`.',
                    parameters : [
                        {
                            name       : 'tagId',
                            in         : 'path',
                            required   : true,
                            description: '8-char hex tag ID, e.g. `00000025`',
                            schema     : { type: 'string', example: '00000025' },
                        },
                    ],
                    responses: {
                        200: {
                            description: 'Tag metadata',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/TagMetadata' },
                                    example: {
                                        tagId           : '00000025',
                                        name            : 'Language',
                                        type            : 'INT',
                                        parentTagId     : null,
                                        isInputParameter: true,
                                        found           : true,
                                    },
                                },
                            },
                        },
                        404: { $ref: '#/components/responses/ProfileError404' },
                    },
                },
            },
        },

        // -----------------------------------------------------------------------
        // Component additions (merged into main spec's components)
        // -----------------------------------------------------------------------
        components: {
            schemas: {

                // ------------------------------------------------------------------
                // Reusable primitives
                // ------------------------------------------------------------------
                ProfileInput: {
                    type       : 'string',
                    description: 'Base64 or hex-encoded profile blob',
                    example    : 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...',
                },

                TagId: {
                    type       : 'string',
                    description: '8-char hex tag ID',
                    example    : '00000025',
                },

                // ------------------------------------------------------------------
                // Request bodies
                // ------------------------------------------------------------------
                ProfileOnlyRequest: {
                    type      : 'object',
                    required  : ['profile'],
                    properties: {
                        profile: { $ref: '#/components/schemas/ProfileInput' },
                    },
                },

                ProfileDecodeRequest: {
                    type      : 'object',
                    required  : ['profile'],
                    properties: {
                        profile      : { $ref: '#/components/schemas/ProfileInput' },
                        friendlyNames: { type: 'boolean', default: true,  description: 'Enrich tags with name/type from loaded metadata' },
                        includeRaw   : { type: 'boolean', default: false, description: 'Include rawHex and hexDump per tag' },
                        includeStats : { type: 'boolean', default: false, description: 'Include profile size and index statistics' },
                    },
                },

                ProfileTagRequest: {
                    type      : 'object',
                    required  : ['profile', 'tagId'],
                    properties: {
                        profile   : { $ref: '#/components/schemas/ProfileInput' },
                        tagId     : { $ref: '#/components/schemas/TagId' },
                        includeRaw: { type: 'boolean', default: false, description: 'Include rawHex and hexDump in response' },
                    },
                },

                ProfileTagValueRequest: {
                    type      : 'object',
                    required  : ['profile', 'tagId', 'value'],
                    properties: {
                        profile: { $ref: '#/components/schemas/ProfileInput' },
                        tagId  : { $ref: '#/components/schemas/TagId' },
                        value  : {
                            description: 'String (UTF-8), integer (stored as uint32 BE), or base64/hex raw bytes',
                            example    : 1,
                        },
                    },
                },

                ProfileTwoRequest: {
                    type      : 'object',
                    required  : ['profile1', 'profile2'],
                    properties: {
                        profile1  : { $ref: '#/components/schemas/ProfileInput' },
                        profile2  : { $ref: '#/components/schemas/ProfileInput' },
                        textReport: { type: 'boolean', default: false, description: 'Also return a formatted text diff report' },
                    },
                },

                // ------------------------------------------------------------------
                // Response bodies
                // ------------------------------------------------------------------
                ProfileStats: {
                    type      : 'object',
                    properties: {
                        tagCount : { type: 'integer', description: 'Number of tags in the profile' },
                        totalSize: { type: 'integer', description: 'Total profile size in bytes' },
                        indexSize: { type: 'integer', description: 'Size of the index section in bytes' },
                        dataSize : { type: 'integer', description: 'Size of the data section in bytes' },
                    },
                },

                TagResult: {
                    type      : 'object',
                    properties: {
                        found           : { type: 'boolean' },
                        tagId           : { type: 'string',  example: '00000025' },
                        value           : { description: 'Typed value (number, boolean, or string)' },
                        display         : { type: 'string',  description: 'Human-readable string representation' },
                        name            : { type: 'string',  nullable: true, example: 'Language' },
                        type            : { type: 'string',  nullable: true, example: 'INT' },
                        parentTagId     : { type: 'string',  nullable: true },
                        isInputParameter: { type: 'boolean', nullable: true },
                        rawHex          : { type: 'string',  nullable: true, description: 'Raw hex bytes (if includeRaw=true)' },
                        hexDump         : { type: 'string',  nullable: true, description: 'Hex dump (if includeRaw=true)' },
                    },
                },

                TagMetadata: {
                    type      : 'object',
                    properties: {
                        tagId           : { type: 'string',  example: '00000025' },
                        name            : { type: 'string',  example: 'Language' },
                        type            : { type: 'string',  example: 'INT', enum: ['INT', 'BOOL', 'STR', 'RAW'] },
                        parentTagId     : { type: 'string',  nullable: true },
                        isInputParameter: { type: 'boolean' },
                        found           : { type: 'boolean' },
                    },
                },

                DecodedProfileResponse: {
                    type      : 'object',
                    properties: {
                        valid         : { type: 'boolean' },
                        tagCount      : { type: 'integer' },
                        metadataLoaded: { type: 'boolean' },
                        tags          : {
                            type : 'array',
                            items: { $ref: '#/components/schemas/TagResult' },
                        },
                        stats: { $ref: '#/components/schemas/ProfileStats', nullable: true },
                    },
                },

                ProfileWriteResponse: {
                    type      : 'object',
                    properties: {
                        profile  : { type: 'string', description: 'Base64-encoded modified profile' },
                        tagId    : { type: 'string' },
                        operation: { type: 'string', enum: ['upserted', 'added', 'updated', 'removed'] },
                    },
                },

                ProfileBulkResponse: {
                    type      : 'object',
                    properties: {
                        profile  : { type: 'string', description: 'Base64-encoded result profile' },
                        tagCount : { type: 'integer' },
                        operation: { type: 'string', enum: ['merged', 'subtracted', 'filtered', 'cleared'] },
                    },
                },

                ProfileDiff: {
                    type      : 'object',
                    properties: {
                        tagId        : { type: 'string' },
                        changeType   : { type: 'string', enum: ['added', 'removed', 'changed'] },
                        originalValue: { description: 'Value in profile1 (null if added)', nullable: true },
                        newValue     : { description: 'Value in profile2 (null if removed)', nullable: true },
                        tagInfo      : {
                            type      : 'object',
                            nullable  : true,
                            properties: {
                                name: { type: 'string' },
                                type: { type: 'string' },
                            },
                        },
                    },
                },
            },

            responses: {
                ProfileError400: {
                    description: 'Bad request — missing or invalid field, or invalid profile structure',
                    content    : {
                        'application/json': {
                            schema : {
                                type      : 'object',
                                properties: {
                                    error  : { type: 'string' },
                                    code   : { type: 'string', description: 'ProfileError code, e.g. INVALID_PROFILE, MISSING_FIELD' },
                                    context: { type: 'string' },
                                },
                            },
                            example: { error: "Missing or invalid field: 'profile' (base64 or hex string required)", code: 'MISSING_FIELD', context: 'POST /profile/decode' },
                        },
                    },
                },
                ProfileError404: {
                    description: 'Tag not found — the specified tag ID does not exist in the profile or metadata',
                    content    : {
                        'application/json': {
                            schema : {
                                type      : 'object',
                                properties: {
                                    error: { type: 'string' },
                                    code : { type: 'string' },
                                    found: { type: 'boolean' },
                                },
                            },
                            example: { error: "Tag ID '0000004C' not found", code: 'TAG_NOT_FOUND', found: false },
                        },
                    },
                },
                ProfileError409: {
                    description: 'Conflict — tag already exists in the profile',
                    content    : {
                        'application/json': {
                            schema : {
                                type      : 'object',
                                properties: {
                                    error  : { type: 'string' },
                                    code   : { type: 'string' },
                                    context: { type: 'string' },
                                },
                            },
                            example: { error: "Tag '00000025' already exists", code: 'TAG_EXISTS', context: 'POST /profile/tag/add' },
                        },
                    },
                },
                ProfileError413: {
                    description: 'Profile would exceed maximum permitted memory size',
                    content    : {
                        'application/json': {
                            schema : {
                                type      : 'object',
                                properties: {
                                    error  : { type: 'string' },
                                    code   : { type: 'string' },
                                    context: { type: 'string' },
                                },
                            },
                            example: { error: 'Profile size exceeds maximum allowed', code: 'MEMORY_EXCEEDED', context: 'POST /profile/tag/upsert' },
                        },
                    },
                },
            },
        },
    };
}

module.exports = buildProfileSpec;
