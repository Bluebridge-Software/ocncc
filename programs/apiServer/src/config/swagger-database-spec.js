/**
 * OCNCC Master Database API — OpenAPI Specification.
 * Separate spec for the Oracle subscriber and profile-tag endpoints.
 * Merged into the main spec by server.js at startup.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

/**
 * Returns the paths, tags, and component additions for the database API.
 * The result is merged into the main swagger spec object in server.js.
 *
 * @returns {{ tags: object[], paths: object, components: object }}
 */
function buildDatabaseSpec() {
    return {

        // -----------------------------------------------------------------------
        // Tags (appended to the main spec's tags array)
        // -----------------------------------------------------------------------
        tags: [
            { name: 'Subscriber',    description: 'Subscriber account lookups and profile decoding' },
            { name: 'Profile Tags',  description: 'Profile tag definitions and metadata management' },
        ],

        // -----------------------------------------------------------------------
        // Paths (merged into the main spec's paths object)
        // -----------------------------------------------------------------------
        paths: {

            // ------------------------------------------------------------------
            // Subscriber
            // ------------------------------------------------------------------
            '/db/subscriber': {
                get: {
                    tags       : ['Subscriber'],
                    summary    : 'Look up a subscriber by CLI',
                    description: 'Returns subscriber account details from `CCS_ACCT_REFERENCE`. ' +
                                 'The raw LONG RAW `PROFILE` field is returned as a Base64 string. ' +
                                 'Pass `decode=true` to include a fully decoded, human-readable ' +
                                 'profile with friendly tag names resolved from `ACS_PROFILE_DETAILS`.\n\n' +
                                 'Results are cached in Redis for 30 seconds. Pass `refresh=true` ' +
                                 'to bypass the cache and re-read from the database.',
                    parameters : [
                        {
                            name       : 'cli',
                            in         : 'query',
                            required   : true,
                            description: 'The subscriber CLI (E.164 format, e.g. 447917368246)',
                            schema     : { type: 'string', example: '447917368246' },
                        },
                        {
                            name       : 'decode',
                            in         : 'query',
                            required   : false,
                            description: 'If `true`, includes a decoded profile JSON with friendly tag names',
                            schema     : { type: 'boolean', default: false },
                        },
                        {
                            name       : 'refresh',
                            in         : 'query',
                            required   : false,
                            description: 'If `true`, bypasses Redis cache and re-reads from Oracle',
                            schema     : { type: 'boolean', default: false },
                        },
                    ],
                    responses: {
                        200: {
                            description: 'Subscriber found',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/SubscriberListResponse' },
                                    example: {
                                        count: 1,
                                        data: [
                                            {
                                                id        : 2,
                                                cli       : '07917368246',
                                                acsCustId : 11,
                                                profile   : 'AAAACQAAACUAAABMAAAALAAAAFwAAAAt...',
                                                decodedProfile: {
                                                    valid    : true,
                                                    tagCount : 9,
                                                    tags: [
                                                        {
                                                            tagId  : '00000025',
                                                            value  : 1,
                                                            display: '1',
                                                            name   : 'Language',
                                                            type   : 'INT',
                                                        },
                                                        {
                                                            tagId  : '0000002C',
                                                            value  : true,
                                                            display: 'TRUE',
                                                            name   : 'Outgoing BA List Ignore',
                                                            type   : 'BOOL',
                                                        },
                                                    ],
                                                },
                                            },
                                        ],
                                    },
                                },
                            },
                        },
                        400: { $ref: '#/components/responses/Error400' },
                        404: { $ref: '#/components/responses/DbError404' },
                        500: { $ref: '#/components/responses/Error500' },
                    },
                },
            },

            '/db/subscriber/{cli}/profile': {
                get: {
                    tags       : ['Subscriber'],
                    summary    : 'Get subscriber profile',
                    description: 'Returns only the profile portion of a subscriber record. ' +
                                 'By default returns the decoded JSON form with friendly tag names. ' +
                                 'Pass `decode=false` to get the raw Base64 string instead.',
                    parameters : [
                        {
                            name       : 'cli',
                            in         : 'path',
                            required   : true,
                            description: 'Subscriber CLI',
                            schema     : { type: 'string', example: '447917368246' },
                        },
                        {
                            name       : 'decode',
                            in         : 'query',
                            required   : false,
                            description: 'If `false`, returns raw Base64 profile instead of decoded JSON',
                            schema     : { type: 'boolean', default: true },
                        },
                    ],
                    responses: {
                        200: {
                            description: 'Profile returned',
                            content: {
                                'application/json': {
                                    schema: {
                                        type      : 'object',
                                        properties: {
                                            cli    : { type: 'string' },
                                            profile: {
                                                oneOf: [
                                                    { $ref: '#/components/schemas/DecodedProfile' },
                                                    { type: 'string', description: 'Base64-encoded raw profile' },
                                                ],
                                            },
                                        },
                                    },
                                },
                            },
                        },
                        404: { $ref: '#/components/responses/DbError404' },
                        500: { $ref: '#/components/responses/Error500' },
                    },
                },
            },

            '/db/subscriber/{cli}/cache': {
                delete: {
                    tags       : ['Subscriber'],
                    summary    : 'Invalidate cached subscriber record',
                    description: 'Removes the Redis cache entry for this CLI, forcing the next ' +
                                 'request to re-read from Oracle.',
                    parameters : [
                        {
                            name    : 'cli',
                            in      : 'path',
                            required: true,
                            schema  : { type: 'string' },
                        },
                    ],
                    responses: {
                        200: {
                            description: 'Cache invalidated',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/MessageResponse' },
                                    example: { message: 'Cache invalidated for CLI 447917368246' },
                                },
                            },
                        },
                        500: { $ref: '#/components/responses/Error500' },
                    },
                },
            },

            // ------------------------------------------------------------------
            // Profile Tags
            // ------------------------------------------------------------------
            '/db/profile-tags': {
                get: {
                    tags       : ['Profile Tags'],
                    summary    : 'Get all profile tag definitions',
                    description: 'Returns the full list of profile tag definitions from ' +
                                 '`ACS_PROFILE_DETAILS`, including tag ID (as 8-char hex), ' +
                                 'friendly name, data type, parent tag, and a pre-built ' +
                                 'hierarchy tree for UI rendering.\n\n' +
                                 'Results are cached in Redis for 1 hour. Pass `refresh=true` ' +
                                 'to force a DB re-read and reload the in-process profile parser.',
                    parameters : [
                        {
                            name       : 'refresh',
                            in         : 'query',
                            required   : false,
                            description: 'If `true`, bypasses cache, re-reads DB, and reloads the profile parser',
                            schema     : { type: 'boolean', default: false },
                        },
                    ],
                    responses: {
                        200: {
                            description: 'Tag definitions returned',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/ProfileTagsResponse' },
                                    example: {
                                        count: 2,
                                        data: [
                                            { tagId: '00000025', name: 'Language',                type: 'INT',  parentTagId: null, isInputParameter: true  },
                                            { tagId: '0000002C', name: 'Outgoing BA List Ignore', type: 'BOOL', parentTagId: null, isInputParameter: false },
                                        ],
                                        tree: [
                                            { tagId: '00000025', name: 'Language', type: 'INT', parentTagId: null, isInputParameter: true, children: [] },
                                        ],
                                    },
                                },
                            },
                        },
                        404: { $ref: '#/components/responses/DbError404' },
                        500: { $ref: '#/components/responses/Error500' },
                    },
                },
            },

            '/db/profile-tags/cache': {
                delete: {
                    tags       : ['Profile Tags'],
                    summary    : 'Invalidate profile tags cache',
                    description: 'Removes the Redis cache entry for profile tags. The next call to ' +
                                 '`GET /db/profile-tags` will re-read from Oracle.',
                    responses: {
                        200: {
                            description: 'Cache invalidated',
                            content: {
                                'application/json': {
                                    schema : { $ref: '#/components/schemas/MessageResponse' },
                                    example: { message: 'Profile tags cache invalidated' },
                                },
                            },
                        },
                        500: { $ref: '#/components/responses/Error500' },
                    },
                },
            },

            '/db/profile-tags/status': {
                get: {
                    tags       : ['Profile Tags'],
                    summary    : 'Profile tag metadata status',
                    description: 'Shows whether the in-process profile parser has tag metadata loaded, ' +
                                 'how many tags are known, and when the Redis cache was last populated.',
                    responses: {
                        200: {
                            description: 'Status returned',
                            content: {
                                'application/json': {
                                    schema: {
                                        type      : 'object',
                                        properties: {
                                            parserLoaded: { type: 'boolean' },
                                            tagCount    : { type: 'integer' },
                                            cachedAt    : { type: 'string', format: 'date-time', nullable: true },
                                            redisEnabled: { type: 'boolean' },
                                        },
                                    },
                                    example: {
                                        parserLoaded: true,
                                        tagCount    : 124,
                                        cachedAt    : '2026-04-01T08:00:00.000Z',
                                        redisEnabled: true,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },

        // -----------------------------------------------------------------------
        // Component additions (merged into main spec's components)
        // -----------------------------------------------------------------------
        components: {
            schemas: {
                SubscriberRow: {
                    type      : 'object',
                    properties: {
                        id            : { type: 'integer', example: 2 },
                        cli           : { type: 'string',  example: '07917368246' },
                        acsCustId     : { type: 'integer', example: 11 },
                        profile       : { type: 'string',  description: 'Base64-encoded raw LONG RAW profile' },
                        decodedProfile: { $ref: '#/components/schemas/DecodedProfile', nullable: true },
                    },
                },
                SubscriberListResponse: {
                    type      : 'object',
                    properties: {
                        count: { type: 'integer' },
                        data : { type: 'array', items: { $ref: '#/components/schemas/SubscriberRow' } },
                    },
                },
                DecodedProfile: {
                    type      : 'object',
                    properties: {
                        valid    : { type: 'boolean' },
                        tagCount : { type: 'integer' },
                        tags     : {
                            type : 'array',
                            items: {
                                type      : 'object',
                                properties: {
                                    tagId           : { type: 'string', example: '00000025' },
                                    value           : { description: 'Typed value (number, boolean, or string)' },
                                    display         : { type: 'string', description: 'Human-readable string' },
                                    name            : { type: 'string', example: 'Language' },
                                    type            : { type: 'string', example: 'INT' },
                                    parentTagId     : { type: 'string', nullable: true },
                                    isInputParameter: { type: 'boolean' },
                                },
                            },
                        },
                        stats: {
                            type      : 'object',
                            nullable  : true,
                            properties: {
                                tagCount : { type: 'integer' },
                                totalSize: { type: 'integer' },
                                indexSize: { type: 'integer' },
                                dataSize : { type: 'integer' },
                            },
                        },
                    },
                },
                ProfileTagEntry: {
                    type      : 'object',
                    properties: {
                        tagId           : { type: 'string',  example: '00000025' },
                        name            : { type: 'string',  example: 'Language' },
                        type            : { type: 'string',  example: 'INT', enum: ['INT', 'BOOL', 'STR', 'RAW'] },
                        parentTagId     : { type: 'string',  nullable: true },
                        isInputParameter: { type: 'boolean' },
                        children        : { type: 'array', items: { $ref: '#/components/schemas/ProfileTagEntry' } },
                    },
                },
                ProfileTagsResponse: {
                    type      : 'object',
                    properties: {
                        count: { type: 'integer' },
                        data : { type: 'array', items: { $ref: '#/components/schemas/ProfileTagEntry' } },
                        tree : { type: 'array', items: { $ref: '#/components/schemas/ProfileTagEntry' } },
                    },
                },
                MessageResponse: {
                    type      : 'object',
                    properties: { message: { type: 'string' } },
                },
            },
            responses: {
                DbError404: {
                    description: 'Record not found',
                    content: {
                        'application/json': {
                            schema : { type: 'object', properties: { message: { type: 'string' } } },
                            example: { message: 'Subscriber not found' },
                        },
                    },
                },
                Error500: {
                    description: 'Internal server error',
                    content: {
                        'application/json': {
                            schema : { type: 'object', properties: { error: { type: 'string' }, details: { type: 'string' } } },
                            example: { error: 'Internal server error', details: 'ORA-01234: ...' },
                        },
                    },
                },
            },
        },
    };
}

module.exports = buildDatabaseSpec;
