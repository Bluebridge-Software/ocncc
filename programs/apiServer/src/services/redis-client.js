/**
 * OCNCC Billing Engine Redis Cache Client.
 * Express Server with Swagger UI
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */


const { createClient } = require('redis');
const Config = require('../config/config');

let redis = null;

async function getRedisClient() {
    if (redis) return redis; // reuse existing client

    const host = Config.REDIS_HOST || 'swisspi';
    const port = Config.REDIS_PORT || 6379;
    const username = Config.REDIS_USER || 'intellicharter';
    const password = Config.REDIS_PASSWORD || 'w1mbold345';

    redis = createClient({
        socket: { host, port, family: 4 },
        username,
        password,
    });

    redis.on('error', (err) => console.error('[Redis] Connection error:', err));
    redis.on('connect', () => console.log('[Redis] TCP connection established'));
    redis.on('ready', () => console.log('[Redis] Ready for commands'));

    await redis.connect();

    // optional: sanity check
    const pong = await redis.ping();
    console.log('[Redis] PING response:', pong);

    return redis;
}

module.exports = { getRedisClient };