/**
 * OCNCC Billing Engine Stats Tracker.
 * Tracks API usage statistics aggregated over configurable time periods.
 * Supports optional Redis for cluster-safe collection and storage.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const Redis = require('ioredis');

class StatsTracker {
  constructor(config) {
    this.periodMs = (config.get('statsPeriodMinutes') || 5) * 60 * 1000;
    this.retentionMs = (config.get('statsRetentionDays') || 3) * 24 * 60 * 60 * 1000;

    this.redisEnabled = config.get('redisEnabled') || false;
    this.redis = null;

    if (this.redisEnabled) {
      const url = config.get('redisUrl') || 'redis://localhost:6379';
      this.redis = new Redis(url, {
        retryStrategy: (times) => Math.min(times * 50, 2000)
      });
      this.redis.on('error', (err) => {
        console.error('[StatsTracker] Redis connection error:', err.message);
      });
    }

    // Local state fallback (and local snapshot cache)
    this.buckets = new Map();

    // Start hourly cleanup timer for local and/or Redis obsolete records
    this.cleanupTimer = setInterval(() => this.cleanup(), 60 * 60 * 1000);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  getBucketTime(now = Date.now()) {
    // Round down to the nearest period boundary
    return Math.floor(now / this.periodMs) * this.periodMs;
  }

  recordCall(endpoint, beId, clientId, status = 'success') {
    const bucketTime = this.getBucketTime();
    const safeBeId = (beId === undefined || beId === null) ? 'unknown' : beId.toString();
    const safeClientId = clientId || 'unknown';
    const retentionSeconds = Math.ceil(this.retentionMs / 1000);

    // Also update local tracker state (acts as fallback or local node snapshot)
    if (!this.buckets.has(bucketTime)) {
      this.buckets.set(bucketTime, {
        timestamp: new Date(bucketTime).toISOString(),
        totalCalls: 0,
        failedCalls: 0,
        unauthorisedAttempts: 0,
        byEndpoint: {},
        byBeId: {},
        byClient: {}
      });
    }

    const bucket = this.buckets.get(bucketTime);
    bucket.totalCalls++;
    if (status === 'error') bucket.failedCalls++;
    if (status === 'unauthorised') bucket.unauthorisedAttempts++;

    bucket.byEndpoint[endpoint] = (bucket.byEndpoint[endpoint] || 0) + 1;
    bucket.byBeId[safeBeId] = (bucket.byBeId[safeBeId] || 0) + 1;
    bucket.byClient[safeClientId] = (bucket.byClient[safeClientId] || 0) + 1;

    // Write to Redis if enabled
    if (this.redisEnabled && this.redis.status === 'ready') {
      const p = this.redis.pipeline();

      // Register this bucket time into a sorted set to query later
      p.zadd('stats:buckets', bucketTime, bucketTime);

      // Increment top level metrics
      p.hincrby(`stats:bucket:${bucketTime}`, 'totalCalls', 1);
      if (status === 'error') p.hincrby(`stats:bucket:${bucketTime}`, 'failedCalls', 1);
      if (status === 'unauthorised') p.hincrby(`stats:bucket:${bucketTime}`, 'unauthorisedAttempts', 1);

      // Increment categorical metrics
      p.hincrby(`stats:bucket:${bucketTime}:endpoint`, endpoint, 1);
      p.hincrby(`stats:bucket:${bucketTime}:beId`, safeBeId, 1);
      p.hincrby(`stats:bucket:${bucketTime}:client`, safeClientId, 1);

      // Set expiration so Redis auto-cleans old data
      p.expire('stats:buckets', retentionSeconds);
      p.expire(`stats:bucket:${bucketTime}`, retentionSeconds);
      p.expire(`stats:bucket:${bucketTime}:endpoint`, retentionSeconds);
      p.expire(`stats:bucket:${bucketTime}:beId`, retentionSeconds);
      p.expire(`stats:bucket:${bucketTime}:client`, retentionSeconds);

      p.exec().catch(err => console.error('[StatsTracker] Failed writing to Redis:', err.message));
    }
  }

  /**
   * Retrieves statistics for the specified number of hours.
   */
  async getStats(hours = 24) {
    const now = Date.now();
    const cutoff = now - (hours * 60 * 60 * 1000);

    const result = {
      periodMinutes: this.periodMs / (60 * 1000),
      periodAggregates: []
    };

    if (this.redisEnabled && this.redis.status === 'ready') {
      try {
        // Fetch known bucket timestamps from Redis
        const times = await this.redis.zrangebyscore('stats:buckets', cutoff, '+inf');

        if (times && times.length > 0) {
          const p = this.redis.pipeline();
          for (const bt of times) {
            p.hgetall(`stats:bucket:${bt}`);
            p.hgetall(`stats:bucket:${bt}:endpoint`);
            p.hgetall(`stats:bucket:${bt}:beId`);
            p.hgetall(`stats:bucket:${bt}:client`);
          }

          const redisResults = await p.exec();

          for (let i = 0; i < times.length; i++) {
            const bt = parseInt(times[i], 10);
            const baseData = redisResults[i * 4][1] || {};
            const endpointData = redisResults[i * 4 + 1][1] || {};
            const beIdData = redisResults[i * 4 + 2][1] || {};
            const clientData = redisResults[i * 4 + 3][1] || {};

            // Convert string counts back into Integers
            result.periodAggregates.push({
              timestamp: new Date(bt).toISOString(),
              totalCalls: parseInt(baseData.totalCalls || 0, 10),
              failedCalls: parseInt(baseData.failedCalls || 0, 10),
              unauthorisedAttempts: parseInt(baseData.unauthorisedAttempts || 0, 10),
              byEndpoint: this._mapValuesToInt(endpointData),
              byBeId: this._mapValuesToInt(beIdData),
              byClient: this._mapValuesToInt(clientData)
            });
          }
        }
        return result;
      } catch (err) {
        console.error('[StatsTracker] Failed to retrieve from Redis, dropping back to local state:', err.message);
        // Fallback to local map processing
      }
    }

    // Execute local state resolution (Fallback or explicitly non-redis configuration)
    const sortedKeys = Array.from(this.buckets.keys()).sort();
    for (const key of sortedKeys) {
      if (key >= cutoff) {
        result.periodAggregates.push(this.buckets.get(key));
      }
    }

    return result;
  }

  _mapValuesToInt(obj) {
    const res = {};
    for (const [k, v] of Object.entries(obj)) {
      res[k] = parseInt(v, 10);
    }
    return res;
  }

  async cleanup() {
    const cutoff = Date.now() - this.retentionMs;

    // Local Cleanup
    for (const key of this.buckets.keys()) {
      if (key < cutoff) {
        this.buckets.delete(key);
      }
    }

    // Redis Cleanup: remove old keys from the sorted set (Expire handles the hashes)
    if (this.redisEnabled && this.redis.status === 'ready') {
      try {
        await this.redis.zremrangebyscore('stats:buckets', '-inf', cutoff - 1);
      } catch (err) {
        console.error('[StatsTracker] Failed to cleanup Redis zset:', err.message);
      }
    }
  }

  destroy() {
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    if (this.redis) this.redis.disconnect();
  }
}

module.exports = StatsTracker;
