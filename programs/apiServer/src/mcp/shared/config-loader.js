/**
 * Platform Configuration Loader
 *
 * Reads platform.config.yaml, resolves ${ENV_VAR} placeholders,
 * validates required fields, and exports the resolved config.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const CONFIG_PATH = process.env.PLATFORM_CONFIG
    || path.resolve(__dirname, '../../config/platform.config.yaml');

// ---------------------------------------------------------------------------
// Resolve ${ENV_VAR} placeholders in any string value in the config tree
// ---------------------------------------------------------------------------

function resolveEnvVars(obj) {
    if (typeof obj === 'string') {
        return obj.replace(/\$\{([^}]+)\}/g, (_, varName) => {
            const val = process.env[varName];
            if (val === undefined) {
                throw new Error(`[Config] Environment variable '${varName}' is not set (referenced in platform.config.yaml)`);
            }
            return val;
        });
    }
    if (Array.isArray(obj)) return obj.map(resolveEnvVars);
    if (obj && typeof obj === 'object') {
        return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, resolveEnvVars(v)]));
    }
    return obj;
}

// ---------------------------------------------------------------------------
// Validate the resolved config structure
// ---------------------------------------------------------------------------

function validate(config) {
    const errors = [];

    if (!config.gateway?.port) errors.push('gateway.port is required');
    if (!config.gateway?.jwt_secret) errors.push('gateway.jwt_secret is required');

    if (!Array.isArray(config.ocs_adapters) || config.ocs_adapters.length === 0) {
        errors.push('ocs_adapters[] must contain at least one entry');
    } else {
        config.ocs_adapters.forEach((a, i) => {
            if (!a.id) errors.push(`ocs_adapters[${i}].id is required`);
            if (!a.type) errors.push(`ocs_adapters[${i}].type is required`);
        });
    }

    if (!Array.isArray(config.mcp_servers) || config.mcp_servers.length === 0) {
        errors.push('mcp_servers[] must contain at least one entry');
    } else {
        config.mcp_servers.forEach((s, i) => {
            if (!s.id) errors.push(`mcp_servers[${i}].id is required`);
            if (!s.port) errors.push(`mcp_servers[${i}].port is required`);
            if (!s.type) errors.push(`mcp_servers[${i}].type is required`);
            if (!s.ocs_adapter) errors.push(`mcp_servers[${i}].ocs_adapter is required`);
        });
    }

    if (!Array.isArray(config.roles) || config.roles.length === 0) {
        errors.push('roles[] must contain at least one entry');
    } else {
        config.roles.forEach((r, i) => {
            if (!r.id) errors.push(`roles[${i}].id is required`);
            if (!Array.isArray(r.allowed_mcp_servers)) errors.push(`roles[${i}].allowed_mcp_servers[] is required`);
        });
    }

    if (errors.length) {
        throw new Error(`[Config] Invalid platform.config.yaml:\n  ${errors.join('\n  ')}`);
    }
}

// ---------------------------------------------------------------------------
// Load, resolve, validate, return
// ---------------------------------------------------------------------------

let _cached = null;

function loadConfig() {
    if (_cached) return _cached;

    if (!fs.existsSync(CONFIG_PATH)) {
        throw new Error(`[Config] platform.config.yaml not found at: ${CONFIG_PATH}`);
    }

    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    const parsed = yaml.load(raw);
    const resolved = resolveEnvVars(parsed);

    validate(resolved);

    // Build lookup maps for fast access
    resolved._adapterById = Object.fromEntries(resolved.ocs_adapters.map(a => [a.id, a]));
    resolved._mcpServerById = Object.fromEntries(resolved.mcp_servers.map(s => [s.id, s]));
    resolved._roleById = Object.fromEntries(resolved.roles.map(r => [r.id, r]));

    _cached = resolved;
    console.log(`[Config] Loaded: ${resolved.mcp_servers.length} MCP servers, ${resolved.ocs_adapters.length} adapters, ${resolved.roles.length} roles`);
    return resolved;
}

// Allow tests to reset the cache
function _resetCache() { _cached = null; }

module.exports = { loadConfig, _resetCache };