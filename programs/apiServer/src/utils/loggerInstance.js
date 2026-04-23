/**
 * Universal Logger Instance
 * Enhanced singleton with improved environment detection
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2025
 * Author: Tony Craven
 */

import Logger, { LogLevel } from './logger.js';
import { getLoggerConfig } from '../../config/config.js';

const isNode = typeof process !== 'undefined' && process.versions?.node != null;

function parseLogLevel(levelName) {
  const levelMap = {
    ERROR: LogLevel.ERROR,
    WARN: LogLevel.WARN,
    INFO: LogLevel.INFO,
    DEBUG: LogLevel.DEBUG,
    TRACE: LogLevel.TRACE,
  };
  return levelMap[levelName.toUpperCase()] ?? LogLevel.INFO;
}

// Get configuration from config.js
const config = getLoggerConfig();

const logger = new Logger({
  level: parseLogLevel(config.level),
  json: config.json,
  colors: config.colors,
  timestamp: config.timestamp,
});

/**
 * Detect and parse log level from environment
 * @returns {number} LogLevel constant
 */
function detectLogLevel() {
  let levelName = 'INFO';

  if (isNode) {
    // Node.js environment - use process.env
    levelName = process.env.LOG_LEVEL?.toUpperCase() || 'INFO';
  } else if (globalThis.window !== undefined) {
    // BrowseglobalThis.window !== undefinedocalStorage
    levelName =
      globalThis.__LOG_LEVEL__ ||
      localStorage.getItem('LOG_LEVEL')?.toUpperCase() ||
      'INFO';
  }

  const levelMap = {
    ERROR: LogLevel.ERROR,
    WARN: LogLevel.WARN,
    INFO: LogLevel.INFO,
    DEBUG: LogLevel.DEBUG,
    TRACE: LogLevel.TRACE,
  };

  return levelMap[levelName] ?? LogLevel.INFO;
}

/**
 * Check if JSON logging should be enabled
 * @returns {boolean}
 */
function shouldUseJSON() {
  if (!isNode) return false;

  // Enable JSON in production or if explicitly set
  return (
    process.env.LOG_JSON === 'true' || process.env.NODE_ENV === 'production'
  );
}

/**
 * Check if colors should be enabled
 * @returns {boolean}
 */
function shouldUseColors() {
  if (isNode) {
    // Disable colors if NO_COLOR is set or if not a TTY
    if (process.env.NO_COLOR) return false;
    if (process.stdout && !process.stdout.isTTY) return false;
  }
  return true;
}

// Export the singleton instance
export default logger;

// Also export LogLevel for convenience
export { LogLevel };

/**
 * Helper function to set log level at runtime
 * Useful for debugging in browser console or node REPL
 *
 * Usage in browser console:
 *   window.setLogLevel('DEBUG')
 *
 * Usage in Node REPL:
 *   setLogLevel('DEBUG')
 */
export function setLogLevel(levelName) {
  const levelMap = {
    ERROR: LogLevel.ERROR,
    WARN: LogLevel.WARN,
    INFO: LogLevel.INFO,
    DEBUG: LogLevel.DEBUG,
    TRACE: LogLevel.TRACE,
  };

  const level = levelMap[levelName.toUpperCase()];

  if (level === undefined) {
    console.warn(
      `Invalid log level: ${levelName}. Valid levels: ERROR, WARN, INFO, DEBUG, TRACE`
    );
    return;
  }

  logger.setLevel(level);

  // Persist to localStorage in browser
  if (!isNode && typeof localStorage !== 'undefined') {
    localStorage.setItem('LOG_LEVEL', levelName.toUpperCase());
  }

  console.log(`Log level set to: ${levelName.toUpperCase()}`);
}

/**
 * Helper to expose setLogLevel in browser console
 */
if (!isNode && globalThis.window !== undefined) {
  globalThis.setLogLevel = setLogLevel;
}
