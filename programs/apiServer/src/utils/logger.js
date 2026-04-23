/**
 * Universal Logger Implementation
 * Enhanced version combining best practices
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2025
 * Author: Tony Craven
 */

export const LogLevel = Object.freeze({
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
  TRACE: 4, // Added for more granular debugging
});

const isNode = typeof process !== 'undefined' && process.versions?.node != null;

class Logger {
  constructor(config = {}) {
    this.level = config.level ?? LogLevel.INFO;
    this.json = config.json ?? false; // JSON structured logging
    this.context = config.context ?? null;
    this.timestamp = config.timestamp ?? true; // Allow disabling timestamps
    this.colors = config.colors ?? true; // Allow disabling colors

    // Granular level control - can disable specific levels
    this.enabledLevels = {
      [LogLevel.ERROR]: true,
      [LogLevel.WARN]: true,
      [LogLevel.INFO]: true,
      [LogLevel.DEBUG]: true,
      [LogLevel.TRACE]: true,
      ...(config.enabledLevels || {}),
    };
  }

  /**
   * Set the global log level threshold
   * @param {number} level - LogLevel constant
   */
  setLevel(level) {
    this.level = level;
  }

  /**
   * Enable JSON structured logging (useful for production log aggregators)
   */
  enableJSON() {
    this.json = true;
  }

  /**
   * Disable JSON logging, use pretty format
   */
  disableJSON() {
    this.json = false;
  }

  /**
   * Enable or disable timestamps
   * @param {boolean} enabled
   */
  setTimestamp(enabled) {
    this.timestamp = enabled;
  }

  /**
   * Enable or disable colors
   * @param {boolean} enabled
   */
  setColors(enabled) {
    this.colors = enabled;
  }

  /**
   * Enable or disable a specific log level
   * @param {number} level - LogLevel constant
   * @param {boolean} enabled
   */
  setLevelEnabled(level, enabled) {
    this.enabledLevels[level] = enabled;
  }

  /**
   * Create a child logger with additional context
   * @param {string} context - Context identifier
   * @returns {Logger}
   */
  child(context) {
    const childContext = this.context ? `${this.context}:${context}` : context;

    return new Logger({
      level: this.level,
      json: this.json,
      timestamp: this.timestamp,
      colors: this.colors,
      enabledLevels: { ...this.enabledLevels },
      context: childContext,
    });
  }

  /**
   * Check if a log level should be output
   * @private
   */
  shouldLog(level) {
    return level <= this.level && this.enabledLevels[level];
  }

  /**
   * Get the string name of a log level
   * @private
   */
  getLevelName(level) {
    return Object.keys(LogLevel).find((key) => LogLevel[key] === level);
  }

  /**
   * Format a log message
   * @private
   */
  format(level, message, meta) {
    const timestamp = this.timestamp ? new Date().toISOString() : null;
    const levelName = this.getLevelName(level);

    // JSON structured format (for production log aggregators)
    if (this.json && isNode) {
      const logObject = {
        level: levelName,
        message,
      };

      if (timestamp) logObject.timestamp = timestamp;
      if (this.context) logObject.context = this.context;
      if (meta !== undefined) logObject.meta = meta;

      return JSON.stringify(logObject);
    }

    // Pretty format for development
    const parts = [];

    if (timestamp) {
      parts.push(`[${timestamp}]`);
    }

    parts.push(`[${levelName}]`);

    if (this.context) {
      parts.push(`[${this.context}]`);
    }

    return { prefix: parts.join(' '), meta };
  }

  /**
   * Internal log method
   * @private
   */
  log(level, message, meta = undefined) {
    if (!this.shouldLog(level)) return;

    const formatted = this.format(level, message, meta);

    // JSON output (typically for production)
    if (this.json && isNode) {
      console.log(formatted);
      return;
    }

    const { prefix } = formatted;
    const levelName = this.getLevelName(level);

    if (isNode) {
      // ANSI colors for Node.js terminal
      const colors = {
        ERROR: '\x1b[31m', // Red
        WARN: '\x1b[33m', // Yellow
        INFO: '\x1b[36m', // Cyan
        DEBUG: '\x1b[90m', // Gray
        TRACE: '\x1b[90m', // Gray
      };
      const reset = '\x1b[0m';
      const color = this.colors ? colors[levelName] || '' : '';
      const resetCode = this.colors ? reset : '';

      // Use appropriate console method
      const consoleMethod =
        level === LogLevel.ERROR
          ? console.error
          : level === LogLevel.WARN
            ? console.warn
            : console.log;

      if (meta !== undefined) {
        consoleMethod(`${color}${prefix}${resetCode}`, message, meta);
      } else {
        consoleMethod(`${color}${prefix}${resetCode}`, message);
      }
    } else {
      // Browser console styling
      const styles = {
        ERROR: 'color: #ff4444; font-weight: bold;',
        WARN: 'color: #ff9800; font-weight: bold;',
        INFO: 'color: #2196F3;',
        DEBUG: 'color: #9c27b0;',
        TRACE: 'color: #999;',
      };

      const style = this.colors ? styles[levelName] || '' : '';

      // Use appropriate console method
      const consoleMethod =
        level === LogLevel.ERROR
          ? console.error
          : level === LogLevel.WARN
            ? console.warn
            : console.log;

      if (meta !== undefined) {
        consoleMethod(`%c${prefix}`, style, message, meta);
      } else {
        consoleMethod(`%c${prefix}`, style, message);
      }
    }
  }

  /**
   * Log an error message
   * @param {string} message - Error message
   * @param {any} meta - Additional metadata (error object, context, etc.)
   */
  error(message, meta) {
    this.log(LogLevel.ERROR, message, meta);
  }

  /**
   * Log a warning message
   * @param {string} message - Warning message
   * @param {any} meta - Additional metadata
   */
  warn(message, meta) {
    this.log(LogLevel.WARN, message, meta);
  }

  /**
   * Alias for warn
   */
  warning(message, meta) {
    this.warn(message, meta);
  }

  /**
   * Log an info message
   * @param {string} message - Info message
   * @param {any} meta - Additional metadata
   */
  info(message, meta) {
    this.log(LogLevel.INFO, message, meta);
  }

  /**
   * Log a debug message
   * @param {string} message - Debug message
   * @param {any} meta - Additional metadata
   */
  debug(message, meta) {
    this.log(LogLevel.DEBUG, message, meta);
  }

  /**
   * Log a trace message (most verbose)
   * @param {string} message - Trace message
   * @param {any} meta - Additional metadata
   */
  trace(message, meta) {
    this.log(LogLevel.TRACE, message, meta);
  }

  /**
   * Get current configuration
   * @returns {Object}
   */
  getConfig() {
    return {
      level: this.level,
      levelName: this.getLevelName(this.level),
      json: this.json,
      timestamp: this.timestamp,
      colors: this.colors,
      context: this.context,
      enabledLevels: { ...this.enabledLevels },
    };
  }
}

export default Logger;
