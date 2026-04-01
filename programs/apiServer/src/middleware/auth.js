/**
 * OCNCC Billing Engine Client Authentication.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

const jwt = require('jsonwebtoken');

/**
 * Creates an Express middleware for verifying JWT tokens.
 * @param {Config} config - The application configuration object
 * @param {StatsTracker} [statsTracker] - Statistics tracker
 * @param {AlertManager} [alertManager] - Alert manager
 * @returns {Function} Express middleware function
 */
function createAuthMiddleware(config, statsTracker, alertManager) {
  return function authMiddleware(req, res, next) {
    // Skip if JWT is globally disabled
    if (!config.get('jwtEnabled')) {
      return next();
    }

    // Skip authentication for public status and swagger routes
    const publicRoutes = ['/status', '/config', '/api-docs', '/health'];
    if (publicRoutes.some(route => req.path.startsWith(route))) {
      return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // Record failed unauthorised attempt
      if (statsTracker) {
        statsTracker.recordCall(req.path, null, req.ip, 'unauthorised');
      }
      return res.status(401).json({ error: 'Missing or invalid Authorization header. Provide a valid Bearer token.' });
    }

    const token = authHeader.split(' ')[1];

    try {
      const decoded = jwt.verify(token, config.get('jwtSecret'));

      // Restrict access based on allowedEndpoints array inside the token payload
      if (decoded.allowedEndpoints && Array.isArray(decoded.allowedEndpoints)) {
        // req.path will be relative to the router mount point (e.g., '/wallet-info')
        const isAllowed = decoded.allowedEndpoints.some(ep =>
          ep === '*' || req.path === ep || req.path.startsWith(ep + '/')
        );

        if (!isAllowed) {
          // FRAUD DETECTION: Attempting to access unauthorised endpoint
          const reason = `Forbidden: Client '${decoded.clientId}' endpoint limit hit for '${req.path}'`;

          if (statsTracker) {
            statsTracker.recordCall(req.path, null, decoded.clientId, 'unauthorised');
          }
          if (alertManager) {
            alertManager.triggerSecurityAlert('FORBIDDEN_API_ACCESS_ATTEMPT', {
              clientId: decoded.clientId,
              ip: req.ip,
              reason: reason
            });
          }

          return res.status(403).json({ error: reason });
        }
      }

      // Attach decoded payload to request
      req.user = decoded;

      // Inject clientId so stats-tracker picks it up dynamically
      if (decoded.clientId) {
        req.headers['x-client-id'] = decoded.clientId;
      }

      next();
    } catch (err) {
      const isExpired = err.name === 'TokenExpiredError';
      const msg = isExpired ? 'Token expired' : 'Invalid token';

      // Record failure
      if (statsTracker) {
        statsTracker.recordCall(req.path, null, req.ip, 'unauthorised');
      }

      // SECURITY ALERT: High frequency of invalid tokens could mean a brute-force or attack
      if (alertManager && !isExpired) {
        alertManager.triggerSecurityAlert('INVALID_TOKEN_ATTEMPT', {
          ip: req.ip,
          reason: msg
        });
      }

      return res.status(401).json({ error: `Authentication failed: ${msg}` });
    }
  };
}

module.exports = createAuthMiddleware;
