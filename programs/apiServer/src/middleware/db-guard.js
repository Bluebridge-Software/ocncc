/**
 * OCNCC Database Guard.
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

module.exports = (getDbReady) => (req, res, next) => {
    if (!getDbReady()) {
        return res.status(503).json({
            error: 'Database unavailable',
            message: 'The database connection is not yet established. Please try again shortly.',
        });
    }
    next();
};