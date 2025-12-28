const jwt = require('jsonwebtoken');
const { pool, redisClient } = require('../server');

// Verify JWT token
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                success: false,
                error: 'Access denied. No token provided.' 
            });
        }

        const token = authHeader.split(' ')[1];
        
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if user exists and is active
        const client = await pool.connect();
        try {
            const userResult = await client.query(
                `SELECT id, telegram_id, telegram_username, first_name, last_name, 
                        profile_pic_url, tier, balance_coins, balance_cash, 
                        total_earned, level, xp, is_admin, is_super_admin, 
                        is_active, is_verified, created_at
                 FROM users 
                 WHERE id = $1 AND is_active = true`,
                [decoded.userId]
            );

            if (userResult.rows.length === 0) {
                return res.status(401).json({ 
                    success: false,
                    error: 'User not found or account inactive' 
                });
            }

            // Attach user to request
            req.user = userResult.rows[0];
            next();
            
        } finally {
            client.release();
        }

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid or expired token' 
            });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false,
                error: 'Token expired. Please login again.' 
            });
        }
        
        console.error('Authentication error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Authentication failed' 
        });
    }
};

// Admin middleware
const requireAdmin = async (req, res, next) => {
    if (!req.user.is_admin && !req.user.is_super_admin) {
        return res.status(403).json({ 
            success: false,
            error: 'Admin access required' 
        });
    }
    next();
};

// Super admin middleware
const requireSuperAdmin = async (req, res, next) => {
    if (!req.user.is_super_admin) {
        return res.status(403).json({ 
            success: false,
            error: 'Super admin access required' 
        });
    }
    next();
};

// Premium user middleware
const requirePremium = async (req, res, next) => {
    if (req.user.tier !== 'premium') {
        return res.status(403).json({ 
            success: false,
            error: 'Premium subscription required' 
        });
    }
    next();
};

// Rate limiting per user
const rateLimitByUser = (maxRequests, windowMs) => {
    return async (req, res, next) => {
        if (!req.user) {
            return next();
        }
        
        const key = `rate_limit:${req.user.id}:${req.path}`;
        const current = await redisClient.get(key);
        
        if (current === null) {
            await redisClient.setEx(key, windowMs / 1000, '1');
            return next();
        }
        
        if (parseInt(current) >= maxRequests) {
            return res.status(429).json({ 
                success: false,
                error: 'Too many requests. Please try again later.' 
            });
        }
        
        await redisClient.incr(key);
        next();
    };
};

module.exports = {
    authenticate,
    requireAdmin,
    requireSuperAdmin,
    requirePremium,
    rateLimitByUser
};