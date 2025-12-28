const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { pool, redisClient } = require('../server');

// Verify Telegram authentication data
function verifyTelegramInitData(initData) {
    const encoder = new TextEncoder();
    
    // Parse the initData string
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    params.delete('hash');
    
    // Sort parameters alphabetically
    const sortedParams = Array.from(params.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');
    
    // Create secret key from bot token
    const secretKey = crypto.createHmac('sha256', 'WebAppData')
        .update(process.env.TELEGRAM_BOT_TOKEN)
        .digest();
    
    // Calculate hash
    const calculatedHash = crypto.createHmac('sha256', secretKey)
        .update(sortedParams)
        .digest('hex');
    
    return calculatedHash === hash;
}

// Telegram OAuth login
router.post('/telegram-login', async (req, res) => {
    try {
        const { initData } = req.body;
        
        if (!initData) {
            return res.status(400).json({ error: 'Telegram initData required' });
        }
        
        // Verify the data
        if (!verifyTelegramInitData(initData)) {
            return res.status(401).json({ error: 'Invalid Telegram authentication' });
        }
        
        // Parse user data
        const params = new URLSearchParams(initData);
        const userStr = params.get('user');
        const user = JSON.parse(userStr);
        
        // Check if user exists
        const client = await pool.connect();
        try {
            let dbUser = await client.query(
                'SELECT * FROM users WHERE telegram_id = $1',
                [user.id]
            );
            
            if (dbUser.rows.length === 0) {
                // Create new user
                const referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
                
                dbUser = await client.query(`
                    INSERT INTO users (
                        telegram_id, telegram_username, first_name, last_name,
                        profile_pic_url, referral_code, last_login, last_ip
                    ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
                    RETURNING *
                `, [
                    user.id,
                    user.username,
                    user.first_name,
                    user.last_name,
                    user.photo_url,
                    referralCode,
                    req.ip
                ]);
                
                console.log(`✅ New user created: ${user.username || user.first_name}`);
            } else {
                // Update last login
                await client.query(
                    'UPDATE users SET last_login = NOW(), last_ip = $1 WHERE telegram_id = $2',
                    [req.ip, user.id]
                );
            }
            
            const userData = dbUser.rows[0];
            
            // Generate JWT tokens
            const accessToken = jwt.sign(
                { 
                    userId: userData.id,
                    telegramId: userData.telegram_id,
                    tier: userData.tier,
                    isAdmin: userData.is_admin 
                },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            const refreshToken = jwt.sign(
                { userId: userData.id },
                process.env.JWT_REFRESH_SECRET,
                { expiresIn: '30d' }
            );
            
            // Store refresh token in Redis
            await redisClient.setEx(
                `refresh_token:${userData.id}`,
                30 * 24 * 60 * 60, // 30 days
                refreshToken
            );
            
            res.json({
                success: true,
                user: {
                    id: userData.id,
                    telegramId: userData.telegram_id,
                    username: userData.telegram_username,
                    firstName: userData.first_name,
                    lastName: userData.last_name,
                    profilePic: userData.profile_pic_url,
                    tier: userData.tier,
                    balanceCoins: userData.balance_coins,
                    balanceCash: userData.balance_cash,
                    isAdmin: userData.is_admin,
                    isSuperAdmin: userData.is_super_admin,
                    level: userData.level,
                    xp: userData.xp
                },
                tokens: {
                    accessToken,
                    refreshToken
                }
            });
            
        } finally {
            client.release();
        }
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

// Get current user
router.get('/me', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const client = await pool.connect();
        try {
            const user = await client.query(
                'SELECT id, telegram_id, telegram_username, first_name, last_name, profile_pic_url, tier, balance_coins, balance_cash, is_admin, is_super_admin, level, xp, created_at FROM users WHERE id = $1',
                [decoded.userId]
            );
            
            if (user.rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json({ user: user.rows[0] });
        } finally {
            client.release();
        }
        
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        res.status(500).json({ error: 'Server error' });
    }
});

// Refresh token
router.post('/refresh-token', async (req, res) => {
    try {
        const { refreshToken } = req.body;
        
        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token required' });
        }
        
        // Verify refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        
        // Check if token exists in Redis
        const storedToken = await redisClient.get(`refresh_token:${decoded.userId}`);
        if (storedToken !== refreshToken) {
            return res.status(401).json({ error: 'Invalid refresh token' });
        }
        
        // Get user data
        const client = await pool.connect();
        try {
            const user = await client.query(
                'SELECT id, telegram_id, tier, is_admin FROM users WHERE id = $1',
                [decoded.userId]
            );
            
            if (user.rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            // Generate new access token
            const newAccessToken = jwt.sign(
                { 
                    userId: user.rows[0].id,
                    telegramId: user.rows[0].telegram_id,
                    tier: user.rows[0].tier,
                    isAdmin: user.rows[0].is_admin 
                },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            res.json({
                success: true,
                accessToken: newAccessToken
            });
            
        } finally {
            client.release();
        }
        
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid refresh token' });
        }
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout
router.post('/logout', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.decode(token);
        
        if (decoded && decoded.userId) {
            // Remove refresh token from Redis
            await redisClient.del(`refresh_token:${decoded.userId}`);
        }
        
        res.json({ success: true, message: 'Logged out successfully' });
        
    } catch (error) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

module.exports = router;