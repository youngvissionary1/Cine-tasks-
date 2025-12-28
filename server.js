// server.js - Complete Production Server
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const https = require('https');
const fs = require('fs');
require('dotenv').config();

const app = express();

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://telegram.org", "https://pagead2.googlesyndication.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", "https://api.telegram.org", "https://api.paystack.co"],
            frameSrc: ["'self'", "https://telegram.org"],
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// CORS configuration
app.use(cors({
    origin: [
        process.env.CLIENT_URL,
        'https://telegram.org',
        'https://web.telegram.org',
        'https://*.telegram.org'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Telegram-Init-Data']
}));

// Logging
app.use(morgan('combined'));

// Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use('/uploads', express.static('public/uploads'));
app.use('/thumbnails', express.static('public/thumbnails'));

// Database connection
const { Pool } = require('pg');
const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20, // max number of clients in the pool
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Test database connection
pool.connect()
    .then(client => {
        console.log('✅ PostgreSQL connected successfully');
        client.release();
        
        // Create tables if they don't exist
        initializeDatabase();
    })
    .catch(err => {
        console.error('❌ PostgreSQL connection error:', err.message);
        console.error('❌ Connection details:', {
            host: process.env.DB_HOST,
            database: process.env.DB_NAME,
            user: process.env.DB_USER
        });
    });

// Redis for caching and sessions
const redis = require('redis');
const redisClient = redis.createClient({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
    password: process.env.REDIS_PASSWORD,
    retry_strategy: function(options) {
        if (options.error && options.error.code === 'ECONNREFUSED') {
            return new Error('Redis server refused connection');
        }
        if (options.total_retry_time > 1000 * 60 * 60) {
            return new Error('Retry time exhausted');
        }
        if (options.attempt > 10) {
            return undefined;
        }
        return Math.min(options.attempt * 100, 3000);
    }
});

redisClient.on('connect', () => console.log('✅ Redis connected'));
redisClient.on('error', (err) => console.error('❌ Redis error:', err));

// Initialize database tables
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        // Enable UUID extension
        await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
        
        // Create tables
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                telegram_id BIGINT UNIQUE NOT NULL,
                telegram_username VARCHAR(100),
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                email VARCHAR(255),
                phone VARCHAR(20),
                profile_pic_url TEXT,
                tier VARCHAR(20) DEFAULT 'freemium',
                subscription_end DATE,
                balance_coins INTEGER DEFAULT 0,
                balance_cash DECIMAL(10,2) DEFAULT 0.00,
                total_earned DECIMAL(10,2) DEFAULT 0.00,
                level INTEGER DEFAULT 1,
                xp INTEGER DEFAULT 0,
                referral_code VARCHAR(20) UNIQUE,
                referred_by INTEGER REFERENCES users(id),
                is_verified BOOLEAN DEFAULT false,
                is_active BOOLEAN DEFAULT true,
                is_admin BOOLEAN DEFAULT false,
                is_super_admin BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_ip INET,
                settings JSONB DEFAULT '{}'
            );
            
            CREATE TABLE IF NOT EXISTS movies (
                id SERIAL PRIMARY KEY,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                google_drive_id VARCHAR(255),
                google_drive_url TEXT,
                thumbnail_url TEXT,
                duration_seconds INTEGER,
                year INTEGER,
                genre VARCHAR(100),
                rating DECIMAL(3,2) DEFAULT 0.00,
                price_coins INTEGER DEFAULT 0,
                access_tier VARCHAR(20) DEFAULT 'freemium',
                uploader_id INTEGER REFERENCES users(id),
                views_count INTEGER DEFAULT 0,
                watch_time_total BIGINT DEFAULT 0,
                votes_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS gigs (
                id SERIAL PRIMARY KEY,
                client_id INTEGER REFERENCES users(id) NOT NULL,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                category VARCHAR(50),
                budget_type VARCHAR(20),
                budget_min DECIMAL(10,2),
                budget_max DECIMAL(10,2),
                deadline TIMESTAMP,
                status VARCHAR(20) DEFAULT 'open',
                skills_required TEXT[],
                experience_level VARCHAR(20),
                is_featured BOOLEAN DEFAULT false,
                is_urgent BOOLEAN DEFAULT false,
                applications_count INTEGER DEFAULT 0,
                views_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS gig_applications (
                id SERIAL PRIMARY KEY,
                gig_id INTEGER REFERENCES gigs(id) NOT NULL,
                freelancer_id INTEGER REFERENCES users(id) NOT NULL,
                proposal TEXT,
                proposed_budget DECIMAL(10,2),
                proposed_timeline INTEGER,
                status VARCHAR(20) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(gig_id, freelancer_id)
            );
            
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                type VARCHAR(50),
                amount DECIMAL(10,2),
                coin_amount INTEGER,
                description TEXT,
                status VARCHAR(20) DEFAULT 'pending',
                payment_method VARCHAR(50),
                transaction_id VARCHAR(100),
                reference VARCHAR(100),
                metadata JSONB,
                ip_address INET,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id) NOT NULL,
                receiver_id INTEGER REFERENCES users(id),
                room_id VARCHAR(100),
                content TEXT,
                message_type VARCHAR(20) DEFAULT 'text',
                attachments TEXT[],
                is_read BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS communities (
                id SERIAL PRIMARY KEY,
                name VARCHAR(200) NOT NULL,
                description TEXT,
                avatar_url TEXT,
                cover_url TEXT,
                creator_id INTEGER REFERENCES users(id),
                privacy VARCHAR(20) DEFAULT 'public',
                members_count INTEGER DEFAULT 0,
                posts_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS community_members (
                id SERIAL PRIMARY KEY,
                community_id INTEGER REFERENCES communities(id) NOT NULL,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                role VARCHAR(20) DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(community_id, user_id)
            );
            
            CREATE TABLE IF NOT EXISTS watch_posts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                community_id INTEGER REFERENCES communities(id),
                title VARCHAR(200),
                content TEXT,
                media_url TEXT,
                likes_count INTEGER DEFAULT 0,
                comments_count INTEGER DEFAULT 0,
                shares_count INTEGER DEFAULT 0,
                earnings INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS votes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                movie_id INTEGER REFERENCES movies(id) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, movie_id)
            );
            
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                role VARCHAR(50) DEFAULT 'moderator',
                permissions JSONB DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_gigs_status ON gigs(status);
            CREATE INDEX IF NOT EXISTS idx_gigs_client_id ON gigs(client_id);
            CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
            CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
            CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id);
            CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON messages(sender_id, receiver_id);
            CREATE INDEX IF NOT EXISTS idx_votes_user_movie ON votes(user_id, movie_id);
        `);
        
        console.log('✅ Database tables created/verified');
        
        // Create super admin user if not exists
        const superAdminId = process.env.SUPER_ADMIN_TELEGRAM_ID;
        if (superAdminId) {
            await client.query(`
                INSERT INTO users (telegram_id, first_name, telegram_username, tier, is_admin, is_super_admin)
                VALUES ($1, $2, $3, 'premium', true, true)
                ON CONFLICT (telegram_id) 
                DO UPDATE SET is_admin = true, is_super_admin = true
            `, [superAdminId, 'Super Admin', 'superadmin']);
            console.log('✅ Super admin user created');
        }
        
    } catch (error) {
        console.error('❌ Database initialization error:', error);
    } finally {
        client.release();
    }
}

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const movieRoutes = require('./routes/movies');
const gigRoutes = require('./routes/gigs');
const walletRoutes = require('./routes/wallet');
const chatRoutes = require('./routes/chat');
const adminRoutes = require('./routes/admin');

// Use routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/movies', movieRoutes);
app.use('/api/gigs', gigRoutes);
app.use('/api/wallet', walletRoutes);
app.use('/api/chat', chatRoutes);
app.use('/api/admin', adminRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV,
        version: '1.0.0',
        services: {
            database: 'connected',
            redis: 'connected',
            telegram: 'configured',
            paystack: 'configured'
        }
    });
});

// Serve HTML pages for Telegram Web App
app.get('/*.html', (req, res) => {
    const htmlFile = req.path.replace('/', '');
    res.sendFile(__dirname + `/web-pages/${htmlFile}`);
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Cannot ${req.method} ${req.url}`
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('🔥 Error:', err.stack);
    
    // Don't leak error details in production
    const errorResponse = {
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    };
    
    res.status(err.status || 500).json(errorResponse);
});

// Setup Telegram webhook
async function setupTelegramWebhook() {
    const { Telegraf } = require('telegraf');
    const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
    
    const webhookUrl = `${process.env.SERVER_URL}/telegram-webhook`;
    
    try {
        await bot.telegram.setWebhook(webhookUrl);
        console.log(`✅ Telegram webhook set to: ${webhookUrl}`);
        
        // Handle webhook updates
        app.post('/telegram-webhook', (req, res) => {
            bot.handleUpdate(req.body, res);
        });
        
    } catch (error) {
        console.error('❌ Failed to set Telegram webhook:', error.message);
    }
}

// Start server
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV === 'production') {
    // For production, you need SSL certificates
    const sslOptions = {
        key: fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/privkey.pem'),
        cert: fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/fullchain.pem')
    };
    
    https.createServer(sslOptions, app).listen(PORT, () => {
        console.log(`🚀 HTTPS Server running on port ${PORT}`);
        setupTelegramWebhook();
    });
} else {
    // Development - HTTP
    app.listen(PORT, () => {
        console.log(`🚀 HTTP Server running on port ${PORT}`);
        console.log(`🌐 Environment: ${process.env.NODE_ENV}`);
        console.log(`📁 Database: ${process.env.DB_NAME}`);
        console.log(`🤖 Telegram Bot: ${process.env.TELEGRAM_BOT_TOKEN ? 'Configured' : 'Not configured'}`);
        console.log(`💰 Paystack: ${process.env.PAYSTACK_SECRET_KEY ? 'Configured' : 'Not configured'}`);
    });
}

module.exports = { app, pool, redisClient };