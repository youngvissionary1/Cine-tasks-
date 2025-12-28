-- Users Table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    telegram_id BIGINT UNIQUE,
    telegram_username VARCHAR(100),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email VARCHAR(255),
    phone VARCHAR(20),
    profile_pic_url TEXT,
    tier VARCHAR(20) DEFAULT 'freemium', -- freemium/premium
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Movies Table (Local storage for now)
CREATE TABLE movies (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    file_path TEXT, -- Local file path for development
    thumbnail_path TEXT,
    duration_seconds INTEGER,
    year INTEGER,
    genre VARCHAR(100),
    rating DECIMAL(3,2) DEFAULT 0.00,
    price_coins INTEGER DEFAULT 0,
    access_tier VARCHAR(20) DEFAULT 'freemium',
    uploader_id INTEGER REFERENCES users(id),
    views_count INTEGER DEFAULT 0,
    watch_time_total BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Gigs/Tasks Table
CREATE TABLE gigs (
    id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES users(id) NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    category VARCHAR(50),
    budget_type VARCHAR(20), -- fixed/hourly/recurring
    budget_min DECIMAL(10,2),
    budget_max DECIMAL(10,2),
    deadline TIMESTAMP,
    status VARCHAR(20) DEFAULT 'open', -- open/in_progress/completed/cancelled
    skills_required TEXT[],
    experience_level VARCHAR(20),
    is_featured BOOLEAN DEFAULT false,
    is_urgent BOOLEAN DEFAULT false,
    applications_count INTEGER DEFAULT 0,
    views_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Transactions Table
CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) NOT NULL,
    type VARCHAR(50), -- deposit/withdrawal/task_payment/movie_purchase/tip
    amount DECIMAL(10,2),
    coin_amount INTEGER,
    description TEXT,
    status VARCHAR(20) DEFAULT 'pending', -- pending/completed/failed
    payment_method VARCHAR(50),
    transaction_id VARCHAR(100), -- External payment ID
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- Messages Table
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER REFERENCES users(id) NOT NULL,
    receiver_id INTEGER REFERENCES users(id),
    room_id VARCHAR(100), -- For group chats
    content TEXT,
    message_type VARCHAR(20) DEFAULT 'text', -- text/image/voice/money/watch_post
    attachments TEXT[],
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Communities Table
CREATE TABLE communities (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    avatar_url TEXT,
    cover_url TEXT,
    creator_id INTEGER REFERENCES users(id),
    privacy VARCHAR(20) DEFAULT 'public', -- public/private/premium
    members_count INTEGER DEFAULT 0,
    posts_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Watch Posts Table
CREATE TABLE watch_posts (
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

-- Create indexes
CREATE INDEX idx_users_telegram_id ON users(telegram_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_gigs_status ON gigs(status);
CREATE INDEX idx_gigs_client_id ON gigs(client_id);
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_messages_room_id ON messages(room_id);
CREATE INDEX idx_messages_sender_receiver ON messages(sender_id, receiver_id);