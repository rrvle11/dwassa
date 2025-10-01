const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const multer = require('multer');
const sharp = require('sharp');
const { fileTypeFromBuffer } = require('file-type');
const fs = require('fs').promises;
const ipLogger = require('./ipLogger');

const app = express();
const PORT = process.env.PORT || 3000;

(require('dotenv')).config()

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"], // Allow inline event handlers
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false
}));

const generalLimiter = rateLimit({
    windowMs: 30 * 1000, 
    max: 100, 
    message: { error: 'Too many requests, please try again after 30 secs.' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, 
    message: { error: 'Too many authentication attempts, please try again later.' }
});

// Ultra-strict rate limiter for admin operations
const adminOperationLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // Only 10 admin operations per 5 minutes per IP
    message: { error: 'Too many admin operations. Please wait before trying again.' },
    standardHeaders: true,
    legacyHeaders: false,
    // Custom key generator to include user ID for more precise limiting
    keyGenerator: (req) => {
        return `admin_${req.ip}_${req.session?.userId || 'anonymous'}`;
    },
    // Custom handler for rate limit exceeded
    handler: async (req, res) => {
        try {
            await logAdminAudit(
                req.session?.userId || null,
                req.session?.user?.username || 'Unknown',
                'ADMIN_RATE_LIMIT_EXCEEDED',
                null,
                null,
                `Admin operation rate limit exceeded for ${req.method} ${req.originalUrl}`,
                req.ip
            );
        } catch (error) {
            console.error('Failed to log rate limit exceeded:', error);
        }
        res.status(429).json({ error: 'Too many admin operations. Please wait before trying again.' });
    }
});

// Rate limiter specifically for paste creation to prevent spam
const pasteCreationLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5, // Only 5 pastes per 10 minutes per user
    message: { error: 'Too many pastes created. Please wait 10 minutes before creating another paste.' },
    standardHeaders: true,
    legacyHeaders: false,
    // Custom key generator to limit per user ID instead of just IP
    keyGenerator: (req) => {
        return `paste_${req.session?.userId || req.ip}`;
    },
    // Skip rate limiting for admins
    skip: (req) => {
        return req.session?.user?.rank === 'admin';
    }
});

app.use(generalLimiter);

// Security middleware
app.use(mongoSanitize());
app.use(xss());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/assets', express.static('assets'));

// Multer configuration for secure file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 1
    },
    fileFilter: (req, file, cb) => {
        // Only allow image files
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    }
});

if (process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URL,
        touchAfter: 24 * 3600 // lazy session update
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production' && process.env.TRUST_PROXY === 'true',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

mongoose.connect(process.env.MONGODB_URL)
.then(() => console.log('MongoDB connection successful'))
.catch(err => {
    console.error('MongoDB connection failed:', err);
    process.exit(1); 
});

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    rank: { type: String, default: 'Member', enum: ['Admin', 'Manager', 'Moderator', 'Member', 'VIP', 'Criminal', 'Rich'] },
    userColor: { type: String, default: '#ffffff' },
    joinDate: { type: Date, default: Date.now },
    pastesCreated: { type: Number, default: 0 },
    bio: { type: String, default: '', maxlength: 50 },
    profilePicture: { type: String, default: '' },
    banner: { type: String, default: '' },
    profileSong: { type: String, default: '' },
    isBanned: { type: Boolean, default: false },
    banReason: { type: String, default: '' },
    bannedBy: { type: String, default: '' },
    banDate: { type: Date },
    lastLogin: { type: Date },
    loginCount: { type: Number, default: 0 },
    ipAddress: { type: String }
});

// User Activity Log Schema
const userActivitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    username: { type: String, required: true },
    action: { type: String, required: true },
    details: { type: String },
    ipAddress: { type: String },
    timestamp: { type: Date, default: Date.now }
});

// Admin Audit Log Schema
const adminAuditSchema = new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    adminUsername: { type: String, required: true },
    action: { type: String, required: true },
    targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    targetUsername: { type: String },
    details: { type: String },
    ipAddress: { type: String },
    timestamp: { type: Date, default: Date.now }
});

const pasteSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: String, required: true },
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    views: { type: Number, default: 0 },
    comments: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    likes: { type: Number, default: 0 },
    dislikes: { type: Number, default: 0 }
});

const User = mongoose.model('User', userSchema);
const Paste = mongoose.model('Paste', pasteSchema);
const UserActivity = mongoose.model('UserActivity', userActivitySchema);
const AdminAudit = mongoose.model('AdminAudit', adminAuditSchema);

const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

// Ultra-secure admin authentication middleware with enhanced verification
const requireAdmin = async (req, res, next) => {
    // Check if session exists
    if (!req.session.userId) {
        await logAdminAudit(null, 'Anonymous', 
            'ADMIN_ACCESS_NO_SESSION', null, null, 
            `Attempted admin access without session from IP: ${req.ip}`, 
            req.ip);
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
        // Fetch user from database (fresh data, not cached)
        const user = await User.findById(req.session.userId).select('+password');
        
        // Comprehensive user validation
        if (!user) {
            await logAdminAudit(req.session.userId, req.session.user?.username || 'Unknown', 
                'ADMIN_ACCESS_USER_NOT_FOUND', null, null, 
                `User not found in database for session: ${req.session.userId}`, 
                req.ip);
            return res.status(403).json({ error: 'User not found' });
        }
        
        // Check if user is banned
        if (user.isBanned) {
            await logAdminAudit(user._id, user.username, 
                'ADMIN_ACCESS_BANNED_USER', null, null, 
                `Banned user attempted admin access. Ban reason: ${user.banReason}`, 
                req.ip);
            return res.status(403).json({ error: 'Account is banned' });
        }
        
        // Verify admin rank
        if (user.rank !== 'Admin') {
            await logAdminAudit(user._id, user.username, 
                'UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT', null, null, 
                `Non-admin user attempted admin access. Current rank: ${user.rank}`, 
                req.ip);
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        // Session integrity check
        if (req.session.user && req.session.user.username !== user.username) {
            await logAdminAudit(user._id, user.username, 
                'ADMIN_SESSION_MISMATCH', null, null, 
                `Session username mismatch. Session: ${req.session.user.username}, DB: ${user.username}`, 
                req.ip);
            return res.status(403).json({ error: 'Session integrity check failed' });
        }
        
        // Additional security: Check for suspicious IP changes (optional - can be enabled)
        const currentIP = req.ip;
        if (user.ipAddress && user.ipAddress !== currentIP) {
            // Log IP change but don't block (admin might be using different networks)
            await logAdminAudit(user._id, user.username, 
                'ADMIN_IP_CHANGE_DETECTED', null, null, 
                `Admin IP changed from ${user.ipAddress} to ${currentIP}`, 
                req.ip);
        }
        
        // Update user's last activity
        await User.findByIdAndUpdate(user._id, {
            ipAddress: currentIP,
            lastLogin: new Date()
        });
        
        // Log successful admin access
        await logAdminAudit(user._id, user.username, 
            'ADMIN_ACCESS_GRANTED', null, null, 
            `Admin access granted for ${req.method} ${req.originalUrl}`, 
            req.ip);
        
        // Attach verified admin user to request
        req.adminUser = user;
        next();
        
    } catch (error) {
        console.error('Admin auth error:', error);
        
        // Log the error
        try {
            await logAdminAudit(req.session.userId || null, 
                req.session.user?.username || 'Unknown', 
                'ADMIN_AUTH_ERROR', null, null, 
                `Admin authentication error: ${error.message}`, 
                req.ip);
        } catch (logError) {
            console.error('Failed to log admin auth error:', logError);
        }
        
        res.status(500).json({ error: 'Server error during authentication' });
    }
};

// Check if user is banned middleware
const checkBanned = async (req, res, next) => {
    if (!req.session.userId) {
        return next();
    }
    
    try {
        const user = await User.findById(req.session.userId);
        if (user && user.isBanned) {
            req.session.destroy();
            return res.status(403).json({ error: 'Your account has been banned. Reason: ' + user.banReason });
        }
        next();
    } catch (error) {
        console.error('Ban check error:', error);
        next();
    }
};

// Activity logging functions
async function logUserActivity(userId, username, action, details, ipAddress) {
    try {
        // Only create UserActivity record if userId exists (for valid users)
        if (userId) {
            await UserActivity.create({
                userId,
                username,
                action,
                details,
                ipAddress
            });
        }
        
        // Also log IP to file system
        if (ipAddress && userId) {
            await ipLogger.logIP(userId, username, ipAddress, action);
        }
    } catch (error) {
        console.error('Failed to log user activity:', error);
    }
}

async function logAdminAudit(adminId, adminUsername, action, targetUserId, targetUsername, details, ipAddress) {
    try {
        await AdminAudit.create({
            adminId,
            adminUsername,
            action,
            targetUserId,
            targetUsername,
            details,
            ipAddress
        });
        
        // Also log admin IP to file system (with separate error handling)
        if (ipAddress && adminId) {
            try {
                await ipLogger.logIP(adminId, adminUsername, ipAddress, `admin_${action}`);
            } catch (ipError) {
                console.error('Failed to log IP for admin audit (non-critical):', ipError.message);
            }
        }
    } catch (error) {
        console.error('Failed to log admin audit:', error);
        // Don't throw the error to prevent it from breaking the main operation
    }
}

// Check for banned users on all routes (after function definitions)
app.use(checkBanned);

app.get('/', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const skip = (page - 1) * limit;
        const search = sanitizeSearchQuery(req.query.search || '');

        const searchQuery = search ? {
            $or: [
                { title: { $regex: search, $options: 'i' } },
                { content: { $regex: search, $options: 'i' } },
                { author: { $regex: search, $options: 'i' } }
            ]
        } : {};

        const pastes = await Paste.find(searchQuery)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);
        const totalPastes = await Paste.countDocuments(searchQuery);
        const totalPages = Math.ceil(totalPastes / limit);

        res.sendFile(path.join(__dirname, 'public/index.html'));
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});

function sanitizeString(input, maxLength = 1000) {
    if (typeof input !== 'string') return '';
    return validator.escape(input.trim()).substring(0, maxLength);
}

function validateUsername(username) {
    if (!username || typeof username !== 'string') return false;
    return validator.isLength(username.trim(), { min: 3, max: 20 }) && 
           validator.isAlphanumeric(username.trim());
}

function validateEmail(email) {
    if (!email || typeof email !== 'string') return false;
    return validator.isEmail(email.trim());
}

function validatePassword(password) {
    if (!password || typeof password !== 'string') return false;
    return validator.isLength(password, { min: 6, max: 100 });
}

function sanitizeSearchQuery(query) {
    if (!query || typeof query !== 'string') return '';
    return query.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&').substring(0, 100);
}

function sanitizeBio(bio) {
    if (!bio || typeof bio !== 'string') return '';
    
    // Remove HTML tags and potentially dangerous characters
    let sanitized = bio
        .replace(/<[^>]*>/g, '') // Remove HTML tags
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+\s*=/gi, '') // Remove event handlers
        .replace(/&lt;script&gt;/gi, '') // Remove encoded script tags
        .replace(/&lt;\/script&gt;/gi, '')
        .trim();
    
    // Limit length
    if (sanitized.length > 50) {
        sanitized = sanitized.substring(0, 50);
    }
    
    return sanitized;
}

app.get('/api/pastes', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const skip = (page - 1) * limit;
        const search = sanitizeSearchQuery(req.query.search || '');

        const searchQuery = search ? {
            $or: [
                { title: { $regex: search, $options: 'i' } },
                { content: { $regex: search, $options: 'i' } },
                { author: { $regex: search, $options: 'i' } }
            ]
        } : {};

        const pastes = await Paste.find(searchQuery)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);
        const totalPastes = await Paste.countDocuments(searchQuery);
        const totalPages = Math.ceil(totalPastes / limit);

        res.json({
            pastes,
            currentPage: page,
            totalPages,
            totalPastes,
            user: req.session.user || null
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.get('/paste/:id', async (req, res) => {
    try {
        const pasteId = req.params.id;
        const paste = await Paste.findById(pasteId);
        if (!paste) {
            return res.status(404).send('Paste not found');
        }
        paste.views += 1;
        await paste.save();
        res.sendFile(path.join(__dirname, 'public/paste.html'));
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});

app.get('/api/paste/:id', async (req, res) => {
    try {
        const pasteId = req.params.id;
        const paste = await Paste.findById(pasteId);
        if (!paste) {
            return res.status(404).json({ error: 'Paste not found' });
        }

        // Get author ban information if author exists
        let authorBanInfo = null;
        if (paste.author && paste.author !== 'Anonymous') {
            const author = await User.findOne({ username: paste.author }).select('isBanned banReason bannedBy bannedAt');
            if (author) {
                authorBanInfo = {
                    isBanned: author.isBanned,
                    banReason: author.banReason,
                    bannedBy: author.bannedBy,
                    bannedAt: author.bannedAt
                };
            }
        }

        res.json({
            paste,
            authorBanInfo,
            user: req.session.user || null
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.get('/users', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/users.html'));
});

app.get('/api/user', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const user = await User.findById(req.session.userId).select('username rank _id');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ 
            user: { 
                username: user.username, 
                rank: user.rank,
                id: user._id 
            } 
        });
    } catch (error) {
        console.error('Error fetching current user:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/users', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 20;
        const skip = (page - 1) * limit;
        const search = sanitizeSearchQuery(req.query.search || '');

        const searchQuery = search ? { username: { $regex: search, $options: 'i' } } : {};
        const users = await User.find(searchQuery, '-password')
            .sort({ joinDate: 1 })
            .skip(skip)
            .limit(limit);
        const totalUsers = await User.countDocuments(searchQuery);
        const totalPages = Math.ceil(totalUsers / limit);

        res.json({
            users,
            currentPage: page,
            totalPages,
            totalUsers,
            user: req.session.user || null
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.get('/add-paste', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public/add-paste.html'));
});

app.post('/api/add-paste', pasteCreationLimiter, requireAuth, async (req, res) => {
    try {
        const { title, content } = req.body;
        
        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required' });
        }
        
        // Enhanced content validation to prevent spam
        const trimmedTitle = title.trim();
        const trimmedContent = content.trim();
        
        // Check minimum content length to prevent empty/minimal spam
        if (trimmedTitle.length < 3) {
            return res.status(400).json({ error: 'Title must be at least 3 characters long' });
        }
        
        if (trimmedContent.length < 10) {
            return res.status(400).json({ error: 'Content must be at least 10 characters long' });
        }
        
        // Check for repetitive content (spam pattern detection)
        const contentWords = trimmedContent.toLowerCase().split(/\s+/);
        const uniqueWords = new Set(contentWords);
        const repetitionRatio = uniqueWords.size / contentWords.length;
        
        if (contentWords.length > 20 && repetitionRatio < 0.3) {
            return res.status(400).json({ error: 'Content appears to be repetitive spam. Please provide meaningful content.' });
        }
        
        // Check for excessive special characters (common in spam)
        const specialCharCount = (trimmedContent.match(/[^a-zA-Z0-9\s\n\r\t.,!?;:'"()-]/g) || []).length;
        const specialCharRatio = specialCharCount / trimmedContent.length;
        
        if (specialCharRatio > 0.3) {
            return res.status(400).json({ error: 'Content contains too many special characters. Please provide readable content.' });
        }
        
        const sanitizedTitle = sanitizeString(trimmedTitle, 200);
        const sanitizedContent = sanitizeString(trimmedContent, 50000);
        
        if (!sanitizedTitle || !sanitizedContent) {
            return res.status(400).json({ error: 'Invalid title or content after sanitization' });
        }
        
        // Check for duplicate content from the same user in the last 24 hours
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const existingPaste = await Paste.findOne({
            authorId: req.session.userId,
            $or: [
                { title: sanitizedTitle },
                { content: sanitizedContent }
            ],
            createdAt: { $gte: oneDayAgo }
        });
        
        if (existingPaste) {
            return res.status(400).json({ error: 'You have already created a paste with identical title or content in the last 24 hours' });
        }
        
        const paste = new Paste({
            title: sanitizedTitle,
            content: sanitizedContent,
            author: req.session.user.username,
            authorId: req.session.userId
        });
        await paste.save();
        await User.findByIdAndUpdate(req.session.userId, {
            $inc: { pastesCreated: 1 }
        });
        res.json({ success: true, pasteId: paste._id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public/login.html'));
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!validateUsername(username) || !validatePassword(password)) {
            await logUserActivity(null, username || 'Unknown', 'LOGIN_FAILED', 
                'Invalid credentials format', req.ip, req.get('User-Agent'));
            return res.status(400).json({ error: 'Invalid credentials format' });
        }
        
        const user = await User.findOne({ username: username.trim() });
        if (!user || !await bcrypt.compare(password, user.password)) {
            await logUserActivity(user?._id || null, username, 'LOGIN_FAILED', 
                'Invalid username or password', req.ip, req.get('User-Agent'));
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        if (user.isBanned) {
            await logUserActivity(user._id, user.username, 'LOGIN_BLOCKED', 
                `Banned user attempted login. Reason: ${user.banReason}`, req.ip, req.get('User-Agent'));
            return res.status(403).json({ error: 'Your account has been banned. Reason: ' + user.banReason });
        }
        
        // Update user login information
        await User.findByIdAndUpdate(user._id, {
            lastLogin: new Date(),
            $inc: { loginCount: 1 },
            ipAddress: req.ip
        });
        
        req.session.userId = user._id;
        req.session.user = {
            id: user._id,
            username: user.username,
            rank: user.rank
        };
        
        await logUserActivity(user._id, user.username, 'LOGIN_SUCCESS', 
            'User logged in successfully', req.ip);
        
        // Log IP for login event
        await ipLogger.logIP(user._id, user.username, req.ip, 'login');
        
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.get('/register', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public/register.html'));
});

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!validateUsername(username) || !validateEmail(email) || !validatePassword(password)) {
            return res.status(400).json({ error: 'Invalid input format' });
        }
        
        const sanitizedUsername = username.trim();
        const sanitizedEmail = email.trim().toLowerCase();
        
        const existingUser = await User.findOne({ 
            $or: [{ username: sanitizedUsername }, { email: sanitizedEmail }] 
        });
        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({
            username: sanitizedUsername,
            email: sanitizedEmail,
            password: hashedPassword
        });
        await user.save();
        req.session.userId = user._id;
        req.session.user = {
            id: user._id,
            username: user.username,
            rank: user.rank
        };
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Failed to log out' });
        }
        res.clearCookie('connect.sid'); 
        res.json({ success: true });
    });
});

// Ultra-secure admin delete paste endpoint with multiple verification layers
app.delete('/api/admin/paste/:id', adminOperationLimiter, requireAdmin, async (req, res) => {
    try {
        const pasteId = req.params.id;
        
        // Validate additional security headers
        const adminAction = req.get('X-Admin-Action');
        const pasteTitle = req.get('X-Paste-Title');
        
        if (adminAction !== 'delete-paste') {
            await logAdminAudit(
                req.adminUser._id,
                req.adminUser.username,
                'DELETE_PASTE_INVALID_HEADER',
                null,
                null,
                `Invalid admin action header: ${adminAction}`,
                req.ip
            );
            return res.status(400).json({ error: 'Invalid admin action header' });
        }
        
        // Validate paste ID format
        if (!mongoose.Types.ObjectId.isValid(pasteId)) {
            await logAdminAudit(
                req.adminUser._id,
                req.adminUser.username,
                'DELETE_PASTE_FAILED',
                null,
                null,
                `Invalid paste ID format: ${pasteId}`,
                req.ip
            );
            return res.status(400).json({ error: 'Invalid paste ID format' });
        }
        
        // Double-check admin status from database (not just session)
        const currentUser = await User.findById(req.adminUser._id);
        if (!currentUser || currentUser.rank !== 'Admin' || currentUser.isBanned) {
            await logAdminAudit(
                req.adminUser._id,
                req.adminUser.username,
                'DELETE_PASTE_UNAUTHORIZED',
                null,
                null,
                `Admin verification failed - Current rank: ${currentUser?.rank || 'Unknown'}, Banned: ${currentUser?.isBanned || 'Unknown'}`,
                req.ip
            );
            return res.status(403).json({ error: 'Admin verification failed' });
        }
        
        // Verify session integrity
        if (!req.session.userId || req.session.userId.toString() !== currentUser._id.toString()) {
            await logAdminAudit(
                req.adminUser._id,
                req.adminUser.username,
                'DELETE_PASTE_SESSION_MISMATCH',
                null,
                null,
                `Session mismatch detected`,
                req.ip
            );
            return res.status(403).json({ error: 'Session verification failed' });
        }
        
        const paste = await Paste.findById(pasteId);
        
        if (!paste) {
            await logAdminAudit(
                req.adminUser._id,
                req.adminUser.username,
                'DELETE_PASTE_NOT_FOUND',
                null,
                null,
                `Attempted to delete non-existent paste: ${pasteId}`,
                req.ip
            );
            return res.status(404).json({ error: 'Paste not found' });
        }
        
        // Verify paste title matches (additional security check)
        if (pasteTitle && paste.title !== pasteTitle) {
            await logAdminAudit(
                req.adminUser._id,
                req.adminUser.username,
                'DELETE_PASTE_TITLE_MISMATCH',
                null,
                paste.author,
                `Paste title verification failed. Expected: "${pasteTitle}", Actual: "${paste.title}"`,
                req.ip
            );
            return res.status(400).json({ error: 'Paste title verification failed' });
        }
        
        // Log detailed admin action BEFORE deletion
        await logAdminAudit(
            req.adminUser._id,
            req.adminUser.username,
            'DELETE_PASTE_INITIATED',
            null,
            paste.author,
            `Initiating deletion of paste: "${paste.title}" (ID: ${pasteId}) by ${paste.author}, Views: ${paste.views}, Created: ${paste.createdAt}, Provided Title: ${pasteTitle}`,
            req.ip
        );
        
        // Additional security: Log user activity for the paste author if they exist
        try {
            const pasteAuthorUser = await User.findOne({ username: paste.author });
            if (pasteAuthorUser) {
                await logUserActivity(
                    pasteAuthorUser._id,
                    paste.author,
                    'PASTE_DELETED_BY_ADMIN',
                    `Paste "${paste.title}" deleted by admin ${req.adminUser.username}`,
                    req.ip,
                    req.get('User-Agent')
                );
            }
        } catch (authorLogError) {
            console.error('Error logging author activity:', authorLogError);
        }
        
        // Store paste data before deletion for response
        const pasteData = {
            _id: paste._id,
            title: paste.title,
            author: paste.author,
            createdAt: paste.createdAt,
            views: paste.views
        };
        
        // Perform the deletion
        const deletedPaste = await Paste.findByIdAndDelete(pasteId);
        
        if (!deletedPaste) {
            await logAdminAudit(
                req.adminUser._id,
                req.adminUser.username,
                'DELETE_PASTE_FAILED',
                null,
                paste.author,
                `Failed to delete paste: "${paste.title}" - paste may have been already deleted`,
                req.ip
            );
            return res.status(500).json({ error: 'Failed to delete paste' });
        }
        
        // Log successful deletion
        await logAdminAudit(
            req.adminUser._id,
            req.adminUser.username,
            'DELETE_PASTE_SUCCESS',
            null,
            paste.author,
            `Successfully deleted paste: "${paste.title}" (ID: ${pasteId}) by ${paste.author}`,
            req.ip
        );
        
        // Security log for monitoring
        console.log(`[SECURITY] Admin ${req.adminUser.username} (${req.adminUser._id}) deleted paste "${paste.title}" (${pasteId}) from IP ${req.ip} at ${new Date().toISOString()}`);
        
        res.json({ 
            success: true, 
            message: 'Paste deleted successfully',
            deletedPaste: pasteData,
            deletedBy: req.adminUser.username,
            deletedAt: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Error deleting paste:', error);
        
        // Log the error for security monitoring
        try {
            await logAdminAudit(
                req.adminUser?._id || null,
                req.adminUser?.username || 'Unknown',
                'DELETE_PASTE_ERROR',
                null,
                null,
                `Server error during paste deletion: ${error.message}`,
                req.ip
            );
        } catch (logError) {
            console.error('Failed to log admin audit for error:', logError);
        }
        
        res.status(500).json({ error: 'Server error during deletion' });
    }
});

// Admin check user rank endpoint (for frontend to determine if user is admin)
app.get('/api/admin/check', async (req, res) => {
    if (!req.session.userId) {
        return res.json({ isAdmin: false });
    }
    
    try {
        const user = await User.findById(req.session.userId);
        const isAdmin = user && user.rank === 'Admin' && !user.isBanned;
        res.json({ isAdmin, rank: user?.rank || null });
    } catch (error) {
        console.error('Error checking admin status:', error);
        res.json({ isAdmin: false });
    }
});

// Admin endpoint to change user ranks
app.post('/api/admin/change-rank', adminOperationLimiter, requireAdmin, async (req, res) => {
    try {
        const { userId, newRank } = req.body;
        
        // Validate input
        if (!userId || !newRank) {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'RANK_CHANGE_INVALID_INPUT',
                null,
                null,
                `Missing required fields: userId=${userId}, newRank=${newRank}`,
                req.ip
            );
            return res.status(400).json({ error: 'User ID and new rank are required' });
        }
        
        // Validate user ID format
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'RANK_CHANGE_INVALID_USER_ID',
                null,
                null,
                `Invalid user ID format: ${userId}`,
                req.ip
            );
            return res.status(400).json({ error: 'Invalid user ID format' });
        }
        
        // Validate rank
        const validRanks = ['Admin', 'Manager', 'Moderator', 'Member', 'VIP', 'Criminal', 'Rich'];
        if (!validRanks.includes(newRank)) {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'RANK_CHANGE_INVALID_RANK',
                userId,
                null,
                `Invalid rank specified: ${newRank}`,
                req.ip
            );
            return res.status(400).json({ error: 'Invalid rank specified' });
        }
        
        // Find target user
        const targetUser = await User.findById(userId);
        if (!targetUser) {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'RANK_CHANGE_USER_NOT_FOUND',
                userId,
                null,
                `Target user not found: ${userId}`,
                req.ip
            );
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Prevent self-rank change
        if (targetUser._id.toString() === req.session.userId.toString()) {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'RANK_CHANGE_SELF_ATTEMPT',
                userId,
                targetUser.username,
                `Admin attempted to change their own rank from ${targetUser.rank} to ${newRank}`,
                req.ip
            );
            return res.status(403).json({ error: 'Cannot change your own rank' });
        }
        
        // Store old rank for logging
        const oldRank = targetUser.rank;
        
        // Prevent demoting other admins (only super admin functionality would allow this)
        if (targetUser.rank === 'Admin' && newRank !== 'Admin') {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'RANK_CHANGE_ADMIN_DEMOTION_BLOCKED',
                userId,
                targetUser.username,
                `Attempted to demote admin ${targetUser.username} from Admin to ${newRank}`,
                req.ip
            );
            return res.status(403).json({ error: 'Cannot demote other administrators' });
        }
        
        // Update user rank
        await User.findByIdAndUpdate(userId, { rank: newRank });
        
        // Log successful rank change
        await logAdminAudit(
            req.session.userId,
            req.session.user.username,
            'RANK_CHANGE_SUCCESS',
            userId,
            targetUser.username,
            `Changed user rank from ${oldRank} to ${newRank}`,
            req.ip
        );
        
        // Log user activity for the target user
        await logUserActivity(
            userId,
            targetUser.username,
            'RANK_CHANGED',
            `Rank changed from ${oldRank} to ${newRank} by admin ${req.session.user.username}`,
            req.ip,
            req.get('User-Agent')
        );
        
        res.json({ 
            success: true, 
            message: `User rank changed from ${oldRank} to ${newRank}`,
            oldRank,
            newRank,
            targetUser: {
                id: targetUser._id,
                username: targetUser.username
            }
        });
        
    } catch (error) {
        console.error('Error changing user rank:', error);
        
        // Log error
        try {
            await logAdminAudit(
                req.session.userId,
                req.session.user?.username || 'Unknown',
                'RANK_CHANGE_ERROR',
                req.body?.userId || null,
                null,
                `Server error during rank change: ${error.message}`,
                req.ip
            );
        } catch (logError) {
            console.error('Failed to log admin audit for rank change error:', logError);
        }
        
        res.status(500).json({ error: 'Server error during rank change' });
    }
});

// Admin endpoint to get detailed user information
app.get('/api/admin/user-details/:userId', adminOperationLimiter, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        // Validate user ID format
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'USER_DETAILS_INVALID_ID',
                null,
                null,
                `Invalid user ID format: ${userId}`,
                req.ip
            );
            return res.status(400).json({ error: 'Invalid user ID format' });
        }
        
        // Find target user with all details
        const targetUser = await User.findById(userId).select('+password +email');
        if (!targetUser) {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'USER_DETAILS_NOT_FOUND',
                userId,
                null,
                `Target user not found: ${userId}`,
                req.ip
            );
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Get user activity logs (last 10 entries)
        const userLogs = await UserActivity.find({ userId: userId })
            .sort({ timestamp: -1 })
            .limit(10)
            .select('action details timestamp ipAddress');
        
        // Get IP addresses from log files
        const userIPLogs = await ipLogger.getUserIPs(userId);
        const latestIP = await ipLogger.getUserLatestIP(userId);
        
        // Prepare detailed user information
        const userDetails = {
            basicInfo: {
                id: targetUser._id,
                username: targetUser.username,
                email: targetUser.email || 'Not provided',
                rank: targetUser.rank,
                isBanned: targetUser.isBanned,
                banReason: targetUser.banReason || '',
                bannedBy: targetUser.bannedBy || '',
                bannedAt: targetUser.bannedAt || null,
                createdAt: targetUser.createdAt,
                lastLogin: targetUser.lastLogin || 'Never'
            },
            securityInfo: {
                passwordHash: targetUser.password,
                ipAddress: latestIP || targetUser.ipAddress || 'Not available',
                ipHistory: userIPLogs.slice(0, 10), // Show last 10 IP entries
                loginAttempts: targetUser.loginAttempts || 0,
                lastFailedLogin: targetUser.lastFailedLogin || 'None'
            },
            profileInfo: {
                bio: targetUser.bio || 'No bio',
                profilePicture: targetUser.profilePicture || 'Default',
                profileBanner: targetUser.profileBanner || 'Default',
                profileSong: targetUser.profileSong || 'None'
            },
            activityLogs: userLogs
        };
        
        // Log admin access to user details
        await logAdminAudit(
            req.session.userId,
            req.session.user.username,
            'USER_DETAILS_ACCESSED',
            userId,
            targetUser.username,
            `Admin accessed detailed information for user ${targetUser.username}`,
            req.ip
        );
        
        res.json({ success: true, userDetails });
        
    } catch (error) {
        console.error('Error fetching user details:', error);
        
        // Log error
        try {
            await logAdminAudit(
                req.session.userId,
                req.session.user?.username || 'Unknown',
                'USER_DETAILS_ERROR',
                req.params?.userId || null,
                null,
                `Server error during user details fetch: ${error.message}`,
                req.ip
            );
        } catch (logError) {
            console.error('Failed to log admin audit for user details error:', logError);
        }
        
        res.status(500).json({ error: 'Server error fetching user details' });
    }
});

// Ban user endpoint
app.post('/api/admin/ban-user', adminOperationLimiter, requireAdmin, async (req, res) => {
    try {
        console.log('Ban request received:', { userId: req.body.userId, reason: req.body.reason });
        
        const { userId, reason } = req.body;
        
        if (!userId || !reason) {
            console.log('Missing required fields:', { userId: !!userId, reason: !!reason });
            return res.status(400).json({ error: 'User ID and ban reason are required' });
        }
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            console.log('Invalid user ID:', userId);
            return res.status(400).json({ error: 'Invalid user ID' });
        }
        
        const targetUser = await User.findById(userId);
        if (!targetUser) {
            console.log('User not found:', userId);
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Prevent banning other admins
        if (targetUser.rank === 'Admin') {
            console.log('Attempted to ban admin:', targetUser.username);
            return res.status(403).json({ error: 'Cannot ban other administrators' });
        }
        
        console.log('Updating user ban status for:', targetUser.username);
        
        // Update user ban status
        await User.findByIdAndUpdate(userId, {
            isBanned: true,
            banReason: reason.trim(),
            bannedBy: req.session.user.username,
            bannedAt: new Date()
        });
        
        console.log('User ban status updated successfully');
        
        // Log admin action (with error handling)
        try {
            await logAdminAudit(
                req.session.userId,
                req.session.user.username,
                'USER_BANNED',
                userId,
                targetUser.username,
                `User banned. Reason: ${reason.trim()}`,
                req.ip
            );
            console.log('Admin audit logged successfully');
        } catch (auditError) {
            console.error('Failed to log admin audit (non-critical):', auditError);
        }
        
        console.log('Ban operation completed successfully');
        res.json({ success: true, message: 'User banned successfully' });
        
    } catch (error) {
        console.error('Error banning user:', error);
        res.status(500).json({ error: 'Server error banning user' });
    }
});

// Unban user endpoint
app.post('/api/admin/unban-user', adminOperationLimiter, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }
        
        const targetUser = await User.findById(userId);
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Update user ban status
        await User.findByIdAndUpdate(userId, {
            isBanned: false,
            banReason: '',
            bannedBy: '',
            bannedAt: null
        });
        
        // Log admin action
        await logAdminAudit(
            req.session.userId,
            req.session.user.username,
            'USER_UNBANNED',
            userId,
            targetUser.username,
            `User unbanned by admin`,
            req.ip
        );
        
        res.json({ success: true, message: 'User unbanned successfully' });
        
    } catch (error) {
        console.error('Error unbanning user:', error);
        res.status(500).json({ error: 'Server error unbanning user' });
    }
});

// Profile routes
app.get('/profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/profile.html'));
});

app.get('/api/profile/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        const profile = await User.findById(userId).select('-password -ipAddress');
        if (!profile) {
            return res.status(404).json({ error: 'User not found' });
        }

        let currentUser = null;
        let isOwnProfile = false;

        if (req.session.userId) {
            currentUser = await User.findById(req.session.userId).select('username rank _id');
            isOwnProfile = req.session.userId.toString() === userId;
        }

        res.json({
            profile,
            currentUser: currentUser ? { 
                username: currentUser.username, 
                rank: currentUser.rank,
                id: currentUser._id 
            } : null,
            isOwnProfile
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/profile/update', upload.fields([
    { name: 'profilePicture', maxCount: 1 },
    { name: 'banner', maxCount: 1 }
]), async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const { bio } = req.body;
        const updateData = {};

        // Handle bio update with XSS protection
        if (bio !== undefined) {
            const sanitizedBio = sanitizeBio(bio);
            updateData.bio = sanitizedBio;
        }

        // Helper function to process image files
        const processImageFile = async (file, type, maxSize, maxSizeGif, dimensions) => {
            // Validate file type using file-type library
            const fileType = await fileTypeFromBuffer(file.buffer);
            
            if (!fileType || !['image/jpeg', 'image/png', 'image/gif', 'image/webp'].includes(fileType.mime)) {
                throw new Error(`Invalid ${type} file type. Only JPEG, PNG, GIF, and WebP images are allowed.`);
            }

            // Additional security: Check for malicious content
            const fileHeader = file.buffer.slice(0, 100).toString('hex');
            if (fileHeader.includes('3c73637269707420') || // <script 
                fileHeader.includes('6a6176617363726970743a') || // javascript:
                fileHeader.includes('3c696672616d65')) { // <iframe
                throw new Error(`${type} contains potentially malicious content.`);
            }

            // Handle GIFs differently to preserve animation
            let processedBuffer;
            let fileExtension;
            
            if (fileType.mime === 'image/gif') {
                // For GIFs, preserve animation by not processing with Sharp
                processedBuffer = file.buffer;
                fileExtension = 'gif';
                
                // Basic size check for GIFs (since we can't easily resize animated GIFs)
                if (file.size > maxSizeGif) {
                    throw new Error(`GIF ${type} size must be less than ${maxSizeGif / (1024 * 1024)}MB to preserve animation.`);
                }
            } else {
                // Process other image types with sharp for optimization
                processedBuffer = await sharp(file.buffer)
                    .resize(dimensions.width, dimensions.height, { 
                        fit: 'cover',
                        position: 'center'
                    })
                    .jpeg({ quality: 80 })
                    .toBuffer();
                fileExtension = 'jpg';
            }

            // Generate unique filename with appropriate extension
            const filename = `${type}_${req.session.userId}_${Date.now()}.${fileExtension}`;
            const filepath = path.join(__dirname, 'uploads', filename);

            // Save processed image
            await fs.writeFile(filepath, processedBuffer);

            return `/uploads/${filename}`;
        };

        // Handle profile picture upload
        if (req.files && req.files.profilePicture && req.files.profilePicture[0]) {
            try {
                const profilePicturePath = await processImageFile(
                    req.files.profilePicture[0], 
                    'profile', 
                    5 * 1024 * 1024, // 5MB for regular images
                    3 * 1024 * 1024, // 3MB for GIFs
                    { width: 300, height: 300 }
                );

                // Delete old profile picture if it exists
                const currentUser = await User.findById(req.session.userId);
                if (currentUser.profilePicture && currentUser.profilePicture.startsWith('/uploads/')) {
                    const oldPath = path.join(__dirname, currentUser.profilePicture);
                    try {
                        await fs.unlink(oldPath);
                    } catch (err) {
                        console.log('Old profile picture not found or already deleted');
                    }
                }

                updateData.profilePicture = profilePicturePath;
            } catch (imageError) {
                console.error('Profile picture processing error:', imageError);
                return res.status(400).json({ error: imageError.message || 'Invalid profile picture file or processing failed.' });
            }
        }

        // Handle banner upload
        if (req.files && req.files.banner && req.files.banner[0]) {
            try {
                const bannerPath = await processImageFile(
                    req.files.banner[0], 
                    'banner', 
                    8 * 1024 * 1024, // 8MB for regular images
                    5 * 1024 * 1024, // 5MB for GIFs
                    { width: 1200, height: 300 }
                );

                // Delete old banner if it exists
                const currentUser = await User.findById(req.session.userId);
                if (currentUser.banner && currentUser.banner.startsWith('/uploads/')) {
                    const oldPath = path.join(__dirname, currentUser.banner);
                    try {
                        await fs.unlink(oldPath);
                    } catch (err) {
                        console.log('Old banner not found or already deleted');
                    }
                }

                updateData.banner = bannerPath;
            } catch (imageError) {
                console.error('Banner processing error:', imageError);
                return res.status(400).json({ error: imageError.message || 'Invalid banner file or processing failed.' });
            }
        }

        // Update user in database
        const user = await User.findByIdAndUpdate(
            req.session.userId,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ 
            message: 'Profile updated successfully', 
            user: {
                username: user.username,
                bio: user.bio,
                profilePicture: user.profilePicture,
                banner: user.banner,
                rank: user.rank
            }
        });
    } catch (error) {
        console.error('Profile update error:', error);
        
        // Clean up uploaded file if there was an error
        if (req.file) {
            const filename = `profile_${req.session.userId}_${Date.now()}.jpg`;
            const filepath = path.join(__dirname, 'uploads', filename);
            try {
                await fs.unlink(filepath);
            } catch (cleanupError) {
                console.log('No file to cleanup');
            }
        }
        
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.get('/api/user/:userId/pastes', async (req, res) => {
    try {
        const { userId } = req.params;
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const skip = (page - 1) * limit;

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Search by both authorId and author (username) to handle legacy pastes
        const searchQuery = {
            $or: [
                { authorId: userId },
                { author: user.username }
            ]
        };

        const totalPastes = await Paste.countDocuments(searchQuery);

        const pastes = await Paste.find(searchQuery)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .select('title views createdAt _id');

        const totalPages = Math.ceil(totalPastes / limit);

        const response = {
            pastes,
            currentPage: page,
            totalPages,
            totalPastes
        };

        res.json(response);
    } catch (error) {
        console.error('Error fetching user pastes:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Auth check endpoint
app.get('/api/auth/check', async (req, res) => {
    if (req.session.userId) {
        try {
            const user = await User.findById(req.session.userId).select('-password');
            if (user && !user.isBanned) {
                res.json({
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    rank: user.rank,
                    joinDate: user.joinDate,
                    bio: user.bio,
                    profilePicture: user.profilePicture
                });
            } else {
                res.status(401).json({ error: 'User not found or banned' });
            }
        } catch (error) {
            console.error('Auth check error:', error);
            res.status(500).json({ error: 'Server error' });
        }
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});



// Get user pastes endpoint
app.get('/api/user/pastes', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const pastes = await Paste.find({ authorId: userId })
            .select('title content language createdAt views')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const totalPastes = await Paste.countDocuments({ authorId: userId });
        const totalPages = Math.ceil(totalPastes / limit);

        res.json({
            pastes,
            pagination: {
                currentPage: page,
                totalPages,
                totalPastes,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });

    } catch (error) {
        console.error('Get user pastes error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete paste endpoint
app.delete('/api/pastes/:id', requireAuth, async (req, res) => {
    try {
        const pasteId = req.params.id;
        const userId = req.session.userId;

        const paste = await Paste.findById(pasteId);
        if (!paste) {
            return res.status(404).json({ error: 'Paste not found' });
        }

        // Check if user owns the paste or is admin
        const user = await User.findById(userId);
        if (paste.authorId.toString() !== userId && user.rank !== 'Admin') {
            return res.status(403).json({ error: 'You can only delete your own pastes' });
        }

        await Paste.findByIdAndDelete(pasteId);

        // Update user's paste count
        if (paste.authorId.toString() === userId) {
            await User.findByIdAndUpdate(userId, { $inc: { pastesCreated: -1 } });
        }

        // Log the deletion
        await logUserActivity(
            userId,
            user.username,
            'PASTE_DELETE',
            `Deleted paste: ${paste.title}`,
            req.ip,
            req.get('User-Agent')
        );

        res.json({ success: true, message: 'Paste deleted successfully' });

    } catch (error) {
        console.error('Paste deletion error:', error);
        res.status(500).json({ error: 'Server error during deletion' });
    }
});









app.get('/hall-of-autism', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/placeholder.html'));
});

app.get('/support', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/placeholder.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});