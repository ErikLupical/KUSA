require('dotenv').config();
const InitializeDatabaseStructures = require('./seedDatabase');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require("crypto");
const jwt = require('jsonwebtoken');
const cookiesParser = require('cookie-parser');
const Socket_Server = require("socket.io");
const http = require('http');
const nodemailer = require('nodemailer');
const multer = require("multer");
const uploadFile = require("./utils/uploadFile");
const populateFileBase64 = require("./utils/populateFileBase64");
const adminRoutes = require("./adminroutes");
const path = require("path");

const upload = multer({ storage: multer.memoryStorage() });

const app = express();

app.use(cors({
    origin: process.env.FRONTEND_ORIGIN || true,
    credentials: true, // allow sending/receiving cookies
}));
app.use(express.json());
app.use(cookiesParser());

const chat_server = http.createServer(app);
const io = new Socket_Server.Server(chat_server, {
    cors: {
        origin: process.env.FRONTEND_ORIGIN || true,
        credentials: true,
    },
});

// ---- DB CONNECT ----
const PORT = process.env.PORT || 3001;
const mongoURL = process.env.MONGO_URL || 'mongodb://localhost:27017/kusa';
const RESET_SEEDED_DATA = process.env.RESET_SEEDED_DATA || 'false';

// Models
const { User, File, Server, Member, Room, Message, Attachment, Reaction, TimeSlot, Notification } = require('./schema.js');

// config (env)
const ACCESS_TTL = process.env.ACCESS_TTL || '2d';
const REFRESH_TTL = process.env.REFRESH_TTL || '90d';
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'dev-access-secret';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret';

// Helpers
let db_status = false;
const oid = (id) => mongoose.Types.ObjectId.isValid(id);
const asInt = (v, d) => {
    const n = parseInt(v, 10);
    return Number.isFinite(n) ? n : d;
};

const norm = v => (typeof v === 'string' && v.trim() === '' ? null : v);

// Auth middleware
function auth(req, res, next) {
    try {
        const token = req.cookies?.access_token;
        if (!token) {
            return res.status(401).json({ status: 'failed', message: 'Missing token' });
        }
        const { sub } = jwt.verify(token, JWT_ACCESS_SECRET); // payload = { sub }
        req.userId = sub; // store user id for handlers
        next();
    } catch {
        return res.status(401).json({ status: 'failed', message: 'Expired or invalid token' });
    }
}

// optionalAuth middleware, ignore bad/missing token; treat as anonymous
function optionalAuth(req, res, next) {
    try {
        const token = req.cookies?.access_token;
        if (!token) return next();
        const { sub } = jwt.verify(token, JWT_ACCESS_SECRET);
        req.userId = sub;
        next();
    } catch {
        next();
    }
}

// Health route
app.get('/', async (req, res) => {
    console.log("Health check received");
    let data = { backend: true, database: db_status };
    res.send(data);
});

console.log(process.env.NODE_ENV === "production");
const baseCookie = {
    partitioned: true,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",           // must be true in prod
    sameSite: "none",
    path: "/",
};


function signAccess(payload) { return jwt.sign(payload, JWT_ACCESS_SECRET, { expiresIn: ACCESS_TTL }); }
function signRefresh(payload) { return jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: REFRESH_TTL }); }

// ISO string for “now + ms”
function epochMsPlus(ms) { return new Date(Date.now() + ms).toISOString(); }

// Convert TTL to ms
function parseTtlToMs(ttl) {
    const m = /^(\d+)([smhd])$/.exec(ttl);
    if (!m) throw new Error('Invalid TTL format. Use like "15m", "2h", "7d".');
    const n = Number(m[1]); const unit = m[2];
    return n * ({ s: 1000, m: 60000, h: 3600000, d: 86400000 }[unit]);
}

function setAuthCookies(res, accessToken, refreshToken) {
    console.log("Setting auth cookies");
    res.cookie('access_token', accessToken, { ...baseCookie, maxAge: parseTtlToMs(ACCESS_TTL) });
    res.cookie('refresh_token', refreshToken, { ...baseCookie, maxAge: parseTtlToMs(REFRESH_TTL) });
}

// Time table helpers
const DAY_ENUM = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

// Overlap check helper: returns true if new [s,e) overlaps any existing range
function overlaps(aStart, aEnd, bStart, bEnd) {
    return Math.max(aStart, bStart) < Math.min(aEnd, bEnd);
}
// =================== ADMIN DASHBOARD =====================

app.use("/api/v1/admin", adminRoutes);

// ==================== AUTH  =====================

// Register
app.post('/api/v1/login/register', async (req, res) => {
    try {
        const { username, email, password, password_confirmation } = req.body;


        // Tell missing required fields
        const missing = [];
        if (!username) missing.push("username");
        if (!email) missing.push("email");
        if (!password) missing.push("password");
        if (!password_confirmation) missing.push("password_confirmation");

        if (password.length < 8 || password_confirmation.length < 8) {
            return res.status(400).json({ status: "failed", message: "Password must be at least 8 characters" });
        }

        if (missing.length > 0) {
            return res.status(400).send(`Missing required fields: ${missing.join(", ")}`);
        }

        // Check if email already exists
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(409).json({ status: "failed", message: "This email has already been registered" });
        }

        // Check if username already exists
        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.status(409).json({ status: "failed", message: "This username is already taken" });
        }

        // Check if password and password confirmation match
        if (password != password_confirmation) {
            return res.status(400).json({ status: "failed", message: "Password and Confirm Password don't match" })
        }

        // Hash password
        const ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 10;
        const hashedPassword = await bcrypt.hash(password, ROUNDS);

        // Create new user
        const newUser = new User({
            username: username,
            email: email,
            password_hash: hashedPassword
        });

        await newUser.save();
        return res.json({
            status: "success",
            message: "Registration Success",
            user: { id: newUser._id, email: newUser.email }
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ status: "failed", message: "Unable to Register, please try again later" });
    }
});

// Change password
app.post('/api/v1/account/change-password', auth, async (req, res) => {
    try {
        const { old_password, new_password } = req.body;
        if (!old_password || !new_password) {
            return res.status(400).json({ status: "failed", message: "Missing fields" });
        }
        const user = await User.findById(req.userId).select('+password_hash');
        if (!user) return res.status(404).json({ status: "failed", message: "User not found" });

        const ok = await bcrypt.compare(old_password, user.password_hash);
        if (!ok) return res.status(401).json({ status: "failed", message: "Wrong current password" });

        if (new_password.length < 8) {
            return res.status(400).json({ status: "failed", message: "Password must be at least 8 characters" });
        }

        const ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 10;
        user.password_hash = await bcrypt.hash(new_password, ROUNDS);
        await user.save();

        return res.json({ status: "success", message: "Password updated" });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ status: "failed", message: "Unable to change password" });
    }
});


// change Password via resetting token
app.post('/api/v1/account/reset-password-via-token', async (req, res) => {
    try {
        const { token, password } = req.body; // Remove 'await'
        
        if (!token) {
            return res.status(400).json({ message: "Token required" });
        }

        if (password.length < 8) {
            return res.status(400).json({ status: "failed", message: "Password must be at least 8 characters" });
        }

        
        const hashedToken = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: "Token invalid or expired" });
        }

        const ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 10;
        user.password_hash = await bcrypt.hash(password, ROUNDS);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        return res.json({ status: 'success', message: 'Password updated' });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ status: "failed", message: "Unable to change password" });
    }
});

// Login
app.post('/api/v1/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Check if email and password are provided
        if (!email || !password) {
            return res.status(400).json({ status: "failed", message: "Email and password are required" });
        }

        // Find user by email or username
        const user = await User.findOne({ $or: [{ email }, { username: email }] }).select('+password_hash');

        // Check if user exists
        if (!user) {
            return res.status(404).json({ status: "failed", message: "User not found" });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ status: "failed", message: "Invalid email or password" });
        }

        // Create tokens
        const payload = { sub: user._id.toString() };

        console.log("generating token")

        const accessToken = signAccess(payload);               // 15m by default
        const refreshToken = signRefresh({ sub: payload.sub }); // 14d by default

        // Set Cookies
        setAuthCookies(res, accessToken, refreshToken);

        // Send Success Response with Tokens
        const safeUser = user.toObject();
        delete safeUser.password_hash;

        return res.status(200).json({
            status: "success",
            message: "Login successful",
            user: safeUser,
            session: {
                access_expires_at: epochMsPlus(parseTtlToMs(ACCESS_TTL)),
                refresh_expires_at: epochMsPlus(parseTtlToMs(REFRESH_TTL)),
            },
            accessToken: accessToken,
            refreshToken: refreshToken,
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ status: "failed", message: "Unable to login, please try again later" });
    }
});

// Who am I (protected)
app.get('/api/v1/auth/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.userId)
            .populate('icon_file')
            .populate('banner_file')
            .populate({
                path: 'friends',
                select: '_id username icon_file',
                populate: { path: 'icon_file' }
            })
        if (!user) return res.status(404).json({ status: 'failed', message: 'User not found' });
        const userObject = user.toObject ? user.toObject() : user;
        populateFileBase64(userObject);

        const { password_hash, __v, ...safeUserData } = userObject;
        return res.status(200).json({ status: 'success', user: safeUserData });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ status: 'failed', message: 'Server error' });
    }
});

app.patch('/api/v1/auth/me', auth, async (req, res) => {
    try {
        const fields = ['username', 'faculty', 'major', 'pronouns', 'birthday', 'phone', 'email', 'bio'];

        // 1) reject unexpected fields
        const unknown = Object.keys(req.body).filter(k => !fields.includes(k));
        if (unknown.length > 0) {
            return res.status(400).json({ message: 'invalid fields', invalid_fields: unknown });
        }

        // 2) collect updates
        const updates = {};
        fields.forEach(field => {
            if (req.body[field] !== undefined) updates[field] = req.body[field];
        });
        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: 'no valid fields to update' });
        }

        // 3) coerce/validate some values
        if ('birthday' in updates) {
            if (updates.birthday === '' || updates.birthday === null) {
                updates.birthday = null;
            } else {
                const d = new Date(updates.birthday);
                if (isNaN(d.getTime())) return res.status(400).json({ message: 'invalid birthday' });
                updates.birthday = d;
            }
        }
        // Normalize empty strings to null for optional text fields (so schema defaults/nulls behave)
        ['faculty', 'major', 'pronouns', 'phone', 'bio'].forEach(f => {
            if (f in updates && updates[f] === '') updates[f] = null;
        });

        // 4) apply update with validation and get back the updated doc
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            updates,
            { new: true, runValidators: true, context: 'query' }
        )
            .populate('icon_file')
            .populate('banner_file')
            .lean();

        if (!updatedUser) return res.status(404).json({ message: 'user not found' });

        const { password_hash, __v, ...safeUser } = updatedUser;
        res.json({ status: 'success', user: safeUser });
    } catch (e) {
        // Mongoose validation errors
        if (e.name === 'ValidationError') {
            const errors = Object.keys(e.errors).map(k => ({ field: k, message: e.errors[k].message }));
            return res.status(400).json({ message: 'validation failed', errors });
        }
        // duplicate key (unique) error
        if (e.code === 11000) {
            const field = Object.keys(e.keyPattern || e.keyValue || {})[0];
            return res.status(409).json({ message: 'duplicate value', field });
        }
        console.error(e);
        res.status(500).json({ message: 'failed to update user' });
    }
});

// Refresh access token from refresh cookie
app.post('/api/v1/auth/refresh', (req, res) => {
    try {
        const rt = req.cookies?.refresh_token;
        if (!rt) return res.status(401).json({ status: 'failed', message: 'No refresh token' });

        const { sub } = jwt.verify(rt, JWT_REFRESH_SECRET);
        const at = signAccess({ sub });
        res.cookie('access_token', at, { ...baseCookie, maxAge: parseTtlToMs(ACCESS_TTL) });
        res.json({ ok: true, access_expires_at: epochMsPlus(parseTtlToMs(ACCESS_TTL)) });
    } catch {
        return res.status(401).json({ status: 'failed', message: 'Invalid refresh token' });
    }
});

// Logout (clear cookies)
app.post('/api/v1/auth/logout', (_req, res) => {
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/' });
    res.json({ ok: true });
});

// ===================== USER ======================

// Get user info
app.get('/api/v1/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!oid(id)) return res.status(400).json({ message: 'invalid user id' });

        const user = await User.findById(id)
            .populate('icon_file')
            .populate('banner_file')
            .lean();

        populateFileBase64(user);

        if (!user) return res.status(404).json({ message: 'user not found' });

        const { password_hash, __v, ...safeUser } = user;
        res.json({ status: 'success', user: safeUser });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'failed to fetch user' });
    }
});

// Find user
app.get('/api/v1/user/find/:q', async (req, res) => {
    try {
        const q = (req.params.q || '').trim();
        if (!q) return res.status(400).json({ status: 'failed', message: 'missing query parameter q or input' });

        // email detection
        const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q);

        const filter = isEmail ? { email: q.toLowerCase() } : { username: q };

        const user = await User.findOne(filter)
            .select('+created_at +updated_at') // return some useful metadata if present
            .populate('icon_file')
            .populate('banner_file')
            .lean();

        if (!user) return res.status(404).json({ status: 'failed', message: 'user not found' });

        const { password_hash, __v, ...safeUser } = user;
        return res.json({ status: 'success', user: safeUser });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ status: 'failed', message: 'failed to find user' });
    }
});

// ===================== USERS LIST ======================
// GET /api/v1/users?q=alice&page=1&limit=20&sort=-created_at
app.get('/api/v1/users', async (req, res) => {
    try {
        const q = (req.query.q || '').trim();
        const page = Math.max(parseInt(req.query.page || '1', 10), 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 100);
        const sort = (req.query.sort || '-created_at'); // e.g. 'username' or '-created_at'

        const filter = {};
        if (q) {
            // case-insensitive search on username OR email
            const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
            filter.$or = [{ username: rx }, { email: rx }];
        }

        const cursor = User.find(filter)
            .select('+created_at +updated_at') // password_hash is already select:false
            .populate('icon_file')
            .populate('banner_file')
            .sort(sort)
            .skip((page - 1) * limit)
            .limit(limit)
            .lean();

        const [items, total] = await Promise.all([
            cursor,
            User.countDocuments(filter)
        ]);
        
        items.forEach(u => populateFileBase64(u));

        res.json({
            status: 'success',
            page,
            limit,
            total,
            has_more: page * limit < total,
            users: items
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'failed', message: 'failed to list users' });
    }
});

// DELETE /api/v1/users/:id
app.delete('/api/v1/users/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;
        if (!oid(id)) return res.status(400).json({ message: 'invalid user id' });

        // Fetch target
        const target = await User.findById(id).lean();
        if (!target) return res.status(404).json({ message: 'user not found' });

        // Optional: if you store user role in token, decode earlier and set req.role.
        // For now, allow only self-delete.
        if (req.userId !== id) {
            return res.status(403).json({ message: 'forbidden: can only delete your own account' });
        }

        await User.deleteOne({ _id: id });
        // If you want "soft delete", flip a flag instead of deleting.

        // Clear cookies if the user deleted themself
        if (req.userId === id) {
            res.clearCookie('access_token', { path: '/' });
            res.clearCookie('refresh_token', { path: '/' });
        }

        res.json({ status: 'success', deleted_id: id });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'failed', message: 'failed to delete user' });
    }
});

// ===================== Time Table ====================
// Create a time slot for the current user
app.post('/api/v1/timetable', auth, async (req, res) => {
    try {
        // 1) coerce numbers up front
        const title = req.body.title;
        const description = norm(req.body.description);
        const dayRaw = req.body.day;
        const start = asInt(req.body.start_min, -1);
        const end = asInt(req.body.end_min, -1);
        const location = norm(req.body.location);
        const color = norm(req.body.color);

        // 2) normalize/validate
        const day = (typeof dayRaw === 'string') ? dayRaw.toLowerCase() : dayRaw;
        if (!title || !day || start === -1 || end === -1) {
            return res.status(400).json({ status: 'failed', message: 'title, day, start_min, end_min are required' });
        }
        if (!DAY_ENUM.includes(day)) {
            return res.status(400).json({ status: 'failed', message: 'invalid day' });
        }
        if (start < 0 || start > 1439 || end < 1 || end > 1440 || start >= end) {
            return res.status(400).json({ status: 'failed', message: 'invalid time range' });
        }

        // 3) Mongo-side overlap check (faster than pulling all)
        const clash = await TimeSlot.findOne({
            owner: req.userId,
            day,
            start_min: { $lt: end },
            end_min: { $gt: start },
        }).lean();

        if (clash) {
            return res.status(409).json({
                status: 'failed',
                message: `overlaps with "${clash.title}" (${clash.start_min}-${clash.end_min})`
            });
        }

        // 4) Create
        const slot = await TimeSlot.create({
            owner: req.userId,
            title,
            description,
            day,
            start_min: start,
            end_min: end,
            location,
            color,
        });

        return res.status(201).json({ status: 'success', slot });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ status: 'failed', message: 'failed to create slot' });
    }
});

// GET timetable
app.get('/api/v1/users/:userId/timetable', optionalAuth, async (req, res) => {
    try {
        const { userId } = req.params;
        let { day } = req.query;

        if (!oid(userId)) return res.status(400).json({ status: 'failed', message: 'invalid user id' });

        const user = await User.findById(userId).lean();
        if (!user) return res.status(404).json({ status: 'failed', message: 'user not found' });

        const isOwner = req.userId?.toString() === userId.toString();

        if (!isOwner && user.timetable_visibility !== 'public') {
            return res.status(403).json({ status: 'failed', message: 'this timetable is private' });
        }

        // normalize/validate day
        if (typeof day === 'string') day = day.toLowerCase();
        if (day && !DAY_ENUM.includes(day)) {
            return res.status(400).json({ status: 'failed', message: 'invalid day' });
        }

        const filter = { owner: userId };
        if (day) filter.day = day;

        // temporary sort: by day order + start_min (see §2 for stable day-order)
        const slots = await TimeSlot.find(filter)
            .sort({ start_min: 1 }) // we'll reorder by day below
            .lean();

        // reorder by semantic day order
        const dayIndex = d => ({ mon: 0, tue: 1, wed: 2, thu: 3, fri: 4, sat: 5, sun: 6 })[d];
        slots.sort((a, b) => (dayIndex(a.day) - dayIndex(b.day)) || (a.start_min - b.start_min));

        res.json({
            status: 'success',
            slots
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'failed', message: 'failed to fetch timetable' });
    }
});

// Update a slot I own
app.patch('/api/v1/timetable/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;
        if (!oid(id)) return res.status(400).json({ status: 'failed', message: 'invalid id' });

        const slot = await TimeSlot.findOne({ _id: id, owner: req.userId });
        if (!slot) return res.status(404).json({ status: 'failed', message: 'slot not found' });

        // 1) apply updates (coerce and normalize)
        if ('title' in req.body) slot.title = req.body.title;
        if ('description' in req.body) slot.description = norm(req.body.description);
        if ('location' in req.body) slot.location = norm(req.body.location);
        if ('color' in req.body) slot.color = norm(req.body.color);
        if ('day' in req.body) slot.day = (typeof req.body.day === 'string') ? req.body.day.toLowerCase() : req.body.day;
        if ('start_min' in req.body) slot.start_min = asInt(req.body.start_min, slot.start_min);
        if ('end_min' in req.body) slot.end_min = asInt(req.body.end_min, slot.end_min);

        // 2) validate
        if (!DAY_ENUM.includes(slot.day)) {
            return res.status(400).json({ status: 'failed', message: 'invalid day' });
        }
        if (slot.start_min < 0 || slot.start_min > 1440 || slot.end_min < 0 || slot.end_min > 1440 || slot.end_min <= slot.start_min) {
            return res.status(400).json({ status: 'failed', message: 'invalid time range' });
        }

        // 3) Mongo-side overlap check (exclude self)
        const clash = await TimeSlot.findOne({
            owner: req.userId,
            day: slot.day,
            _id: { $ne: slot._id },
            start_min: { $lt: slot.end_min },
            end_min: { $gt: slot.start_min },
        }).lean();

        if (clash) {
            return res.status(409).json({
                status: 'failed',
                message: `overlaps with "${clash.title}" (${clash.start_min}–${clash.end_min})`
            });
        }

        // 4) save
        await slot.save();
        res.json({ status: 'success', slot });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'failed', message: 'failed to update slot' });
    }
});

// Delete a slot I own
app.delete('/api/v1/timetable/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;
        if (!oid(id)) return res.status(400).json({ status: 'failed', message: 'invalid id' });
        const slot = await TimeSlot.findOneAndDelete({ _id: id, owner: req.userId });
        if (!slot) return res.status(404).json({ status: 'failed', message: 'slot not found' });

        res.json({ status: 'success', deleted_id: id });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'failed', message: 'failed to delete slot' });
    }
});


// ====================== Messages =====================
// Get paginated and sorted messages in a DM with another user
app.get('/api/v1/chats/dms/:userId/messages', auth, async (req, res) => {
    try {
        const otherUserId = req.params.userId;
        const currentUserId = req.userId;

        console.log("Fetching DMs between", currentUserId, "and", otherUserId);

        // Pagination
        const page = Math.max(parseInt(req.query.page || '1', 10), 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 100);

        // Sort direction
        const sortDir = req.query.sort === 'desc' ? -1 : 1; // Default: newest first

        // Find direct messages between the two users
        const messages = await Message.find({
            context_type: "User",
            $or: [
                { context: otherUserId, sender: currentUserId },
                { context: currentUserId, sender: otherUserId }
            ]
        })
        .populate({
            path: 'sender',
            select: 'username display_name icon_file',
            populate: { path: 'icon_file' }
        })
        .populate({
            path: 'recipients',
            select: 'username display_name icon_file',
            populate: { path: 'icon_file' }
        })
        .populate({
            path: 'reply_to',
            populate: [
                {
                    path: 'sender',
                    select: 'username display_name icon_file',
                    populate: { path: 'icon_file' }
                },
                {
                    path: 'recipients',
                    select: 'username display_name icon_file',
                    populate: { path: 'icon_file' }
                }
            ]
        })
        .populate({
            path: 'context',
            select: 'username display_name icon_file',
            populate: { path: 'icon_file' }
        })
        .sort({ created_at: sortDir })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean();

        messages.forEach(msg => populateFileBase64(msg));

        // Get total count for pagination
        const total = await Message.countDocuments({
            context_type: 'User',
            $or: [
                {
                    context: otherUserId,
                    sender: currentUserId
                },
                {
                    context: currentUserId,
                    sender: otherUserId
                }
            ]
        });

        res.json({
            status: 'success',
            page,
            limit,
            total,
            has_more: page * limit < total,
            messages: messages
        });

    } catch (error) {
        console.error('Error fetching user chat:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to fetch chat messages' });
    }
});

// Get paginated and sorted messages in a room
app.get('/api/v1/chats/rooms/:roomId/messages', auth, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const currentUserId = req.userId;

        // Pagination
        const page = Math.max(parseInt(req.query.page || '1', 10), 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 100);
        const sortDir = req.query.sort === 'asc' ? 1 : -1;

        // Verify room exists
        const room = await Room.findById(roomId).populate("server");
        if (!room) {
            return res.status(404).json({ status: 'failed', message: 'Room not found' });
        }

        // Verify user is member of the server
        const membership = await Member.findOne({
            server: room.server._id,
            user: currentUserId
        });
        if (!membership) {
            return res.status(403).json({ status: 'failed', message: 'Not a member of this server' });
        }

        // Get **all users** in this server
        const members = await Member.find({ server: room.server._id })
            .populate({
                path: "user",
                select: "username display_name icon_file",
                populate: { path: "icon_file" }
            })
            .lean();

        const memberUserIds = members.map(m => m.user._id.toString());

        // Fetch messages
        const messages = await Message.find({
            context_type: "Room",
            context: roomId
        })
        .populate({
            path: "sender",
            select: "username display_name icon_file",
            populate: { path: "icon_file" }
        })
        .populate({
            path: "reply_to",
            populate: [
                {
                    path: "sender",
                    select: "username display_name icon_file",
                    populate: { path: "icon_file" }
                },
                {
                    path: "recipients",
                    select: "username display_name icon_file",
                    populate: { path: "icon_file" }
                }
            ]
        })
        .populate({
            path: "context",
            select: "title server",
            populate: {
                path: "server",
                select: "server_name icon_file",
                populate: { path: "icon_file" }
            }
        })
        .sort({ created_at: sortDir })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean();

        // Add base64 + inject recipients = all server users
        messages.forEach(msg => {
            populateFileBase64(msg);
            msg.recipients = memberUserIds.map(uid => ({ _id: uid }));
        });

        const total = await Message.countDocuments({
            context_type: "Room",
            context: roomId
        });

        const server = await Server.findById(room.server._id)
            .populate("icon_file")
            .lean();
        if (server) populateFileBase64(server);

        res.json({
            status: 'success',
            page,
            limit,
            total,
            has_more: page * limit < total,
            server,
            roomName: room.title,
            messages,
            members
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ status: 'failed', message: 'Failed to fetch room messages' });
    }
});

// Edit message
app.patch("/api/v1/messages/:id", auth, async (req, res) => {
    try {
        const id = req.params.id.trim();
        const { content } = req.body;

        console.log("PATCH body:", req.body);

        // --- Validate ID ---
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ status: "failed", message: "Invalid message ID" });
        }

        // --- Validate content ---
        if (!content || !content.trim()) {
            return res.status(400).json({ status: "failed", message: "Empty content" });
        }

        // --- Find message and populate sender info ---
        let msg = await Message.findById(id)
            .populate({
                path: "sender",
                select: "_id username",
            });

        if (!msg) {
            return res.status(404).json({ status: "failed", message: "Message not found" });
        }

        // --- Populate context safely ---
        if (msg.context_type === "Room") {
            await msg.populate({ path: "context", populate: { path: "server" } });
        } else {
            await msg.populate("context");
        }

        // --- Permission checks ---
        const senderUserId = msg.sender?._id.toString();
        const currentUserId = req.userId.toString();
        let canEdit = false;

        if (msg.context_type === "User") {
            // Direct message: only sender can edit
            canEdit = senderUserId === currentUserId;
        } else if (msg.context_type === "Room") {
            // Room: sender, owner, or moderator can edit
            const member = await Member.findOne({
                user: currentUserId,
                server: msg.context.server,
            });

            if (member && ["owner", "moderator"].includes(member.role)) canEdit = true;
            if (senderUserId === currentUserId) canEdit = true;
        }

        if (!canEdit) {
            return res.status(403).json({
                status: "failed",
                message: "You do not have permission to edit this message",
            });
        }

        // --- Update the message ---
        msg.content = content.trim();
        msg.edited_count += 1;
        msg.edited_at = new Date();

        await msg.save();

        if (io) {
            const payload = {
                _id: msg._id.toString(),
                content: msg.content,
                edited_count: msg.edited_count,
                edited_at: msg.edited_at,
                context_type: msg.context_type,
                context: msg.context._id ? msg.context._id.toString() : msg.context.toString(),
            };

            if (msg.context_type === "User") {
                // DM: notify both users (sender + other)
                const otherUserId = payload.context; // context is the other user in DM
                io.to(senderUserId).emit("message_edited", payload);
                if (otherUserId && otherUserId !== senderUserId) {
                    io.to(otherUserId).emit("message_edited", payload);
                }
            } else if (msg.context_type === "Room") {
                // Room: notify all users in that server
                const members = await Member.find({ server: msg.context.server }).select("user");
                members.forEach((m) => {
                    const uid = m.user?.toString();
                    if (uid) {
                        io.to(uid).emit("message_edited", payload);
                    }
                });
            }
        }

        return res.json({ status: "success", message: msg });
    } catch (err) {
        console.error("Edit message error:", err);
        return res.status(500).json({
            status: "failed",
            message: "Failed to edit message",
            error: err.message,
        });
    }
});

// unsend message
app.patch('/api/v1/messages/:id/unsend', auth, async (req, res) => {
    try {
        const { id } = req.params;
        if (!oid(id)) {
            console.log("Invalid message ID:", id);
            return res.status(400).json({ status: 'failed', message: 'invalid id' });
        }

        const message = await Message.findById(id)
            .populate({
                path: "sender",
                select: "_id username",
            });

        if (!message || message.active === false) {
            return res.status(404).json({
                status: 'failed',
                message: 'message not found or already inactive'
            });
        }

        if (message.context_type === "Room") {
            await message.populate({ path: "context", populate: { path: "server" } });
        } else {
            await message.populate("context");
        }

        const senderId = message.sender?._id?.toString();
        const currentUserId = req.userId?.toString();

        let canModerate = false;
        if (message.context_type === "User") {
            canModerate = senderId === currentUserId;
        } else if (message.context_type === "Room") {
            const member = await Member.findOne({
                user: currentUserId,
                server: message.context.server,
            });

            const userRole = member.role?.toUpperCase();
            canModerate = senderId === currentUserId || ["OWNER", "MODERATOR"].includes(userRole);
        }

        if (!canModerate) {
            return res.status(403).json({ status: 'failed', message: 'No permission to unsend this message' });
        }

        message.active = false;

        await message.save();

        // Notify via WebSocket
        if (io) {
            const payload = {
                _id: message._id.toString(),
                active: false,
                content: message.content,
                context_type: message.context_type,
            };

            if (message.context_type === "User") {
                // DM: notify both users
                const otherUserId = message.context._id.toString(); // populated above
                io.to(senderId).emit("message_unsent", payload);
                io.to(otherUserId).emit("message_unsent", payload);
            } else if (message.context_type === "Room") {
                // Room: notify every user in that server
                const members = await Member.find({ server: message.context.server }).select("user");
                members.forEach(m => {
                    io.to(m.user.toString()).emit("message_unsent", payload);
                });
            }
        }

        return res.json({
            status: 'success',
            message: 'Message unsent',
            data: {
                _id: message._id,
                active: message.active,
                edited_count: message.edited_count,
                content: message.content
            }
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ status: 'failed', message: 'failed to unsend message' });
    }
});


// ====================== Servers =====================

// CREATE SERVER
app.post('/api/v1/servers/create', auth, async (req, res) => {
    try {
        const { serverName } = req.body;
        const userId = req.userId;

        if (!serverName || !userId) {
            return res.status(400).json({ message: 'Missing serverName or userId.' });
        }

        // ✅ 1. Create server
        const newServer = await Server.create({
            server_name: serverName,
            icon_file: null,
            banned_users: []
        });

        // ✅ 2. Add creator as owner
        const ownerMember = await Member.create({
            user: userId,
            server: newServer._id,
            role: 'OWNER'
        });

        // ✅ 3. Create first/default room
        const generalRoom = await Room.create({
            server: newServer._id,
            title: "general",
            order: 0
        });

        return res.status(201).json({
            message: "Server created successfully!",
            server: newServer,
            owner: ownerMember,
            firstRoomId: generalRoom._id
        });

    } catch (error) {
        console.error("Error creating server:", error);
        return res.status(500).json({ message: "Internal server error." });
    }
});

// List servers (that the user is a member of)
app.get('/api/v1/servers', auth, async (req, res) => {
    try {

        // Find member records for the user
        const memberRecords = await Member.find({ user: req.userId }).select('_id server');

        const memberServerIds = memberRecords.map(m => m.server);

        // Find servers where the user is a member
        const servers = await Server.find({ _id: { $in: memberServerIds } })
            .populate('icon_file')
            .lean();

        servers.forEach(s => populateFileBase64(s));

        // find rooms for each server
        for (let server of servers) {
            // Ensure rooms are returned in the defined "order" field
            const rooms = await Room.find({ server: server._id })
                .sort({ order: 1 })
                .lean();
            server.rooms = rooms;
        }

        res.json({
            status: 'success',
            servers
        });

    } catch (error) {
        console.error('Error fetching servers:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to fetch servers' });
    }
});

// GET /api/v1/servers/banned
app.get('/api/v1/servers/banned', async (req, res) => {
    const { serverId } = req.query;

    const server = await Server.findById(serverId)
        .populate('banned_users', 'username display_name icon_file');

    if (!server) {
        return res.status(404).json({ message: "Server not found" });
    }

    res.json(server.banned_users);
});

// Get server by Id
app.get('/api/v1/servers/:serverId', auth, async (req, res) => {
    try {
        const { serverId } = req.params;
        const server = await Server.findById(serverId);

        if (!server) {
            return res.status(404).json({ message: "Server not found." });
        }

        return res.status(200).json({ server });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Internal server error." });
    }
});

// Update server icon
app.put("/api/v1/servers/:serverId/icon", auth, upload.single("icon"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const server = await Server.findById(req.params.serverId);
    if (!server) return res.status(404).json({ error: "Server not found" });

    const fileDoc = await File.create({
      storage_key: req.file.filename,
      byte_size: req.file.size,
      mime_type: req.file.mimetype,
      original_name: req.file.originalname
    });

    server.icon_file = fileDoc._id;
    await server.save();

    res.status(200).json({ message: "Icon updated", file: fileDoc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.get("/api/v1/files/:fileId", async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);

    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    // Path where Multer stores files (modify if using another folder)
    const filePath = path.join(__dirname, "uploads", file.storage_key);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Stored file missing" });
    }

    // Send file with the correct MIME type
    res.setHeader("Content-Type", file.mime_type);
    res.setHeader("Content-Length", file.byte_size);
    res.sendFile(filePath);
  } catch (err) {
    console.error("File download error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


// Change server name
app.put('/api/v1/servers/:serverId/name', auth, async (req, res) => {
    try {
        const { serverId } = req.params;
        const { newName } = req.body;
        const requester = req.userId;

        if (!newName || newName.trim().length === 0) {
            return res.status(400).json({ message: "New name required." });
        }

        // Check permission
        const member = await Member.findOne({ server: serverId, user: requester });
        if (!member || (member.role !== "OWNER" && member.role !== "MODERATOR")) {
            return res.status(403).json({ message: "No permission to change server name." });
        }

        // Update server name
        await Server.findByIdAndUpdate(serverId, { server_name: newName.trim() });

        return res.status(200).json({ message: "Server name updated successfully." });

    } catch (error) {
        console.error("Change name error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});


// Generate server invite link (which is just href={`/join/${server._id}`})
app.post('/api/v1/servers/:serverId/invite', auth, async (req, res) => {
    try {
        const { serverId } = req.params;
        // Check if the user is a member of the server
        const isMember = await Member.findOne({ server: serverId, user: req.userId });
        console.log(isMember);
        if (!isMember) {
            return res.status(403).json({ status: 'failed', message: 'You are not a member of this server' });
        }
        // For simplicity, the invite link is just the server ID.
        const inviteLink = `${process.env.FRONTEND_ORIGIN || 'http://localhost:3000'}/join/${serverId}`;
        res.json({ status: 'success', invite_link: inviteLink });
    } catch (error) {
        console.error('Error generating invite link:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to generate invite link' });
    }
});

// Join server
app.post('/api/v1/servers/join', auth, async (req, res) => {
    try {
        const { serverId } = req.body;
        const userId = req.userId;

        if (!userId || !serverId) {
            return res.status(400).json({ message: 'Missing userId or serverId.' });
        }

        const server = await Server.findById(serverId);
        if (!server) {
            return res.status(404).json({ message: 'Server not found.' });
        }

        // if user is banned
        if (server.banned_users.includes(userId)) {
            return res.status(403).json({ message: 'You are banned from this server.' });
        }

        // Check membership
        let member = await Member.findOne({ user: userId, server: serverId });
        if (!member) {
            member = await Member.create({
                user: userId,
                server: serverId,
                role: 'MEMBER'
            });
        }

        // Get first room
        const firstRoom = await Room.findOne({ server: serverId }).sort({ order: 1 });

        return res.status(200).json({
            message: "Success",
            member,
            firstRoomId: firstRoom ? firstRoom._id : null
        });

    } catch (error) {
        console.error('Error joining server:', error);
        return res.status(500).json({ message: 'Internal server error.' });
    }
});

// Set role for a member
app.post('/api/v1/servers/set-role', auth, async (req, res) => {
    try {
        const { serverId, userId, role } = req.body;
        const requester = req.userId;
        if (!serverId || !userId || !role) {
            return res.status(400).json({ message: "Missing serverId, userId, or role" });
        }
        // Check permissions (only OWNER can set roles)
        const requesterMember = await Member.findOne({ server: serverId, user: requester });
        if (!requesterMember || requesterMember.role !== 'OWNER') {
            return res.status(403).json({ message: "No permission to set roles" });
        }
        // Update member role
        const updatedMember = await Member.findOneAndUpdate(
            { user: userId, server: serverId },
            { role: role },
            { new: true }
        );
        if (!updatedMember) {
            return res.status(404).json({ message: "Member not found in server" });
        }
        return res.status(200).json({ message: "Role updated successfully", member: updatedMember });
    } catch (error) {
        console.error("Set role error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Kick user from server
app.post('/api/v1/servers/kick', auth, async (req, res) => {
    try {
        const { serverId, userId } = req.body;
        const requester = req.userId;

        if (!serverId || !userId) {
            return res.status(400).json({ message: "Missing serverId or userId" });
        }

        // Check permissions (only OWNER or MODERATOR can kick)
        const requesterMember = await Member.findOne({ server: serverId, user: requester });
        if (!requesterMember || (requesterMember.role !== 'OWNER' && requesterMember.role !== 'MODERATOR')) {
            return res.status(403).json({ message: "No permission to kick users" });
        }

        // Remove membership
        await Member.deleteOne({ user: userId, server: serverId });

        return res.status(200).json({ message: "User kicked successfully" });
    } catch (error) {
        console.error("Kick error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Leave server
app.post('/api/v1/servers/leave', auth, async (req, res) => {
    try {
        const { serverId } = req.body;
        const userId = req.userId;

        if (!serverId) {
            return res.status(400).json({ message: "Missing serverId" });
        }

        // Find membership
        const member = await Member.findOne({ server: serverId, user: userId });
        if (!member) {
            return res.status(400).json({ message: "You are not a member of this server." });
        }

        // If leaving member is OWNER → ensure there is another owner
        if (member.role === "OWNER") {
            const totalOwners = await Member.countDocuments({
                server: serverId,
                role: "OWNER"
            });

            if (totalOwners <= 1) {
                return res.status(403).json({
                    message: "You are the only owner. Promote another owner before leaving."
                });
            }
        }

        // Remove the membership
        await Member.deleteOne({ server: serverId, user: userId });

        return res.status(200).json({ message: "You left the server." });

    } catch (error) {
        console.error("Leave error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Ban user
app.post('/api/v1/servers/ban', auth, async (req, res) => {
    try {
        const { serverId, userId } = req.body;
        const requester = req.userId;

        if (!serverId || !userId) {
            return res.status(400).json({ message: "Missing serverId or userId" });
        }

        const requesterMember = await Member.findOne({ server: serverId, user: requester });
        if (!requesterMember || (requesterMember.role !== 'OWNER' && requesterMember.role !== 'MODERATOR')) {
            return res.status(403).json({ message: "No permission to ban users" });
        }

        // Add to banned list (if not already)
        await Server.findByIdAndUpdate(serverId, {
            $addToSet: { banned_users: userId }
        });

        // Remove membership
        await Member.deleteOne({ user: userId, server: serverId });

        return res.status(200).json({ message: "User banned successfully" });
    } catch (error) {
        console.error("Ban error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// POST /api/v1/servers/unban
app.post('/api/v1/servers/unban', async (req, res) => {
    const { serverId, userId } = req.body;

    const server = await Server.findById(serverId);
    if (!server) {
        return res.status(404).json({ message: "Server not found" });
    }

    // Remove user from banned_users
    server.banned_users = server.banned_users.filter(
        id => id.toString() !== userId
    );

    await server.save();

    res.json({ message: "User unbanned." });
});

// DELETE SERVER
app.delete('/api/v1/servers/:serverId', auth, async (req, res) => {
    try {
        const { serverId } = req.params;
        const userId = req.userId;

        if (!oid(serverId)) {
            return res.status(400).json({ status: 'failed', message: 'Invalid server id' });
        }

        const server = await Server.findById(serverId);
        if (!server) {
            return res.status(404).json({ status: 'failed', message: 'Server not found' });
        }

        const ownerRecord = await Member.findOne({ server: serverId, user: userId, role: 'OWNER' });
        if (!ownerRecord) {
            return res.status(403).json({ status: 'failed', message: 'Only server owner can delete server' });
        }

        const rooms = await Room.find({ server: serverId }, '_id');
        const roomIds = rooms.map(r => r._id);

        const messages = await Message.find({
            context_type: 'Room',
            context: { $in: roomIds }
        }, '_id');

        const messageIds = messages.map(m => m._id);

        await Reaction.deleteMany({ message: { $in: messageIds } });

        const attachments = await Attachment.find({ message: { $in: messageIds } });

        for (const att of attachments) {
            const fileDoc = await File.findById(att.file);
            if (fileDoc) {
                await File.deleteOne({ _id: fileDoc._id });
            }
        }

        await Attachment.deleteMany({ message: { $in: messageIds } });
        await Message.deleteMany({ _id: { $in: messageIds } });
        await Room.deleteMany({ server: serverId });
        await Member.deleteMany({ server: serverId });

        if (server.icon_file) {
            await File.deleteOne({ _id: server.icon_file });
        }

        await Server.deleteOne({ _id: serverId });

        return res.json({
            status: 'success',
            message: 'Server and all related data deleted',
            deletedServerId: serverId
        });

    } catch (err) {
        console.error("Error deleting server:", err);
        return res.status(500).json({ status: 'failed', message: 'Internal server error' });
    }
});

// ====================== Rooms =====================

// Add a room to a server
app.post('/api/v1/rooms', auth, async (req, res) => {
    try {
        const { serverId, title } = req.body;

        if (!serverId || !title) {
            return res.status(400).json({ status: 'failed', message: 'Server ID and room title are required' });
        }

        const isPermission = await Member.findOne({
            server: serverId,
            user: req.userId,
            role: { $in: ['OWNER', 'MODERATOR'] }
        });

        if (!isPermission) {
            return res.status(403).json({ status: 'failed', message: 'You do not have permission to edit this room' });
        }

        const last_room_order = await Room.countDocuments({ server: serverId });

        const room = await Room.create({
            server: serverId,
            title,
            order: last_room_order,
            createdBy: req.userId
        });

        res.status(201).json({ status: 'success', room });
    } catch (error) {
        console.error('Error creating room:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to create room' });
    }
});

// Edit room
app.patch('/api/v1/rooms/:roomId', auth, async (req, res) => {
    try {
        const { roomId } = req.params;
        const { title, order } = req.body;

        const room = await Room.findById(roomId);
        if (!room) {
            return res.status(404).json({ status: 'failed', message: 'Room not found' });
        }

        const isPermission = await Member.findOne({
            server: room.server,
            user: req.userId,
            role: { $in: ['OWNER', 'MODERATOR'] }
        });

        if (!isPermission) {
            return res.status(403).json({ status: 'failed', message: 'You do not have permission to edit this room' });
        }

        if (order !== undefined) {
            const old_index = room.order;
            const new_index = order;

            await Room.updateMany(
                { server: room.server, order: { $gt: old_index } },
                { $inc: { order: -1 } }
            );
            await Room.updateMany(
                { server: room.server, order: { $gte: new_index } },
                { $inc: { order: 1 } }
            );
            room.order = new_index;
        }

        if (title !== undefined) room.title = title;
        await room.save();

        res.json({ status: 'success', room });
    } catch (error) {
        console.error('Error updating room:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to update room' });
    }
});

// Delete room
app.delete('/api/v1/rooms/:roomId', auth, async (req, res) => {
    try {
        const { roomId } = req.params;

        const room = await Room.findById(roomId);
        if (!room) {
            return res.status(404).json({ status: 'failed', message: 'Room not found' });
        }

        const isPermission = await Member.findOne({
            server: room.server,
            user: req.userId,
            role: { $in: ['OWNER', 'MODERATOR'] }
        });

        if (!isPermission) {
            return res.status(403).json({ status: 'failed', message: 'You do not have permission to delete this room' });
        }

        const deletedRoomOrder = room.order;
        await Room.deleteOne({ _id: room._id });

        await Room.updateMany(
            { server: room.server, order: { $gt: deletedRoomOrder } },
            { $inc: { order: -1 } }
        );

        res.json({ status: 'success', message: 'Room deleted successfully' });
    } catch (error) {
        console.error('Error deleting room:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to delete room' });
    }
});

// ====================== Direct Messages =====================

// POST /api/v1/chats/:userId/messages
// Send a direct message to another user
app.post('/api/v1/chats/:userId/messages', auth, async (req, res) => {
    try {
        const otherUserId = req.params.userId;
        const currentUserId = req.userId;
        const { content, message_type = 'text', reply_to = null } = req.body;

        if (!content || !content.trim()) {
            return res.status(400).json({ status: 'failed', message: 'Message content cannot be empty' });
        }

        // Create DM message using USER IDS
        const message = await Message.create({
            sender: currentUserId,
            recipients: [otherUserId],
            context: otherUserId,
            context_type: 'User',
            content: content.trim(),
            message_type,
            reply_to: reply_to || undefined,
        });

        const populated = await Message.findById(message._id)
            .populate({
                path: 'sender',
                select: 'username display_name icon_file',
                populate: { path: 'icon_file' },
            })
            .populate({
                path: 'recipients',
                select: 'username display_name icon_file',
                populate: { path: 'icon_file' },
            })
            .populate({
                path: 'reply_to',
                populate: [
                    {
                        path: 'sender',
                        select: 'username display_name icon_file',
                        populate: { path: 'icon_file' },
                    },
                    {
                        path: 'recipients',
                        select: 'username display_name icon_file',
                        populate: { path: 'icon_file' },
                    }
                ]
            })
            .lean();

        res.json({ status: 'success', message: populated });
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: 'failed', message: 'Failed to send message' });
    }
});


// GET /api/v1/messages/:id/replies?page=1&limit=20&sort=asc|desc
// Get replies to a specific message
app.get('/api/v1/messages/:id/replies', auth, async (req, res) => {
    try {
        const parentId = req.params.id;
        const page = Math.max(parseInt(req.query.page || '1', 10), 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 100);
        const sortDir = req.query.sort === 'asc' ? 1 : -1;

        const me = req.userId;

        // Validate parent message
        const parent = await Message.findById(parentId)
            .populate({
                path: 'context',
                select: 'server',
            }).lean();
        if (!parent) return res.status(404).json({ status: 'failed', message: 'parent message not found' });

        // Fix: robust way to get context id whether populated or not
        const contextId = parent.context?._id || parent.context;

        if (parent.context_type === 'User') {
            // DM: participants = sender + context (both User IDs)
            const isParticipant =
                String(parent.sender) === String(me) ||
                String(contextId) === String(me);

            if (!isParticipant) {
                return res.status(403).json({ status: 'failed', message: 'forbidden: not in this DM' });
            }
        } else if (parent.context_type === 'Room') {
            // Room: context = Room; we populated server on it
            const serverId = parent.context?.server || null;
            if (!serverId) {
                return res.status(500).json({ status: 'failed', message: 'parent room missing server' });
            }

            const member = await Member.findOne({ user: me, server: serverId }).lean();
            if (!member) {
                return res.status(403).json({
                    status: 'failed',
                    message: 'forbidden: not a member of this room\'s server'
                });
            }
        }

        const replies = await Message.find({ reply_to: parentId })
            .sort({ created_at: sortDir })
            .skip((page - 1) * limit)
            .limit(limit)
            .populate({
                path: 'sender',
                select: 'username display_name icon_file',
                populate: { path: 'icon_file' }
            })
            .populate({ path: 'recipients',
                select: 'username display_name icon_file',
                populate: { path: 'icon_file' }
            })
            .lean();
        
        replies.forEach(r => populateFileBase64(r));

        const total = await Message.countDocuments({ reply_to: parentId });

        res.json({
            status: 'success',
            page,
            limit,
            total,
            has_more: page * limit < total,
            replies
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'failed', message: 'failed to fetch replies' });
    }
});

// ====================== Notifications ======================
// const notificationSchema = new Schema({
//     user: { type: ObjectId, ref: 'User', required: true },
//     type: { enum: ['MENTION', 'FRIEND_REQUEST'], type: String, required: true },
//     location: { type: ObjectId, ref: 'Message' },
//     from: { type: ObjectId, ref: 'User', required: true },
// });

app.get('/api/v1/notifications', auth, async (req, res) => {
    try {
        const notifications = await Notification.find({ user: req.userId })
            .populate({ path: "from", select: "username display_name icon_file", populate: { path: 'icon_file' } })
            .populate('location')
            .sort({ created_at: -1 })
            .lean();
        
        notifications.forEach(n => populateFileBase64(n));

        res.json({ status: 'success', notifications });
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to fetch notifications' });
    }
});

app.post('/api/v1/notification/respond', auth, async (req, res) => {
    try {
        const { notificationId, accept } = req.body;
        if (accept) {
            const result = await Notification.deleteOne({ _id: notificationId });
            if (result.deletedCount === 0) {
                return res.status(404).json({ status: 'failed', message: 'Notification not found' });
            }
            return res.json({ status: 'success', message: 'Notification accepted and deleted' });
        }
    } catch (error) {
        console.error('Error responding to notification:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to respond to notification' });
    }
});

// ====================== Friends ======================
// const notificationSchema = new Schema({
//     user: { type: ObjectId, ref: 'User', required: true },
//     type: { enum: ['MENTION', 'FRIEND_REQUEST'], type: String, required: true },
//     location: { type: ObjectId, ref: 'Message' },
//     from: { type: ObjectId, ref: 'User', required: true },
// });
app.post('/api/v1/friend/add', auth, async (req, res) => {
    try {
        const { toUsername } = req.body;

        // check if user exist
        const recipient = await User.findOne({ username: toUsername }).lean();
        if (!toUsername || !recipient) return res.status(404).json({ status: 'failed', message: 'User not found' });

        // Prevent sending a request to yourself
        if (recipient._id.toString() === req.userId.toString()) {
            return res.status(400).json({ status: 'failed', message: 'You cannot add yourself as a friend' });
        }

        // Prevent sending a request if already friends
        if (recipient.friends?.some(id => id.toString() === req.userId.toString())) {
            return res.status(400).json({ status: 'failed', message: 'User is already your friend' });
        }

        //P revent duplicate friend requests
        const friendRequest = await Notification.findOne({ user: recipient._id, type: 'FRIEND_REQUEST', from: req.userId });
        if (friendRequest) return res.status(200).json({ status: 'success', message: 'Friend request already sent' });


        const newFriendRequest = await Notification.create({ user: recipient._id, type: 'FRIEND_REQUEST', from: req.userId });
        res.status(201).json({ status: 'success', message: 'Friend request sent', data: newFriendRequest });

    } catch (error) {
        console.error('Error sending friend request:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to send friend request' });
    }
});

app.post('/api/v1/friend/respond', auth, async (req, res) => {
    try {
        const { notificationId, accept } = req.body;
        const notification = await Notification.findById(notificationId);
        if (!notification) return res.status(404).json({ status: 'failed', message: 'Notification not found' });

        if (notification.type === 'FRIEND_REQUEST' && String(notification.user) === String(req.userId)) {
            if (accept) {
                await User.updateOne(
                    { _id: req.userId },
                    { $addToSet: { friends: notification.from } }
                );
                await User.updateOne(
                    { _id: notification.from },
                    { $addToSet: { friends: req.userId } }
                );
                await Notification.deleteOne({ _id: notificationId });

                return res.json({ status: 'success', message: 'Friend request accepted' });

            } else {
                // Decline: just delete the notification
                await Notification.deleteOne({ _id: notificationId });
                return res.json({ status: 'success', message: 'Friend request declined' });
            }
        } else {
            return res.status(400).json({ status: 'failed', message: 'Invalid notification type or user' });
        }
    } catch (error) {
        console.error('Error accepting friend request:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to accept friend request' });
    }
});

app.post('/api/v1/friend/remove', auth, async (req, res) => {
    try {
        const { friendId } = req.body;
        const removedMe = await User.updateOne(
            { _id: req.userId },
            { $pull: { friends: friendId } }
        );
        const removeThem = await User.updateOne(
            { _id: friendId },
            { $pull: { friends: req.userId } }
        );

        if (removedMe.modifiedCount !== 1 && removeThem.modifiedCount !== 1) {
            return res.status(404).json({ status: 'failed', message: 'Friend not found in your friend list' });
        } else {
            return res.json({ status: 'success', message: 'Friend removed' });
        }
    } catch (error) {
        console.error('Error removing friend:', error);
        res.status(500).json({ status: 'failed', message: 'Failed to remove friend' });
    }
});

app.post('/api/v1/send-email/reset-password', async (req, res) => {
    try {
        const { destinationEmail, subject } = req.body
        // console.log(destinationEmail);
        if (!destinationEmail || destinationEmail.trim() === "") {
            return res.status(400).json({message: "Email is require"});
        }

        const user = await User.findOne({ email: destinationEmail });
        if (!user) return res.status(400).json({ message: "User not found" });

        const resetToken = crypto.randomBytes(32).toString("hex");
        const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 10 * 60 * 1000;

        await user.save();

        const resetURL = `${process.env.FRONTEND_ORIGIN}/reset-password/${resetToken}`;

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: 'phongsiraphat@gmail.com',
                pass: 'ozgc kqxc symd hblu'
            }
        });
        const mailOptions = {
            from: 'phongsiraphat@gmail.com',
            to: destinationEmail,
            subject,
            // text: "idiot!" 
            html: `<!doctype html>
                <html lang="en">

                <head>
                    <meta charset="utf-8" />
                    <meta name="viewport" content="width=device-width,initial-scale=1" />
                    <title>Password reset</title>
                    <style>
                        /* The container div */
                        .kusa-container {
                            padding-top: 1rem;
                            /* pt-4 */
                            padding-left: 1rem;
                            /* pl-4 */
                            margin-bottom: 1.5rem;
                            /* mb-6 */
                        }

                        /* The text div */
                        .kusa-text {
                            display: inline-block;

                            font-size: 3rem;
                            /* text-3xl */
                            line-height: 3rem;
                            /* text-3xl line-height */
                            font-weight: 700;
                            /* font-bold */

                            /* Gradient Background Logic */
                            /* Tailwind green-600 (#16a34a) to yellow-600 (#ca8a04) */
                            background-image: linear-gradient(to right, #16a34a, #6e9f29);

                            /* The magic that clips the background to the text */
                            -webkit-background-clip: text;
                            background-clip: text;

                            /* Makes the text transparent so the background shows through */
                            color: transparent;
                        }
                    </style>
                </head>

                <body style="margin:0;padding:0;background-color:#f4f6f8;font-family:Helvetica,Arial,sans-serif;color:#333333;">
                    <!-- Container -->
                    <table role="presentation" cellpadding="0" cellspacing="0" width="100%"
                        style="max-width:680px;margin:40px auto 40px auto;">
                        <tr>
                            <td align="center" style="padding:20px 16px;">
                                <!-- Card -->
                                <table role="presentation" cellpadding="0" cellspacing="0" width="100%"
                                    style="background:#ffffff;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,0.06);overflow:hidden;">
                                    <!-- Header / Brand -->
                                    <tr>
                                        <td style="padding:24px 28px 8px 28px;text-align:left;">
                                            <div class="kusa-container">
                                                <div class="kusa-text">
                                                    KUSA
                                                </div>
                                            </div>
                                        </td>
                                    </tr>

                                    <!-- Hero / Message -->
                                    <tr>
                                        <td style="padding:12px 28px 8px 28px;">
                                            <h1 style="margin:0 0 8px 0;font-size:20px;font-weight:600;color:#0f1724;">Reset your
                                                password</h1>
                                            <p style="margin:0;font-size:15px;line-height:1.5;color:#475569;">
                                                Hi ${user.username},<br>
                                                We received a request to reset the password for your KUSA account. Click the
                                                button below to choose a new password.
                                            </p>
                                        </td>
                                    </tr>

                                    <!-- CTA -->
                                    <tr>
                                        <td style="padding:18px 28px 18px 28px;">
                                            <table role="presentation" cellpadding="0" cellspacing="0">
                                                <tr>
                                                    <td>
                                                        <!-- Button uses a full absolute URL in production -->
                                                        <a href="${resetURL}" target="_blank" rel="noopener"
                                                            style="display:inline-block;padding:12px 20px;border-radius:8px;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:600;font-size:15px;">
                                                            Reset password
                                                        </a>
                                                    </td>
                                                </tr>
                                            </table>

                                            <p style="margin:14px 0 0 0;font-size:13px;color:#6b7280;line-height:1.45;">
                                                This link will expire in 10 minutes. If you didn't request a password
                                                reset, you can safely ignore this email or contact our support.
                                            </p>
                                        </td>
                                    </tr>

                                    <!-- Fallback link -->
                                    <tr>
                                        <td style="padding:0 28px 20px 28px;">
                                            <p style="margin:0;font-size:13px;color:#6b7280;">
                                                Can't click the button? Copy and paste this link into your browser:
                                            </p>
                                            <p style="word-break:break-all;margin:8px 0 0 0;font-size:13px;color:#0f1724;">
                                                <a href="${resetURL}" target="_blank" rel="noopener"
                                                    style="color:#2563eb;text-decoration:underline;">${resetURL}</a>
                                            </p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding:0 28px 20px 28px;">
                                            <p style="margin:0;font-size:13px;color:#6b7280;">
                                                If you're not the person who make this requested.
                                            </p>
                                            <p style="margin:0;font-size:13px;color:#6b7280;">
                                                We recommend that you manually change your password again at
                                                <a href="${process.env.FRONTEND_ORIGIN || 'http://localhost:3000/'}" target="_blank" rel="noopener"
                                                    style="color:#2563eb;text-decoration:underline;">
                                                    ${process.env.FRONTEND_ORIGIN || 'http://localhost:3000/'}
                                                </a>
                                            </p>
                                        </td>
                                    </tr>

                                    <!-- Footer -->
                                    <tr>
                                        <td style="padding:18px 28px 26px 28px;border-top:1px solid #f1f5f9;">
                                            <p style="margin:0;font-size:12px;color:#9aa4b2;line-height:1.4;">
                                                If you need help, reply to this email or contact <a href="mailto:phongsiraphat@gmail.com"
                                                    style="color:#2563eb;text-decoration:underline;">phongsiraphat@gmail.com</a>.<br>
                                                © 2025 KUSA. All rights reserved.
                                            </p>
                                        </td>
                                    </tr>
                                </table>
                                <!-- End card -->
                            </td>
                        </tr>
                    </table>

                    <!-- Plain signature-style footer (very small) -->
                    <div style="max-width:680px;margin:6px auto 20px auto;text-align:center;color:#98a2b3;font-size:12px;">
                        <p style="margin:0;">This email was sent to ${user.email} because a password reset was requested for your
                            account.</p>
                    </div>
                </body>

                </html>`
        };
        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.error(error);
            } else {
                // console.log('Email.sent: ' + info.response);
                return res.json({ status: 'success', message: 'Sending!' });
            }
        });
    } catch (error) {
        console.error("Error sending an email", error)
        res.status(500).json({message: "Internal server error"})
    }
})

// ====================== Files ======================

app.use("/storage", express.static(path.join(__dirname, "storage")));

app.post("/upload", upload.single("file"), async (req, res) => {
    try {
        const type = req.body.type;
        const id = req.body.id;

        const allowed = ["pfp", "banner", "server_icon", "attachment"];
        if (!allowed.includes(type)) {
            return res.status(400).json({ error: "Invalid upload type" });
        }
        if (!id || id.trim() === "") {
            return res.status(400).json({ error: "ID is required" });
        }

        const file = await uploadFile(req.file, type, id);

        res.json({
            message: `${type} uploaded successfully`,
            file
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ====================== Socket Logic ======================

io.on("connection", (socket) => {
    console.log("✅ New WebSocket connection:", socket.id);

    // Join room per user ID (from query or handshake)
    const userId = socket.handshake.query.userId;
    if (userId) socket.join(userId.toString());

    // Listen for "send_message" event from client
    socket.on("send_message", async (msgData) => {
        try {
            const { from_id, to_id, context_type, content, message_type = "text", reply_to = null } = msgData;

            if (!content || !content.trim()) return;

            let recipientUserIds = [];

            // =============== DIRECT MESSAGE ==================
            if (context_type === "User") {
                recipientUserIds = [to_id];
            }

            // =============== ROOM MESSAGE =====================
            else if (context_type === "Room") {
                const room = await Room.findById(to_id).lean();
                if (!room) return;

                const members = await Member.find({ server: room.server }).select("user");
                recipientUserIds = members.map(m => m.user.toString());
            }

            // Create DB message with **USER IDs** for recipients
            const message = await Message.create({
                sender: from_id,
                recipients: recipientUserIds,
                context: to_id,
                context_type,
                content: content.trim(),
                message_type,
                reply_to: reply_to || undefined,
            });

            const populatedMessage = await Message.findById(message._id)
                .populate({
                    path: "sender",
                    select: "username display_name icon_file",
                    populate: { path: "icon_file" }
                })
                .populate({
                    path: "recipients",
                    select: "username display_name icon_file",
                    populate: { path: "icon_file" }
                })
                .populate({
                    path: "reply_to",
                    populate: [
                        {
                            path: "sender",
                            select: "username display_name icon_file",
                            populate: { path: "icon_file" }
                        },
                        {
                            path: "recipients",
                            select: "username display_name icon_file",
                            populate: { path: "icon_file" }
                        }
                    ]
                })
                .lean();

            // =============== EMIT TO SENDER ==================
            io.to(from_id).emit("receive_message", populatedMessage);

            // =============== EMIT TO RECIPIENTS ==============
            recipientUserIds.forEach(uid => {
                if (uid !== from_id) {
                    io.to(uid).emit("receive_message", populatedMessage);
                }
            });

            // Mentions → create notifications
            const mentionRegex = /@([\w]+)/g;
            let match;
            const mentioned = new Set();

            while ((match = mentionRegex.exec(content)) !== null) {
                mentioned.add(match[1]);
            }

            for (const username of mentioned) {
                const target = await User.findOne({ username }).lean();
                if (target && String(target._id) !== String(from_id)) {
                    await Notification.create({
                        user: target._id,
                        type: "MENTION",
                        location: message._id,
                        from: from_id
                    });
                }
            }

        } catch (err) {
            console.error("Socket error:", err);
        }
    });

    socket.on("disconnect", () => {
        console.log("❌ WebSocket disconnected:", socket.id);
    });
});

mongoose.connection.on("connected", () => {
    console.log("MongoDB connected")
    db_status = true

    if (RESET_SEEDED_DATA === "true") {
        console.log("Resetting and seeding database structures...")
        mongoose.connection.db
            .dropDatabase()
            .then(() => {
                console.log("Database dropped")
                InitializeDatabaseStructures(RESET_SEEDED_DATA)
            })
            .catch((err) => console.error("Error dropping database:", err))
    } else {
        console.log("Skipping database seed/reset.")
    }
})

mongoose.connection.on('disconnected', () => {
    console.warn('MongoDB disconnected');
    db_status = false;
    setTimeout(connectWithRetry, 50000);
});

const connectWithRetry = async () => {
    console.log('Trying to connect to MongoDB...');
    try {
        await mongoose.connect(mongoURL);
    } catch (err) {
        console.error('MongoDB connection error. Retrying in 50s...', err.message);
        setTimeout(connectWithRetry, 50000);
    }
};

// Start the combined server (handles both HTTP + WS)
chat_server.listen(PORT, () => console.log(`🚀 Backend + WS running on port ${PORT}`));

// Initialize DB connection (with retry)
connectWithRetry();
