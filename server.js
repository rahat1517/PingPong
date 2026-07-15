const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

// ১. প্রোডাকশন CORS কনফিগারেশন
const allowedOrigins = [
    process.env.FRONTEND_URL, // আপনার লাইভ ফ্রন্টএন্ড ডোমেইন (যেমন: https://my-league-app.vercel.app)
    'http://localhost:3000',  // লোকাল ডেভেলপমেন্টের সুবিধার জন্য রাখা হলো
    'http://127.0.0.1:5500'   // Live Server-এর জন্য
];

app.use(cors({
    origin: function (origin, callback) {
        // allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true
}));

app.use(express.json());
app.get('/', (req, res) => res.sendFile('index.html', { root: __dirname }));

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET is not defined.");
    process.exit(1);
}

// ২. অপ্টিমাইজড PostgreSQL কানেকশন পুল (Production Pool Config)
const dbConfig = {
    ...(process.env.DATABASE_URL
        ? { connectionString: process.env.DATABASE_URL }
        : {
            host: process.env.DB_HOST,
            port: Number(process.env.DB_PORT || 5432),
            user: process.env.DB_USER,
            password: String(process.env.DB_PASSWORD || ''),
            database: process.env.DB_DATABASE
        }),
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false, // ক্লাউড PG-এর জন্য SSL আবশ্যক
    max: 20, // সর্বোচ্চ ২০টি অ্যাক্টিভ কানেকশন থাকবে
    idleTimeoutMillis: 30000, // অলস কানেকশন ৩০ সেকেন্ড পর বন্ধ হবে
    connectionTimeoutMillis: 2000, // কানেক্ট হতে ২ সেকেন্ডের বেশি সময় লাগলে ফেইল মারবে
};

const pool = new Pool(dbConfig);

const MAIL_USER = process.env.MAIL_USER || 'gmrashidulislam003@gmail.com';
const MAIL_APP_PASSWORD = String(process.env.MAIL_APP_PASSWORD || '').replace(/\s/g, '');
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://127.0.0.1:5500';
const RESET_PAGE_URL = process.env.RESET_PAGE_URL || `${FRONTEND_URL.replace(/\/$/, '')}/index.html`;
const mailer = MAIL_APP_PASSWORD
    ? nodemailer.createTransport({
        service: 'gmail',
        auth: { user: MAIL_USER, pass: MAIL_APP_PASSWORD }
    })
    : null;
const mailCooldowns = new Map();

const tokenHash = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
const generateOtp = () => String(crypto.randomInt(100000, 1000000));
const validateStageScore = (stage, winner, teamA, teamB, score) => {
    const match = String(score || '').replace(/\s/g, '').match(/^(\d+)-(\d+)$/);
    if (!match) return 'Set score must use a format like 2-1 or 3-2.';
    const first = Number(match[1]);
    const second = Number(match[2]);
    const expectedTotal = stage === 'group_stage' ? 3 : 5;
    if (first + second !== expectedTotal) {
        return `${stage === 'group_stage' ? 'Group Stage' : 'Knockout Stage'} set scores must add up to ${expectedTotal}.`;
    }
    if ((winner === teamA && first <= second) || (winner === teamB && second <= first)) {
        return `The selected winner (${winner}) must have the higher set score.`;
    }
    return '';
};
const requireMailer = () => {
    if (!mailer) {
        const error = new Error('Email service is not configured. Add MAIL_APP_PASSWORD to .env.');
        error.statusCode = 503;
        throw error;
    }
};
const enforceMailCooldown = (key, seconds = 60) => {
    const now = Date.now();
    const nextAllowed = mailCooldowns.get(key) || 0;
    if (nextAllowed > now) {
        const error = new Error(`Please wait ${Math.ceil((nextAllowed - now) / 1000)} seconds before requesting another email.`);
        error.statusCode = 429;
        throw error;
    }
    mailCooldowns.set(key, now + seconds * 1000);
};
const sendOtpEmail = (to, name, otp) => mailer.sendMail({
    from: `"BracketX Security" <${MAIL_USER}>`,
    to,
    subject: 'Verify your BracketX account',
    text: `Hello ${name}, your BracketX verification code is ${otp}. It expires in 10 minutes.`,
    html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:28px;color:#0f172a"><h2 style="margin:0 0 8px">Verify your BracketX account</h2><p>Hello ${String(name).replace(/[<>&"]/g, '')},</p><p>Use this one-time verification code:</p><div style="margin:24px 0;padding:18px;border-radius:12px;background:#ecfdf5;color:#065f46;font-size:32px;font-weight:800;letter-spacing:10px;text-align:center">${otp}</div><p>This code expires in 10 minutes. If you did not create this account, ignore this email.</p></div>`
});
const sendResetEmail = (to, name, rawToken) => {
    const separator = RESET_PAGE_URL.includes('?') ? '&' : '?';
    const resetUrl = `${RESET_PAGE_URL}${separator}token=${encodeURIComponent(rawToken)}`;
    return mailer.sendMail({
        from: `"BracketX Security" <${MAIL_USER}>`,
        to,
        subject: 'Reset your BracketX password',
        text: `Hello ${name}, reset your password using this link (valid for 15 minutes): ${resetUrl}`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:28px;color:#0f172a"><h2>Reset your password</h2><p>Hello ${String(name).replace(/[<>&"]/g, '')},</p><p>This secure link expires in 15 minutes and can be used only once.</p><p style="margin:26px 0"><a href="${resetUrl}" style="padding:12px 18px;border-radius:9px;color:#fff;background:#059669;text-decoration:none;font-weight:700">Reset Password</a></p><p>If you did not request this change, you can safely ignore this email.</p></div>`
    });
};

pool.on('error', (err, client) => {
    console.error('Unexpected error on idle PostgreSQL client', err);
    process.exit(-1);
});

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Access Token Required" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Session expired, please login again" });
        req.user = user;
        next();
    });
};

// --- AUTH API ENDPOINTS ---

// ১. সাইন-আপ (Password Security Enabled)
app.post('/api/auth/signup', async (req, res, next) => {
    const { name, email, password, role } = req.body;
    const cleanEmail = String(email || '').toLowerCase().trim();
    if (!name?.trim() || !cleanEmail || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }
    if (String(password).length < 8) {
        return res.status(400).json({ error: 'Password must contain at least 8 characters.' });
    }
    const client = await pool.connect();
    try {
        requireMailer();
        enforceMailCooldown(`otp:${cleanEmail}`);
        const otp = generateOtp();
        const hashedPassword = await bcrypt.hash(password, 12);
        await client.query('BEGIN');
        const existing = await client.query('SELECT id, email_verified FROM users WHERE email = $1 FOR UPDATE', [cleanEmail]);
        if (existing.rowCount && existing.rows[0].email_verified) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Email already registered!' });
        }
        const newUser = await client.query(
            `INSERT INTO users
                (name, email, password, role, email_verified, approval_status, otp_hash, otp_expires_at)
             VALUES ($1, $2, $3, 'predictor', FALSE, 'pending_verification', $4, NOW() + INTERVAL '10 minutes')
             ON CONFLICT (email) DO UPDATE SET
                name = EXCLUDED.name, password = EXCLUDED.password, role = 'predictor',
                email_verified = FALSE, approval_status = 'pending_verification',
                otp_hash = EXCLUDED.otp_hash, otp_expires_at = EXCLUDED.otp_expires_at
             RETURNING id, name, email, role, approval_status`,
            [name.trim(), cleanEmail, hashedPassword, tokenHash(otp)]
        );
        await sendOtpEmail(cleanEmail, name.trim(), otp);
        await client.query('COMMIT');
        res.status(201).json({ message: 'Verification code sent to your email.', user: newUser.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        next(err);
    } finally {
        client.release();
    }
});

app.post('/api/auth/resend-otp', async (req, res, next) => {
    const email = String(req.body.email || '').toLowerCase().trim();
    try {
        requireMailer();
        enforceMailCooldown(`otp:${email}`);
        const userResult = await pool.query(
            'SELECT id, name, email_verified FROM users WHERE email = $1',
            [email]
        );
        if (!userResult.rowCount || userResult.rows[0].email_verified) {
            return res.json({ message: 'If verification is required, a new code has been sent.' });
        }
        const otp = generateOtp();
        await pool.query(
            `UPDATE users SET otp_hash = $1, otp_expires_at = NOW() + INTERVAL '10 minutes' WHERE id = $2`,
            [tokenHash(otp), userResult.rows[0].id]
        );
        await sendOtpEmail(email, userResult.rows[0].name, otp);
        res.json({ message: 'A new verification code has been sent.' });
    } catch (err) {
        next(err);
    }
});

app.post('/api/auth/verify-otp', async (req, res, next) => {
    const email = String(req.body.email || '').toLowerCase().trim();
    const otp = String(req.body.otp || '').trim();
    if (!/^\d{6}$/.test(otp)) return res.status(400).json({ message: 'Enter a valid 6-digit OTP.' });
    try {
        const result = await pool.query(
            `UPDATE users SET email_verified = TRUE, approval_status = 'pending',
                otp_hash = NULL, otp_expires_at = NULL
             WHERE email = $1 AND otp_hash = $2 AND otp_expires_at > NOW() AND email_verified = FALSE
             RETURNING id, name, email, role, approval_status`,
            [email, tokenHash(otp)]
        );
        if (!result.rowCount) return res.status(400).json({ message: 'The OTP is invalid or has expired.' });
        res.json({ message: 'Email verified. Your account is awaiting Admin Approval.', user: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

// ২. লগইন
app.post('/api/auth/login', async (req, res, next) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
        if (result.rows.length === 0) return res.status(401).json({ message: "Invalid email or password!" });

        const user = result.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) return res.status(401).json({ message: "Invalid email or password!" });
        if (!user.email_verified) return res.status(403).json({ message: 'Verify your email with the OTP before signing in.' });
        if (user.approval_status === 'pending') return res.status(403).json({ message: 'Your account is awaiting Admin Approval.' });
        if (user.approval_status === 'rejected') return res.status(403).json({ message: 'Your membership request was rejected.' });

        const token = jwt.sign(
            { id: user.id, role: user.role, name: user.name }, 
            JWT_SECRET, 
            { expiresIn: '24h' } // টোকেনের মেয়াদ ২৪ ঘণ্টা রাখা হলো নিরাপত্তার জন্য
        );

        res.json({ 
            token, 
            user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.approval_status }
        });
    } catch (err) {
        next(err);
    }
});

// --- USER PREDICTION API (With Strict Atomic Transaction) ---
app.post('/api/predict', authenticateToken, async (req, res, next) => {
    const { match_id, predicted_winner, bet_amount, predicted_score } = req.body;
    
    if (!match_id || !predicted_winner || !bet_amount || !predicted_score) {
        return res.status(400).json({ message: "Incomplete prediction details" });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // ১. লক দিয়ে ইউজারের ব্যালেন্স রিড করা (Concurrency safety-র জন্য FOR UPDATE ব্যবহার করা হয়েছে)
        const userRes = await client.query('SELECT balance FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
        const currentBalance = userRes.rows[0].balance;

        if (currentBalance < bet_amount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: "Insufficient balance!" });
        }

        // ২. ব্যালেন্স কাটা
        const updatedUser = await client.query(
            'UPDATE users SET balance = balance - $1 WHERE id = $2 RETURNING balance',
            [bet_amount, req.user.id]
        );

        // ৩. প্রেডিকশন ইনসার্ট করা
        await client.query(
            'INSERT INTO predictions (user_id, match_id, predicted_winner, bet_amount, predicted_score) VALUES ($1, $2, $3, $4, $5)',
            [req.user.id, match_id, predicted_winner, bet_amount, predicted_score]
        );

        await client.query('COMMIT');
        res.json({ message: "Prediction successfully submitted!", newBalance: updatedUser.rows[0].balance });
    } catch (err) {
        await client.query('ROLLBACK');
        next(err);
    } finally {
        client.release(); // কানেকশন পুলে ফেরত পাঠানো
    }
});

// --- ADMIN SETTLE MATCH API (Dynamic Pool Distribution) ---
app.post('/api/admin/settle-match', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin access only!" });

    const { match_id, actual_winner, actual_score } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // ১. ম্যাচ আপডেট
        await client.query(
            "UPDATE matches SET status = 'finished', actual_winner = $1, actual_score = $2 WHERE id = $3",
            [actual_winner, actual_score, match_id]
        );

        // ২. প্রেডিকশন রিড
        const predRes = await client.query('SELECT * FROM predictions WHERE match_id = $1 FOR UPDATE', [match_id]);
        const predictions = predRes.rows;

        let totalWinningBets = 0;
        let totalLosingPool = 0;

        predictions.forEach(p => {
            if (p.predicted_winner === actual_winner) totalWinningBets += p.bet_amount;
            else totalLosingPool += p.bet_amount;
        });

        // ৩. ক্যালকুলেশন ও ডিস্ট্রিবিউশন
        for (let p of predictions) {
            let payout = 0;
            let bonus = 0;
            let finalStatus = 'lost';

            if (p.predicted_winner === actual_winner) {
                finalStatus = 'won';
                let profitShare = totalWinningBets > 0 ? (p.bet_amount / totalWinningBets) * totalLosingPool : 0;
                payout = Math.round(p.bet_amount + profitShare);
            }

            if (p.predicted_score === actual_score) {
                bonus = 100; // এক্সাক্ট স্কোর বোনাস
            }

            if (payout > 0 || bonus > 0) {
                await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [payout + bonus, p.user_id]);
            }

            await client.query('UPDATE predictions SET status = $1 WHERE id = $2', [finalStatus, p.id]);
        }

        await client.query('COMMIT');
        res.json({ message: "Match settled and payouts disbursed successfully." });
    } catch (err) {
        await client.query('ROLLBACK');
        next(err);
    } finally {
        client.release();
    }
});

app.post('/api/auth/forgot-password', async (req, res, next) => {
    const email = String(req.body.email || '').toLowerCase().trim();
    const genericMessage = 'If this email exists, a password reset link has been sent.';
    try {
        requireMailer();
        enforceMailCooldown(`reset:${email}`);
        const result = await pool.query('SELECT id, name FROM users WHERE email = $1', [email]);
        if (result.rowCount) {
            const rawToken = crypto.randomBytes(32).toString('hex');
            await pool.query(
                `UPDATE users SET reset_token_hash = $1,
                    reset_token_expires_at = NOW() + INTERVAL '15 minutes' WHERE id = $2`,
                [tokenHash(rawToken), result.rows[0].id]
            );
            await sendResetEmail(email, result.rows[0].name, rawToken);
        }
        res.json({ message: genericMessage });
    } catch (err) {
        next(err);
    }
});

app.post('/api/auth/reset-password', async (req, res, next) => {
    const rawToken = String(req.body.token || '');
    const password = String(req.body.new_password || req.body.password || '');
    if (!rawToken || password.length < 8) {
        return res.status(400).json({ message: 'A valid reset token and an 8-character password are required.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 12);
        const result = await pool.query(
            `UPDATE users SET password = $1, reset_token_hash = NULL, reset_token_expires_at = NULL
             WHERE reset_token_hash = $2 AND reset_token_expires_at > NOW()
             RETURNING id`,
            [hashedPassword, tokenHash(rawToken)]
        );
        if (!result.rowCount) return res.status(400).json({ message: 'The reset link is invalid or has expired.' });
        res.json({ message: 'Password reset successfully. You can now sign in.' });
    } catch (err) {
        next(err);
    }
});

// --- ADMIN-PUBLISHED MATCH PREDICTION FLOW ---
// The admin is the only source of fixtures. Players can only predict matches
// returned by GET /api/matches while their status is "open".
app.get('/api/matches', authenticateToken, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT m.id, m.team_a, m.team_b, m.team_a_members, m.team_b_members,
                    m.status, m.actual_winner, m.actual_score,
                    COALESCE(m.stage, 'group_stage') AS stage,
                    p.predicted_winner AS user_prediction,
                    p.predicted_score AS user_predicted_score,
                    p.bet_amount AS user_bet_amount,
                    p.payout_profit AS user_payout_profit,
                    p.balance_change AS user_balance_change
             FROM matches m
             LEFT JOIN predictions p ON p.match_id = m.id AND p.user_id = $1
             ORDER BY m.id DESC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        next(err);
    }
});

app.post('/api/admin/create-match', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access only!' });
    const { team_a, team_b, team_a_members, team_b_members, stage } = req.body;
    const validStages = new Set(['group_stage', 'semi_final', 'third_place', 'final']);

    if (!team_a?.trim() || !team_b?.trim() || !validStages.has(stage)) {
        return res.status(400).json({ message: 'Valid stage and both team names are required.' });
    }
    if (team_a.trim().toLowerCase() === team_b.trim().toLowerCase()) {
        return res.status(400).json({ message: 'A team cannot play against itself.' });
    }
    const cleanMembers = (members) => Array.isArray(members)
        ? members.map((name) => String(name).trim()).filter(Boolean)
        : [];
    const membersA = cleanMembers(team_a_members);
    const membersB = cleanMembers(team_b_members);
    if (membersA.length !== 4 || membersB.length !== 4) {
        return res.status(400).json({ message: 'Each team must have exactly 4 member names.' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO matches (team_a, team_b, team_a_members, team_b_members, stage, status)
             VALUES ($1, $2, $3, $4, $5, 'open')
             RETURNING id, team_a, team_b, team_a_members, team_b_members, stage, status`,
            [team_a.trim(), team_b.trim(), JSON.stringify(membersA), JSON.stringify(membersB), stage]
        );
        res.status(201).json({ message: 'Match published for prediction.', match: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

app.put('/api/admin/matches/:id', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access only!' });
    const matchId = Number(req.params.id);
    const { team_a, team_b, team_a_members, team_b_members, stage } = req.body;
    const validStages = new Set(['group_stage', 'semi_final', 'third_place', 'final']);
    const cleanMembers = (members) => Array.isArray(members)
        ? members.map((name) => String(name).trim()).filter(Boolean)
        : [];
    const membersA = cleanMembers(team_a_members);
    const membersB = cleanMembers(team_b_members);

    if (!Number.isInteger(matchId) || !team_a?.trim() || !team_b?.trim() || !validStages.has(stage)) {
        return res.status(400).json({ message: 'Valid match, stage, and team names are required.' });
    }
    if (team_a.trim().toLowerCase() === team_b.trim().toLowerCase()) {
        return res.status(400).json({ message: 'A team cannot play against itself.' });
    }
    if (membersA.length !== 4 || membersB.length !== 4) {
        return res.status(400).json({ message: 'Each team must have exactly 4 member names.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const existing = await client.query('SELECT * FROM matches WHERE id = $1 FOR UPDATE', [matchId]);
        if (!existing.rowCount) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'Match not found.' });
        }
        if (existing.rows[0].status === 'finished') {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: 'A finished match cannot be edited.' });
        }
        const teamsChanged = existing.rows[0].team_a !== team_a.trim() || existing.rows[0].team_b !== team_b.trim();
        const result = await client.query(
            `UPDATE matches
             SET team_a = $1, team_b = $2, team_a_members = $3, team_b_members = $4, stage = $5
             WHERE id = $6
             RETURNING id, team_a, team_b, team_a_members, team_b_members, stage, status`,
            [team_a.trim(), team_b.trim(), JSON.stringify(membersA), JSON.stringify(membersB), stage, matchId]
        );
        if (teamsChanged) {
            await client.query('DELETE FROM predictions WHERE match_id = $1', [matchId]);
        }
        await client.query('COMMIT');
        res.json({
            message: teamsChanged
                ? 'Match updated. Previous predictions were cleared because the teams changed.'
                : 'Match updated successfully.',
            match: result.rows[0]
        });
    } catch (err) {
        await client.query('ROLLBACK');
        next(err);
    } finally {
        client.release();
    }
});

app.post('/api/predict-match', authenticateToken, async (req, res, next) => {
    const { match_id, predicted_winner, predicted_score, bet_amount } = req.body;
    const stake = bet_amount === '' || bet_amount === null || bet_amount === undefined ? 0 : Number(bet_amount);
    if (!Number.isInteger(stake) || stake < 0) {
        return res.status(400).json({ message: 'Bet amount is optional, but when provided it must be a non-negative whole number.' });
    }
    if (!/^\d+\s*-\s*\d+$/.test(String(predicted_score || ''))) {
        return res.status(400).json({ message: 'Predicted set score must use a format like 3-1.' });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const matchResult = await client.query(
            `SELECT id, team_a, team_b, status, COALESCE(stage, 'group_stage') AS stage
             FROM matches WHERE id = $1 FOR UPDATE`,
            [match_id]
        );
        if (!matchResult.rowCount) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'This match no longer exists.' });
        }
        const match = matchResult.rows[0];
        if (match.status !== 'open') {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: 'Predictions for this match are locked.' });
        }
        if (![match.team_a, match.team_b].includes(predicted_winner)) {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: 'Select one of the teams published by the admin.' });
        }
        const scoreError = validateStageScore(
            match.stage, predicted_winner, match.team_a, match.team_b, predicted_score
        );
        if (scoreError) {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: scoreError });
        }

        const duplicate = await client.query(
            'SELECT id FROM predictions WHERE user_id = $1 AND match_id = $2',
            [req.user.id, match.id]
        );
        if (duplicate.rowCount) {
            await client.query('ROLLBACK');
            return res.status(409).json({ message: 'You have already placed a bet on this match.' });
        }
        await client.query(
            `INSERT INTO predictions
                (user_id, match_id, predicted_winner, bet_amount, predicted_score, status)
             VALUES ($1, $2, $3, $4, $5, 'pending')`,
            [req.user.id, match.id, predicted_winner, stake, String(predicted_score).replace(/\s/g, '')]
        );
        await client.query('COMMIT');
        res.status(201).json({ message: 'Team and set predictions locked successfully.' });
    } catch (err) {
        await client.query('ROLLBACK');
        next(err);
    } finally {
        client.release();
    }
});

app.post('/api/admin/update-match-result', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access only!' });
    const { match_id, official_winner, actual_score } = req.body;
    if (!/^\d+\s*-\s*\d+$/.test(String(actual_score || ''))) {
        return res.status(400).json({ message: 'Actual set score must use a format like 3-1.' });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const matchResult = await client.query(
            `SELECT id, team_a, team_b, status FROM matches WHERE id = $1 FOR UPDATE`,
            [match_id]
        );
        if (!matchResult.rowCount) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'Match not found.' });
        }
        const match = matchResult.rows[0];
        if (match.status === 'finished') {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: 'This match has already been settled.' });
        }
        if (![match.team_a, match.team_b].includes(official_winner)) {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: 'Winner must be one of the scheduled teams.' });
        }
        const cleanScore = String(actual_score).replace(/\s/g, '');
        await client.query(
            `UPDATE matches SET status = 'finished', actual_winner = $1, actual_score = $2 WHERE id = $3`,
            [official_winner, cleanScore, match.id]
        );
        const predictionResult = await client.query(
            'SELECT * FROM predictions WHERE match_id = $1 FOR UPDATE', [match.id]
        );
        const predictions = predictionResult.rows;
        const winners = predictions.filter((prediction) => prediction.predicted_winner === official_winner);
        const winningPool = winners.reduce(
            (sum, prediction) => sum + Number(prediction.bet_amount), 0
        );
        const losingPool = predictions
            .filter((prediction) => prediction.predicted_winner !== official_winner)
            .reduce((sum, prediction) => sum + Number(prediction.bet_amount), 0);

        // Allocate every whole unit of the losing pool exactly once. Each paid
        // winner receives a share based on their stake in the winning pool.
        // Largest-remainder allocation prevents rounding from creating or losing money.
        const profitByPrediction = new Map();
        const paidWinners = winners.filter((prediction) => Number(prediction.bet_amount) > 0);
        if (winningPool > 0 && losingPool > 0) {
            const shares = paidWinners.map((prediction) => {
                const exact = Number(prediction.bet_amount) / winningPool * losingPool;
                return { prediction, profit: Math.floor(exact), remainder: exact - Math.floor(exact) };
            });
            let undistributed = losingPool - shares.reduce((sum, share) => sum + share.profit, 0);
            shares.sort((a, b) => b.remainder - a.remainder || Number(a.prediction.id) - Number(b.prediction.id));
            for (let index = 0; index < undistributed; index += 1) {
                shares[index % shares.length].profit += 1;
            }
            shares.forEach((share) => profitByPrediction.set(share.prediction.id, share.profit));
        }

        for (const prediction of predictions) {
            const won = prediction.predicted_winner === official_winner;
            const proportionalProfit = won ? (profitByPrediction.get(prediction.id) || 0) : 0;
            // If nobody backed the official winner with money, there is no valid
            // winning pool, so monetary stakes are refunded (prediction status still settles).
            const balanceChange = won ? proportionalProfit : (winningPool > 0 ? -Number(prediction.bet_amount) : 0);
            await client.query(
                'UPDATE users SET balance = balance + $1 WHERE id = $2',
                [balanceChange, prediction.user_id]
            );
            await client.query(
                `UPDATE predictions SET status = $1, payout_profit = $2, balance_change = $3 WHERE id = $4`,
                [won ? 'won' : 'lost', proportionalProfit, balanceChange, prediction.id]
            );
        }
        await client.query('COMMIT');
        res.json({
            message: 'Result updated and betting pool distributed.',
            settlement: {
                winning_pool: winningPool,
                losing_pool: losingPool,
                distributed_profit: winningPool > 0 ? losingPool : 0,
                refunded: winningPool > 0 ? 0 : losingPool
            }
        });
    } catch (err) {
        await client.query('ROLLBACK');
        next(err);
    } finally {
        client.release();
    }
});

app.get('/api/predictions/stats', authenticateToken, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT COUNT(*)::int AS total_predictions,
                    COUNT(*) FILTER (WHERE status = 'won')::int AS wins,
                    COUNT(*) FILTER (WHERE status = 'lost')::int AS losses,
                    COALESCE(ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'won') /
                        NULLIF(COUNT(*) FILTER (WHERE status IN ('won', 'lost')), 0), 1), 0) AS win_rate
             FROM predictions WHERE user_id = $1`,
            [req.user.id]
        );
        const user = await pool.query('SELECT balance FROM users WHERE id = $1', [req.user.id]);
        res.json({ ...result.rows[0], balance: user.rows[0]?.balance ?? 0 });
    } catch (err) {
        next(err);
    }
});

// --- LEADERBOARD ---
app.get('/api/leaderboard', async (req, res, next) => {
    try {
        const teamResult = await pool.query(
            `SELECT u.name,
                    COUNT(p.id) FILTER (WHERE p.status = 'won')::int AS wins,
                    COALESCE(ROUND(100.0 * COUNT(p.id) FILTER (WHERE p.status = 'won') /
                        NULLIF(COUNT(p.id) FILTER (WHERE p.status IN ('won', 'lost')), 0), 1), 0) AS win_rate
             FROM users u
             LEFT JOIN predictions p ON p.user_id = u.id
             GROUP BY u.id, u.name
             ORDER BY wins DESC, win_rate DESC, u.name ASC
             LIMIT 50`
        );
        const setResult = await pool.query(
            `SELECT u.name,
                    COUNT(p.id) FILTER (
                        WHERE m.status = 'finished' AND p.predicted_score = m.actual_score
                    )::int AS exact_sets,
                    COUNT(p.id) FILTER (WHERE m.status = 'finished')::int AS settled_predictions,
                    COALESCE(ROUND(100.0 * COUNT(p.id) FILTER (
                        WHERE m.status = 'finished' AND p.predicted_score = m.actual_score
                    ) / NULLIF(COUNT(p.id) FILTER (WHERE m.status = 'finished'), 0), 1), 0) AS accuracy
             FROM users u
             LEFT JOIN predictions p ON p.user_id = u.id
             LEFT JOIN matches m ON m.id = p.match_id
             GROUP BY u.id, u.name
             ORDER BY exact_sets DESC, accuracy DESC, u.name ASC
             LIMIT 50`
        );
        res.json({
            teamLeaderboard: teamResult.rows,
            setLeaderboard: setResult.rows
        });
    } catch (err) {
        next(err);
    }
});

// ৪. গ্লোবাল এরর হ্যান্ডলিং মিডলওয়্যার (Internal Error Information Protection)
app.get('/api/admin/pending-users', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access only!' });
    try {
        const result = await pool.query(
            `SELECT id, name, email, role, created_at, approval_status
             FROM users WHERE email_verified = TRUE AND approval_status = 'pending'
             ORDER BY created_at ASC`
        );
        res.json({ users: result.rows });
    } catch (err) {
        next(err);
    }
});

app.post('/api/admin/approve-user', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access only!' });
    try {
        const result = await pool.query(
            `UPDATE users SET approval_status = 'approved'
             WHERE id = $1 AND email_verified = TRUE AND approval_status = 'pending'
             RETURNING id, name, email, role, approval_status`,
            [Number(req.body.user_id)]
        );
        if (!result.rowCount) return res.status(404).json({ message: 'Pending member request not found.' });
        res.json({ message: 'Member approved successfully.', user: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

app.post('/api/admin/reject-user', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access only!' });
    try {
        const result = await pool.query(
            `UPDATE users SET approval_status = 'rejected'
             WHERE id = $1 AND email_verified = TRUE AND approval_status = 'pending'
             RETURNING id, name, email, role, approval_status`,
            [Number(req.body.user_id)]
        );
        if (!result.rowCount) return res.status(404).json({ message: 'Pending member request not found.' });
        res.json({ message: 'Member request rejected.', user: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

app.use((err, req, res, next) => {
    console.error(err.stack); // সার্ভার লগে ডিটেইলস দেখাবে
    const status = Number(err.statusCode) || 500;
    res.status(status).json({ error: status === 500 ? "Something went wrong! Please try again later." : err.message });
});

// ৫. গ্রেসফুল শাটডাউন (Graceful Shutdown)
process.on('SIGTERM', () => {
    console.info('SIGTERM signal received. Closing HTTP server and DB Pool gracefully.');
    pool.end(() => {
        console.log('Database pool has ended.');
        process.exit(0);
    });
});

const PORT = process.env.PORT || 5000;
async function startServer() {
    // Backward-compatible migration for databases created by the earlier match schema.
    await pool.query("ALTER TABLE matches ADD COLUMN IF NOT EXISTS stage VARCHAR(30) NOT NULL DEFAULT 'group_stage'");
    await pool.query("ALTER TABLE matches ADD COLUMN IF NOT EXISTS team_a_members JSONB NOT NULL DEFAULT '[]'::jsonb");
    await pool.query("ALTER TABLE matches ADD COLUMN IF NOT EXISTS team_b_members JSONB NOT NULL DEFAULT '[]'::jsonb");
    await pool.query('ALTER TABLE users ALTER COLUMN balance SET DEFAULT 0');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE');
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status VARCHAR(30) NOT NULL DEFAULT 'approved'");
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_hash TEXT');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_expires_at TIMESTAMPTZ');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires_at TIMESTAMPTZ');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()');
    await pool.query('ALTER TABLE predictions ADD COLUMN IF NOT EXISTS payout_profit INTEGER NOT NULL DEFAULT 0');
    await pool.query('ALTER TABLE predictions ADD COLUMN IF NOT EXISTS balance_change INTEGER NOT NULL DEFAULT 0');
    // Existing accounts with no completed prediction still belong to the initial state.
    await pool.query(`UPDATE users u SET balance = 0
        WHERE NOT EXISTS (
            SELECT 1 FROM predictions p
            WHERE p.user_id = u.id AND p.status IN ('won', 'lost')
        )`);
    if (mailer) {
        mailer.verify()
            .then(() => console.log(`Gmail SMTP ready: ${MAIL_USER}`))
            .catch((error) => console.error(`Gmail SMTP verification failed: ${error.message}`));
    } else {
        console.warn('Email disabled: add MAIL_APP_PASSWORD to .env to enable OTP and password reset mail.');
    }
    app.listen(PORT, () => console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`));
}

startServer().catch((err) => {
    console.error('Failed to initialize the application:', err);
    process.exit(1);
});
