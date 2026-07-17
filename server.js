const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// dotenv শুধু লোকাল ডেভেলপমেন্টে ব্যবহার করো
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const app = express();

// --- CORS Config ---
const allowedOrigins = [
    process.env.FRONTEND_URL,   // তোমার লাইভ ফ্রন্টএন্ড ডোমেইন
    'http://localhost:3000',    // লোকাল ডেভেলপমেন্ট
    'http://127.0.0.1:5500'     // Live Server
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'CORS policy does not allow this origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true
}));

app.use(express.json());

// Railway health check endpoint. This intentionally does not depend on the
// database so Railway can verify that the HTTP process is running.
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET is not defined.");
    process.exit(1);
}

// --- PostgreSQL Connection Pool ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }, // Railway PG requires SSL
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// --- AUTH Middleware ---
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

// --- Signup ---
app.post('/api/auth/signup', async (req, res, next) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = await pool.query(
            'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
            [name, email.toLowerCase().trim(), hashedPassword, role || 'user']
        );
        res.status(201).json({ message: "User registered successfully", user: newUser.rows[0] });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: "Email already registered!" });
        }
        next(err);
    }
});

// --- Login ---
app.post('/api/auth/login', async (req, res, next) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
        if (result.rows.length === 0) return res.status(401).json({ message: "Invalid email or password!" });

        const user = result.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) return res.status(401).json({ message: "Invalid email or password!" });

        const token = jwt.sign(
            { id: user.id, role: user.role, name: user.name },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role, balance: user.balance }
        });
    } catch (err) {
        next(err);
    }
});

// --- Prediction API ---
app.post('/api/predict', authenticateToken, async (req, res, next) => {
    const { match_id, predicted_winner, bet_amount, predicted_score } = req.body;
    if (!match_id || !predicted_winner || !bet_amount || !predicted_score) {
        return res.status(400).json({ message: "Incomplete prediction details" });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const userRes = await client.query('SELECT balance FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
        const currentBalance = userRes.rows[0].balance;

        if (currentBalance < bet_amount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: "Insufficient balance!" });
        }

        const updatedUser = await client.query(
            'UPDATE users SET balance = balance - $1 WHERE id = $2 RETURNING balance',
            [bet_amount, req.user.id]
        );

        await client.query(
            'INSERT INTO predictions (user_id, match_id, predicted_winner, bet_amount, predicted_score) VALUES ($1, $2, $3, $4, $5)',
            [req.user.id, match_id, predicted_winner, bet_amount, predicted_score]
        );

        await client.query('COMMIT');
        res.json({ message: "Prediction submitted!", newBalance: updatedUser.rows[0].balance });
    } catch (err) {
        await client.query('ROLLBACK');
        next(err);
    } finally {
        client.release();
    }
});

// --- Leaderboard ---
app.get('/api/leaderboard', async (req, res, next) => {
    try {
        const result = await pool.query('SELECT name, balance FROM users ORDER BY balance DESC LIMIT 50');
        res.json(result.rows);
    } catch (err) {
        next(err);
    }
});

// --- Error Handling ---
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: "Something went wrong! Please try again later." });
});

// --- Graceful Shutdown ---
process.on('SIGTERM', () => {
    console.info('SIGTERM received. Closing server and DB pool.');
    pool.end(() => {
        console.log('Database pool closed.');
        process.exit(0);
    });
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
