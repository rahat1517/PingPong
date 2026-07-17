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
const productionOrigin = String(process.env.FRONTEND_URL || '').replace(/\/$/, '');
const isProduction = process.env.NODE_ENV === 'production';
const isLocalDevelopmentOrigin = (origin) => {
    try {
        const url = new URL(origin);
        return url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname);
    } catch {
        return false;
    }
};

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        const normalizedOrigin = origin.replace(/\/$/, '');
        const allowed = normalizedOrigin === productionOrigin
            || (!isProduction && isLocalDevelopmentOrigin(normalizedOrigin));
        if (!allowed) {
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
    console.log('Server healthy');
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
    const matchId = Number(match_id);
    const stake = Number(bet_amount);
    if (!Number.isInteger(matchId) || matchId < 1 || !predicted_winner || !predicted_score) {
        return res.status(400).json({ message: "Incomplete prediction details" });
    }
    if (!Number.isInteger(stake) || stake <= 0) {
        return res.status(400).json({ message: "Bet amount must be a positive whole number." });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const userRes = await client.query('SELECT balance FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
        if (!userRes.rowCount) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: "User not found." });
        }
        const currentBalance = Number(userRes.rows[0].balance);

        if (currentBalance < stake) {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: "Insufficient balance!" });
        }

        const updatedUser = await client.query(
            'UPDATE users SET balance = balance - $1 WHERE id = $2 RETURNING balance',
            [stake, req.user.id]
        );

        await client.query(
            'INSERT INTO predictions (user_id, match_id, predicted_winner, bet_amount, predicted_score) VALUES ($1, $2, $3, $4, $5)',
            [req.user.id, matchId, String(predicted_winner).trim(), stake, String(predicted_score).trim()]
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

// --- Admin Match Settlement ---
app.post('/api/admin/settle-match', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access only!" });
    }

    const matchId = Number(req.body.match_id);
    const actualWinner = String(req.body.actual_winner || req.body.official_winner || '').trim();
    const actualScore = String(req.body.actual_score || '').trim();
    if (!Number.isInteger(matchId) || matchId < 1 || !actualWinner || !actualScore) {
        return res.status(400).json({ message: "Match, winner, and actual score are required." });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const matchResult = await client.query(
            'SELECT id, team_a, team_b, status FROM matches WHERE id = $1 FOR UPDATE',
            [matchId]
        );
        if (!matchResult.rowCount) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: "Match not found." });
        }

        const match = matchResult.rows[0];
        if (match.status === 'finished') {
            await client.query('ROLLBACK');
            return res.status(409).json({ message: "This match has already been settled." });
        }
        if (![match.team_a, match.team_b].includes(actualWinner)) {
            await client.query('ROLLBACK');
            return res.status(400).json({ message: "Winner must be one of the match teams." });
        }

        const predictionResult = await client.query(
            'SELECT id, user_id, predicted_winner, bet_amount FROM predictions WHERE match_id = $1 FOR UPDATE',
            [matchId]
        );
        const predictions = predictionResult.rows;
        const winners = predictions.filter((prediction) => prediction.predicted_winner === actualWinner);
        const winningPool = winners.reduce((sum, prediction) => sum + Number(prediction.bet_amount), 0);
        const losingPool = predictions
            .filter((prediction) => prediction.predicted_winner !== actualWinner)
            .reduce((sum, prediction) => sum + Number(prediction.bet_amount), 0);

        const profitByPrediction = new Map();
        if (winningPool > 0 && losingPool > 0) {
            const shares = winners.map((prediction) => {
                const exactProfit = Number(prediction.bet_amount) / winningPool * losingPool;
                return {
                    prediction,
                    profit: Math.floor(exactProfit),
                    remainder: exactProfit - Math.floor(exactProfit)
                };
            });
            let undistributed = losingPool - shares.reduce((sum, share) => sum + share.profit, 0);
            shares.sort((a, b) => b.remainder - a.remainder || Number(a.prediction.id) - Number(b.prediction.id));
            for (let index = 0; index < undistributed; index += 1) {
                shares[index % shares.length].profit += 1;
            }
            shares.forEach((share) => profitByPrediction.set(share.prediction.id, share.profit));
        }

        for (const prediction of predictions) {
            const won = prediction.predicted_winner === actualWinner;
            // Stakes were deducted when predictions were placed. Winners receive
            // their stake back plus profit. If nobody won, every stake is refunded.
            const payout = winningPool === 0
                ? Number(prediction.bet_amount)
                : won
                    ? Number(prediction.bet_amount) + (profitByPrediction.get(prediction.id) || 0)
                    : 0;
            if (payout > 0) {
                await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [payout, prediction.user_id]);
            }
            await client.query(
                'UPDATE predictions SET status = $1 WHERE id = $2',
                [won ? 'won' : 'lost', prediction.id]
            );
        }

        await client.query(
            `UPDATE matches SET status = 'finished', actual_winner = $1, actual_score = $2 WHERE id = $3`,
            [actualWinner, actualScore, matchId]
        );
        await client.query('COMMIT');

        res.json({
            message: "Match settled and payouts distributed.",
            settlement: {
                predictions: predictions.length,
                winners: winners.length,
                winning_pool: winningPool,
                losing_pool: losingPool,
                refunded: winningPool === 0
            }
        });
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
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
