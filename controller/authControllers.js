const pool = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const register = async (req, res) => {
    const { fullname, username, passwordx } = req.body;

    try {
        const hashedPasswordx = await bcrypt.hash(passwordx, 10);
        await pool.query('INSERT INTO users (fullname, username, passwordx) VALUES (?, ?, ?)', [fullname, username, hashedPasswordx]);

        res.status(201).json({ message: 'User registered' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

const login = async (req, res) => {
    const { username, passwordx } = req.body;

    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.status(400).json({ error: 'Invalid username' });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(passwordx, user.passwordx);

        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        const token = jwt.sign(
            { user_id: user.user_id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_ACCESS_EXPIRATION_TIME } 
        );

        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};


module.exports = { register, login };
