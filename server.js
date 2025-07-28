import { createConnection } from 'mysql2';
import express, { json } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
dotenv.config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: ["http://localhost:3000", "https://msg-min.xyz"]
    }
});

app.use(cors())
app.use(json())

const JWT_SECRET = process.env.JWT_SECRET || 'defaultsecret';

const connection = createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: 'root',
  password: 'root'
});

connection.query('CREATE DATABASE IF NOT EXISTS min')
connection.query('USE min')
connection.query('CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(64), email VARCHAR(64), password VARCHAR(64))')

// Signing up
app.post('/register', async (req, res) => {
    const { email, username, password } = req.body;
    connection.query('SELECT * FROM users WHERE name = ? OR email = ?', [username, email], (error, results) => {
        if (error) {
            return res.status(500).json({ msg: 'MySQL error' });
        }
        if (results.length > 0) {
            return res.status(400).json({ msg: 'User with such username or email exists' })
        }
        if (password.length < 6) {
            return res.status(400).json({ msg: 'Password must be at least 6 characters long!' });
        }
        bcrypt.hash(password, 10, async (error, hash) => {
            if (error) {
                return res.status(400).json({ msg: 'Error hashing password!' });
            }
            connection.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [username, email, hash])
            const token = jwt.sign({ name: username, email: email }, JWT_SECRET, { expiresIn: '1h' });
            if (!token) {
                return res.status(500).json({ msg: 'Error generating token' });
            }
            return res.json({ token: token });
        });
    });
});

// Singing in
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    connection.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
        if (error) {
            return res.status(500).json({ msg: 'MySQL error' });
        }
        if (results.length === 0) {
            return res.status(400).json({ msg: 'User with such email does not exist' });
        }
        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).json({ msg: 'Error comparing password' });
            }
            if (!isMatch) {
                return res.status(400).json({ msg: 'Incorrect password' });
            }
            const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
            return res.json({ token: token });
        })
    })
});

io.use((socket, next) => {
    const token = socket.handshake.auth.token;

    if (!token) {
        return next(new Error("No token provided (╯°□°）╯︵ ┻━┻"));
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.user = decoded;
        next();
    } catch (err) {
        next(new Error("Invalid token (╯°□°）╯︵ ┻━┻"));
    }
});

io.on('connection', (socket) => {
    console.log(`User ${socket.id} connected!`)

    socket.on('msg', (data) => {
        io.emit('message', data);
    });

    socket.on('reg', (data) => {
        if (!data.username || !data.email || !data.password) {
            socket.emit('error', { msg: 'All fields are required!' });
            return;
        }
        if (data.password.length < 6) {
            socket.emit('error', { msg: 'Password must be at least 6 characters long!' });
            return;
        }
        bcrypt.hash(data.password, 10, async (error, hash) => {
            if (error) {
                socket.emit('error', { msg: 'Error hashing password!' });
                return;
            }
            data.password = hash;
            connection.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [data.username, data.email, data.password])
            socket.emit('success', { msg: 'Registration successful!' });
        });
    });

    socket.on('disconnect', () => {
        console.log(`User ${socket.id} disconnected!`);
    });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`Server is running on ${PORT} port!`);
});