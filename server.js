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
        origin: ["http://localhost:3000", "http://192.168.0.120:3000", "https://msg-min.xyz"]
    }
});

app.use(cors())
app.use(json())

const JWT_SECRET = process.env.JWT_SECRET || 'defaultsecret';

const initConnection = createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: 'root',
  password: 'root',
  multipleStatements: true
});

initConnection.query(`CREATE DATABASE IF NOT EXISTS min;
USE min;
CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(64), email VARCHAR(64), password VARCHAR(64));
CREATE TABLE IF NOT EXISTS chats (id INT AUTO_INCREMENT PRIMARY KEY, type ENUM('private', 'group') NOT NULL, name VARCHAR(64));
INSERT IGNORE INTO chats (id, type, name) VALUES (1, 'group', 'Default Chat');
CREATE TABLE IF NOT EXISTS chat_users (
    chat_id INT, 
    user_id INT, 
    PRIMARY KEY (chat_id, user_id),
    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    chat_id INT NOT NULL,
    sender_id INT NOT NULL,
    content TEXT NOT NULL,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);
`, (error, res) => {
    initConnection.end();
});

const connection = createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: 'root',
  password: 'root',
  database: 'min',
  multipleStatements: false
});

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
            const token = jwt.sign({ name: username, email: email }, JWT_SECRET, { expiresIn: '7d' });
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
            return res.status(500).json({ msg: 'MySQL error'});
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
            const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
            return res.json({ token: token, username: user.name });
        })
    })
});

// Verify token
app.post('/verify', (req, res) => {
    const token = req.body.token;
    if (!token) {
        return res.status(400).json({ msg: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return res.json({ valid: true, user: decoded });
    }
    catch (err) {
        return res.status(400).json({ valid: false, msg: 'Invalid token' });
    }
})

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
    socket.on('msg', (data) => {
        if (!data || !data.text || !data.chat) {
            socket.emit('error', { msg: 'Message is empty or some required arguments are missing' });
        }
        const to_send = {
            text: data.text,
            author: socket.user.name
        }
        io.emit('message', to_send);
        connection.query('INSERT INTO messages (chat_id, sender_id, content) VALUES (?, ?, ?)', [1, socket.user.id, data.text], (error, results) => {
            if (error) {
                socket.emit('error', { msg: 'MySQL error happened while trying to save your message.' });
            }
        });
    });

    socket.on('getChatHistory', (data) => {
        if (!data || !data.chat) {
            socket.emit('error', { msg: 'Chat ID is required to get chat history' });
            return;
        }
        connection.query(`SELECT
            messages.id,
            messages.content,
            messages.sent_at,
            users.name AS sender_name
            FROM messages
            JOIN users ON messages.sender_id = users.id
            WHERE messages.chat_id = ?
            ORDER BY messages.sent_at ASC
            LIMIT 100 OFFSET 0;`, 
        [data.chat], (error, results) => {
            if (error) {
                socket.emit('error', { msg: 'MySQL error while fetching chat history' });
                return;
            }
            const messages = results.map(msg => ({
                id: msg.id,
                chat_id: msg.chat_id,
                author: msg.sender_name,
                text: msg.content,
                sent_at: msg.sent_at
            }));
            socket.emit('history', { chat: data.chat, messages: messages });
        });
    });

    socket.on('getName', data => {
        try {
            socket.emit('username', socket.user.name);
        } catch (error) {
            socket.emit('error', { msg: 'Error getting username' });
        }
    });
});

const PORT = process.env.PORT || 5000;
server.listen({ port: PORT, hostname: '0.0.0.0' }, () => {
    console.log(`Server is running on ${PORT} port!`);
});