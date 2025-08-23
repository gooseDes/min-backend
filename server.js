import { createConnection } from 'mysql2';
import express, { json } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import sharp from 'sharp';
dotenv.config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: ["http://localhost:3000", "http://192.168.0.120:3000", "https://msg-min.xyz"],
        credentials: true
    }
});

app.use(cors())
app.use(json())
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Creating folder for uploads and avatars
const uploadsDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
const avatarsDir = path.join(uploadsDir, "avatars");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir);

const upload = multer({ dest: "temp/", limits: { fileSize: 5 * 1024 * 1024 } });

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

// Some function lol :3
function authMiddleware(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "No token" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Invalid token" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid Token" });
    }
}

// Route for loading avatars
app.post("/upload-avatar", authMiddleware, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "File is not loaded" });

    const userId = req.userId;
    const outPath = path.join(avatarsDir, `${userId}.webp`);

    await sharp(req.file.path)
      .resize(512, 512, { fit: "cover" })
      .toFormat("webp", { quality: 80 })
      .toFile(outPath);

    fs.unlinkSync(req.file.path);

    res.json({ url: `/avatars/${userId}.webp` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error loading" });
  }
});


// Hosting avatars
app.use("/avatars", express.static(avatarsDir));

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
            connection.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [username, email, hash], (error, result) => {
                const token = jwt.sign({ id: result.insertId, name: username, email: email }, JWT_SECRET, { expiresIn: '7d' });
                return res.json({ id: result.insertId, token: token });
            });
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
            if (!token) {
                return res.status(500).json({ msg: 'Error generating token' });
            }
            return res.json({ token: token, username: user.name, id: user.id });
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
        connection.query('INSERT INTO messages (chat_id, sender_id, content) VALUES (?, ?, ?)', [data.chat, socket.user.id, data.text], (error, results) => {
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

    socket.on('createChat', data => {
        try {
            if (!data || !data.nickname) {
                socket.emit('createChatResult', { success: false, msg: 'Nickname is required' });
                return;
            }
            connection.query('SELECT id FROM users WHERE name = ?', [data.nickname], (error, result) => {
                if (error) {
                    socket.emit('createChatResult', { success: false, msg: 'No such user' });
                    return;
                }
                if (result.length === 0) {
                    socket.emit('createChatResult', { success: false, msg: 'No such user' });
                    return;
                }
                const userId = result[0].id;
                const chatUsers = [socket.user.id, userId];
                const chatName = chatUsers.sort().join('-');
                connection.query('SELECT id FROM chats WHERE name = ?', [chatName], (error, results) => {
                    if (error) {
                        socket.emit('createChatResult', { success: false, msg: 'MySQL error while checking chat existence' });
                        return;
                    }
                    if (results.length > 0) {
                        socket.emit('createChatResult', { success: false, msg: 'Chat already exists' });
                        return;
                    }
                    connection.query('INSERT INTO chats (type, name) VALUES (?, ?)', ['private', chatName], (error, results) => {
                        if (error) {
                            socket.emit('createChatResult', { success: false, msg: 'MySQL error while creating chat' });
                            return;
                        }
                        for (let id of chatUsers) {
                            connection.query('INSERT INTO chat_users (chat_id, user_id) VALUES (?, ?)', [results.insertId, id], (error, results) => {
                                if (error) {
                                    socket.emit('createChatResult', { success: false, msg: 'MySQL error while adding users to chat' });
                                    return;
                                }
                            });
                        }
                        socket.emit('createChatResult', { success: true, chatId: results.insertId, chatName: chatName, users: chatUsers });
                    });
                });
            });
        } catch (error) {
            socket.emit('createChatResult', { success: false, msg: 'Error creating chat' });
        }
    });

    socket.on('getChats', data => {
        try {
            connection.query(`SELECT 
                                chats.id,
                                chats.type,
                                CASE 
                                    WHEN chats.type = 'private' THEN (
                                        SELECT u.name 
                                        FROM chat_users cu
                                        JOIN users u ON cu.user_id = u.id
                                        WHERE cu.chat_id = chats.id AND cu.user_id != ?
                                        LIMIT 1
                                    )
                                    ELSE chats.name
                                END AS name
                            FROM chats
                            WHERE chats.id IN (
                                SELECT chat_id FROM chat_users WHERE user_id = ?
                            )`, [socket.user.id, socket.user.id], (error, results) => {
                if (error) {
                    socket.emit('error', { msg: 'MySQL error while fetching chats' });
                    return;
                }
                socket.emit('chats', { chats: results });
            });
        } catch (error) {
            socket.emit('error', { msg: 'Error getting chats' });
        }
    });
});

setInterval(() => {
    connection.ping(err => {
        if (err) console.error('MySQL ping error:', err);
    });
}, 60000);

const PORT = process.env.PORT || 5000;
server.listen({ port: PORT, hostname: '0.0.0.0' }, () => {
    console.log(`Server is running on ${PORT} port!`);
});