import { createConnection } from 'mysql2/promise';
import express from 'express';
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
import webpush from 'web-push';
import { formatUser, jsonToObject, objectToJson } from './utils.js';
import pino from 'pino';
dotenv.config();

const logsDir = 'logs';
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

const logFile = path.join(logsDir, `${new Date().toISOString().replace(/:/g, '-')}.log`);

const streams = [
    {
        stream: pino.transport({
        target: 'pino-pretty',
        options: {
            colorize: true,
            translateTime: "yyyy-mm-dd HH:MM:ss",
            ignore: 'pid,hostname'
        }
        })
    },
    { stream: pino.destination(logFile) }
];

const logger = pino(
    {
        level: 'info',
        timestamp: pino.stdTimeFunctions.isoTime
    },
    pino.multistream(streams)
);

logger.info("Setting things up...");

const origins = ["http://localhost:3000", "http://192.168.0.120:3000", "https://msg-min.xyz"];

const app = express();
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: origins,
        credentials: true
    }
});

app.use(cors({
    origin: origins,
    credentials: true
}))
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

webpush.setVapidDetails(
    `mailto:${process.env.EMAIL}`,
    process.env.VAPID_PUBLIC,
    process.env.VAPID_PRIVATE
);

// Creating folder for uploads and avatars
const uploadsDir = "uploads";
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
const imagesDir = "images";
const defaultAvatar = path.join(imagesDir, "logo.webp");
const defaultAttachment = path.join(imagesDir, "no_image.webp");
const avatarsDir = path.join(uploadsDir, "avatars");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir);
const attachmentsDir = path.join(uploadsDir, "attachments");
if (!fs.existsSync(attachmentsDir)) fs.mkdirSync(attachmentsDir);

const upload = multer({ dest: path.join(uploadsDir, "temp"), limits: { fileSize: 10 * 1024 * 1024 } });

const JWT_SECRET = process.env.JWT_SECRET || 'defaultsecret';

// Creating base and its structure
const initConnection = await createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: 'root',
    password: 'root',
    multipleStatements: true
});

await initConnection.query(`CREATE DATABASE IF NOT EXISTS min;
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
CREATE TABLE IF NOT EXISTS messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    chat_id INT NOT NULL,
    sender_id INT NOT NULL,
    content TEXT NOT NULL,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS subscriptions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  subscription JSON NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

`);
await initConnection.end();

// Creating connection with database
const connection = await createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: 'root',
    password: 'root',
    database: 'min',
    multipleStatements: false
});

// Something for verification
function authMiddleware(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "No token" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Invalid token" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.id;
        req.userName = decoded.name;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid Token" });
    }
}

// Route for loading avatars
app.post("/upload-avatar", authMiddleware, upload.single("avatar"), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ success: false, msg: "File is not loaded" });

        const userId = req.userId;
        const outPath = path.join(avatarsDir, `${userId}.webp`);

        // Converting and resizing image
        await sharp(req.file.path)
        .resize(512, 512, { fit: "cover" })
        .toFormat("webp", { quality: 80 })
        .toFile(outPath);

        fs.unlinkSync(req.file.path);

        res.json({ success: true, url: `/avatars/${userId}.webp` });
        logger.info(`${formatUser({ id: userId, name: req.userName })} uploaded their avatar`);
    } catch (err) {
        logger.error(`Error loading avatar for user ${formatUser({ id: userId, name: req.userName })}:\n${err}`)
        res.status(500).json({ success: false, msg: "Error loading" });
    }
});


// Hosting avatars
app.get("/avatars/:id.webp", (req, res) => {
    const filePath = path.join(avatarsDir, req.params.id + ".webp");
    if (fs.existsSync(filePath)) {
        res.sendFile(path.resolve(filePath));
    } else {
        res.sendFile(path.resolve(defaultAvatar));
    }
});

// Route for loading attachments
app.post("/attach", authMiddleware, upload.array("attachments", 5), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) return res.status(400).json({ success: false, msg: "Files are not loaded" });
        const userId = req.userId;
        const urls = [];
        for (let file of req.files) {
            const ext = path.extname(file.originalname);
            const newFilename = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
            const outPath = path.join(attachmentsDir, newFilename);
            fs.renameSync(file.path, outPath);
            urls.push(`/attachments/${newFilename}`);
            logger.info(`${formatUser({ id: userId, name: req.userName })} uploaded attachment ${newFilename}`);
        }
        res.json({ success: true, urls: urls });
    } catch (err) {
        logger.error(`Error loading attachments for ${formatUser({ id: req.userId, name: req.userName })}:\n${err}`)
        res.status(500).json({ success: false, msg: "Error loading" });
    }
});

// Hosting attachments
app.get("/attachments/:filename", (req, res) => {
    const filePath = path.join(attachmentsDir, req.params.filename);
    if (fs.existsSync(filePath)) {
        res.sendFile(path.resolve(filePath));
    } else {
        res.sendFile(path.resolve(defaultAttachment));
    }
});

// Signing up
app.post('/register', async (req, res) => {
    try {
        const { email, username, password } = req.body;
        const [results] = await connection.query('SELECT * FROM users WHERE name = ? OR email = ?', [username, email]);
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
            const [inserted] = await connection.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [username, email, hash]);
            const token = jwt.sign({ id: inserted.insertId, name: username, email: email }, JWT_SECRET, { expiresIn: '7d' });
            return res.json({ id: inserted.insertId, token: token });
        });
    } catch (err) {
        logger.error(`Unexpected error happend while registering user account with data ${objectToJson(req.body)}`);
        return res.status(400).json({ msg: 'Unexpected error while registering' });
    }
});

// Singing in
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [results] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);
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
        });
    } catch (err) {
        logger.error(`Unexpected error happend while logining user with data ${objectToJson(req.body)}`);
        return res.status(400).json({ msg: 'Unexpected error while logining' })
    }
});

// Verify token
app.post('/verify', (req, res) => {
    try {
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
    } catch (err) {
        return res.status(400).json({ msg: 'Unexpected error while verifying' });
    }
});


// Route for subscribing to web push
app.post('/subscribe', async (req, res) => {
    try {
        const subscription = req.body.subscription;
        const token = req.body.token;
        if (!token) {
            return res.status(400).json({ ok: false, msg: 'No token provided' });
        }
        const decoded = jwt.verify(token, JWT_SECRET);
        const [subscriptions] = await connection.query("SELECT subscription FROM subscriptions WHERE user_id=?", [decoded.id]);
        let contin = true;
        subscriptions.forEach(row => {
            if (jsonToObject(row.subscription).endpoint == subscription.endpoint) {
                contin = false;
            }
        });
        if (!contin) return res.status(400).json({ ok: false, msg: 'This device has already subscribed' });
        await connection.query("INSERT INTO subscriptions (user_id, subscription) VALUES (?, ?)",  [decoded.id, JSON.stringify(subscription)]);
        if (error) {
            return res.status(400).json({ ok: false, msg: 'MySQL error while saving subscription' });
        }
        return res.json({ ok: true });
    }
    catch (err) {
        logger.error(`Unexpected error happend while subscribing user to push messages with data ${objectToJson(req.body)}`);
        return res.status(400).json({ ok: false, msg: 'Unexpected error while subscribing' });
    }
});

io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;

    if (!token) {
        return next(new Error("No token provided (╯°□°）╯︵ ┻━┻"));
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.user = decoded;
        const [chat_ids] = await connection.query('SELECT chat_id FROM chat_users WHERE user_id=?', [decoded.id]);
        chat_ids.forEach(chat => {
            socket.join(`chat:${chat.chat_id}`);
        });
        socket.join('chat:1');
        next();
    } catch (err) {
        return next(new Error("Invalid token (╯°□°）╯︵ ┻━┻"));
    }
});

io.on('connection', (socket) => {
    socket.on('msg', async (data) => {
        try {
            if (!data || !data.text || !data.chat) {
                socket.emit('error', { msg: 'Message is empty or some required arguments are missing' });
                return;
            }

            // Saving to db
            const [inserted] = await connection.query('INSERT INTO messages (chat_id, sender_id, content) VALUES (?, ?, ?)', [data.chat, socket.user.id, data.text]);

            // Sending to everyone
            const to_send = {
                id: inserted.insertId,
                text: data.text,
                author_id: socket.user.id,
                author: socket.user.name,
                chat: data.chat
            }
            io.to(`chat:${data.chat}`).emit('message', to_send);

            // Sending push messages
            const [chat_users] = await connection.query("SELECT user_id FROM chat_users WHERE chat_id=?", [data.chat]);
            chat_users.forEach(async row => {
                const [subscriptions] = await connection.query("SELECT id, subscription FROM subscriptions WHERE user_id = ?", [row.user_id]);
                    if (row.user_id != socket.user.id) {
                        const [results] = await connection.query(`SELECT 
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
                                        SELECT chat_id FROM chat_users WHERE user_id = ? AND chat_id = ?
                                    )`, 
                        [row.user_id, row.user_id, data.chat]);
                        if (results.length > 0) {
                            const payload = JSON.stringify({ chat: results[0].name, author: socket.user.id, message: data.text });
                            let sentCount = 0;

                            subscriptions.forEach(sub => {
                                let subscription;
                                try {
                                    if (typeof sub.subscription == 'string') {
                                        subscription = JSON.parse(sub.subscription);
                                    } else {
                                        subscription = sub.subscription;
                                    }
                                    webpush.sendNotification(subscription, payload)
                                    .then(() => {
                                        sentCount++;
                                    })
                                    .catch(err => {
                                        console.error("Push failed for", subscription.endpoint, err);
                                        connection.query('DELETE FROM subscriptions WHERE id=?', (sub.id));
                                    });
                                } catch (error) {
                                    console.log(error);
                                }
                            });
                        }
                    }
            });
        } catch (error) {
            socket.emit('error', { msg: 'Unexpected error while sending your message' });
            logger.error(`Unexpected error happend while sending message by ${formatUser(socket.user)}:\n${error}`);
            return;
        }
    });

    socket.on('getChatHistory', async (data) => {
        try {
            if (!data || !data.chat) {
                socket.emit('error', { msg: 'Chat ID is required to get chat history' });
                return;
            }
            const [history] = await connection.query(`SELECT
                messages.id,
                messages.content,
                messages.sent_at,
                messages.sender_id,
                users.name AS sender_name
                FROM messages
                JOIN users ON messages.sender_id = users.id
                WHERE messages.chat_id = ?
                ORDER BY messages.sent_at ASC
                LIMIT 100 OFFSET 0;`, 
            [data.chat]);
            logger.info(`${formatUser(socket.user)} requested chat history for chat ${data.chat}:${history.join('\n')}`);
            const messages = history.map(msg => ({
                id: msg.id,
                chat_id: msg.chat_id,
                author_id: msg.sender_id,
                author: msg.sender_name,
                text: msg.content,
                sent_at: msg.sent_at
            }));
            socket.emit('history', { chat: data.chat, messages: messages });
        } catch (err) {
            socket.emit('error', { msg: 'Unexpected error while sending chat history' });
        }
    });

    socket.on('getName', async data => {
        try {
            socket.emit('username', socket.user.name);
        } catch (error) {
            socket.emit('error', { msg: 'Error getting username' });
        }
    });

    socket.on('createChat', async data => {
        try {
            if (!data || !data.nickname) {
                socket.emit('createChatResult', { success: false, msg: 'Nickname is required' });
                return;
            }
            const [user_ids] = await connection.query('SELECT id FROM users WHERE name = ?', [data.nickname]);
            if (user_ids.length === 0) {
                socket.emit('createChatResult', { success: false, msg: 'No such user' });
                return;
            }
            const userId = user_ids[0].id;
            const chatUsers = [socket.user.id, userId];
            const chatName = chatUsers.sort().join('-');
            const [chat_id] = await connection.query('SELECT id FROM chats WHERE name = ?', [chatName]);
            if (chat_id.length > 0) {
                socket.emit('createChatResult', { success: false, msg: 'Chat already exists' });
                return;
            }
            const [inserted_chat] = connection.query('INSERT INTO chats (type, name) VALUES (?, ?)', ['private', chatName]);
            for (let id of chatUsers) {
                await connection.query('INSERT INTO chat_users (chat_id, user_id) VALUES (?, ?)', [inserted_chat.insertId, id]);
            }
            socket.emit('createChatResult', { success: true, chatId: inserted_chat.insertId, chatName: chatName, users: chatUsers });
        } catch (error) {
            socket.emit('createChatResult', { success: false, msg: 'Unexpected error while creating chat' });
            logger.error(`Unexpected error happend while trying to create chat by ${formatUser(socket.user)} with ${data.nickname || 'Unknown'}:\n${error}`);
        }
    });

    socket.on('getChats', async data => {
        try {
            const [chats] = await connection.query(`
                SELECT 
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
                )
            `, [socket.user.id, socket.user.id]);
            if (chats.length <= 0) {
                socket.emit('chats', { chats: [] });
                return;
            }
            const chatIds = chats.map(c => c.id);
            const [participants] = await connection.query(`
                SELECT cu.chat_id, u.id as user_id, u.name
                FROM chat_users cu
                JOIN users u ON cu.user_id = u.id
                WHERE cu.chat_id IN (?)
            `, [chatIds]);
            const participantsByChat = {};
            for (const p of participants) {
                if (!participantsByChat[p.chat_id]) participantsByChat[p.chat_id] = [];
                participantsByChat[p.chat_id].push({ id: p.user_id, name: p.name });
            }
            const chatsWithParticipants = chats.map(chat => ({
                ...chat,
                participants: participantsByChat[chat.id] || []
            }));
            socket.emit('chats', { chats: chatsWithParticipants });
        } catch (error) {
            socket.emit('error', { msg: 'Unexpected error getting chats' });
            logger.error(`Unexpected error happend while getting chats by ${formatUser(socket.user)}:\n${error}`);
            return;
        }
    });

    socket.on('getUserInfo', async data => {
        if (!data || (!data.id && !data.name)) {
            socket.emit('error', { msg: 'No data provided' });
            return;
        }
        const [results] = await connection.query('SELECT id, name FROM users WHERE id = ? OR name = ?', [data.id || 0, data.name || '']);
        socket.emit('userInfo', { user: results[0] });
    });

    socket.on('getChatWith', async data => {
        if (!data || (!data.id && !data.name)) {
            socket.emit('error', { msg: 'No data provided' });
            return;
        }
        const [user_id] = await connection.query('SELECT id FROM users WHERE id = ? OR name = ?', [data.id || 0, data.name || '']);
        data.id = user_id[0].id;
        const chatUsers = [socket.user.id, data.id];
        const chatName = chatUsers.sort().join('-');
        const [results] = await connection.query('SELECT id FROM chats WHERE name=?', [chatName]);
        if (results.length > 0) {
            socket.emit('getChatWithResult', { 'chatId': results[0].id });
            return;
        } else {
            socket.emit('getChatWithResult', { 'chatId': -1 });
            return;
        }
    });
});

// Pinging MySQL connection every minute
setInterval(() => {
    connection.ping();
}, 60000);

const PORT = process.env.PORT || 5000;
server.listen({ port: PORT, hostname: '0.0.0.0' }, () => {
    logger.info(`Server is successfully started and is running on ${PORT} port!`)
});