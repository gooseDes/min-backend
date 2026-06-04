import bcrypt from "bcrypt";
import cors from "cors";
import { and, asc, desc, eq, inArray, ne, or, sql } from "drizzle-orm";
import express, { Request, Response } from "express";
import fs from "fs";
import { createServer } from "http";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import pino from "pino";
import sharp from "sharp";
import { Server } from "socket.io";
import webpush from "web-push";
import { db } from "./db/index.js";
import {
    chatsTable,
    chatUsersTable,
    emojisTable,
    fcmTokensTable,
    messagesTable,
    subscriptionsTable,
    usersTable,
} from "./db/schema.js";
import { fcm, initAdmin } from "./lib/firebaseAdmin.js";
import { Turn } from "./lib/turn.js";
import { formatUser, jsonToObject, objectToJson, validateString } from "./lib/utils.js";

initAdmin();

const EMOJI_SIZE = 96;
const AVATAR_SIZE = 512;
const MAX_ATTACHMENT_SIZE = 2048;

const logsDir = "logs";
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

const logFile = path.join(logsDir, `${new Date().toISOString().replace(/:/g, "-")}.log`);

const streams = [
    {
        stream: pino.transport({
            target: "pino-pretty",
            options: {
                colorize: true,
                translateTime: "yyyy-mm-dd HH:MM:ss",
                ignore: "pid,hostname",
            },
        }),
    },
    { stream: pino.destination(logFile) },
];

const logger = pino(
    {
        level: "info",
        timestamp: pino.stdTimeFunctions.isoTime,
    },
    pino.multistream(streams),
);

logger.info("Setting things up...");

const origins = ["http://localhost:3000", "http://192.168.0.120:3000", "https://web.msg-min.xyz"];

const app = express();
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: origins,
        credentials: true,
    },
});

app.use(
    cors({
        origin: origins,
        credentials: true,
    }),
);
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

webpush.setVapidDetails(`mailto:${process.env.EMAIL}`, process.env.VAPID_PUBLIC, process.env.VAPID_PRIVATE);

// Creating folder for uploads and avatars
const uploadsDir = "uploads";
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
const imagesDir = "images";
const avatarsDir = path.join(uploadsDir, "avatars");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir);
const attachmentsDir = path.join(uploadsDir, "attachments");
if (!fs.existsSync(attachmentsDir)) fs.mkdirSync(attachmentsDir);
const emojisDir = path.join(uploadsDir, "emojis");
if (!fs.existsSync(emojisDir)) fs.mkdirSync(emojisDir);

// Setting up fallbacks
const defaultAvatar = path.join(imagesDir, "logo.webp");
const defaultAttachment = path.join(imagesDir, "no_image.webp");
const defaultEmoji = path.join(imagesDir, "no_image.webp");

const upload = multer({ dest: path.join(uploadsDir, "temp"), limits: { fileSize: 10 * 1024 * 1024 } });

const JWT_SECRET = process.env.JWT_SECRET || "defaultsecret";

await db
    .insert(chatsTable)
    .values({ id: 1, type: "group", name: "Default Chat" })
    .onDuplicateKeyUpdate({ set: { id: 1 } });

// Add avatar column to users table
const users = await db.select().from(usersTable);
for (const user of users) {
    if (user.avatar === "replace") {
        await db
            .update(usersTable)
            .set({ avatar: `${user.id}` })
            .where(eq(usersTable.id, user.id));
    }
}

// Initializing turn server api
const turn = new Turn(db.$client);

interface TokenPayload {
    id: number;
    name: string;
    email: string;
}

interface AuthRequest extends Request {
    userId?: number;
    userName?: string;
}

declare module "socket.io" {
    interface Socket {
        user?: TokenPayload;
    }
}

// Something for verification
function authMiddleware(req: AuthRequest, res: Response, next: () => void) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "No token" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Invalid token" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
        req.userId = decoded.id;
        req.userName = decoded.name;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid Token" });
    }
}

// Route for loading avatars
app.post("/upload-avatar", authMiddleware, upload.single("avatar"), async (req: AuthRequest, res: Response) => {
    try {
        if (!req.file) return res.status(400).json({ success: false, msg: "File is not loaded" });

        const userId = req.userId;
        const suffix = Math.round(Date.now() / 1000);
        const outPath = path.join(avatarsDir, `${userId}_${suffix}.webp`);

        // Converting and resizing image
        await sharp(req.file.path)
            .resize(AVATAR_SIZE, AVATAR_SIZE, { fit: "cover" })
            .toFormat("webp", { quality: 80 })
            .toFile(outPath);

        // Deleting temp
        fs.unlinkSync(req.file.path);

        // Deleting old avatar
        const oldAvatarDb = await db.query.usersTable.findFirst({ where: eq(usersTable.id, userId) });
        if (oldAvatarDb?.avatar) {
            const oldAvatar = oldAvatarDb.avatar;
            try {
                console.log(path.join(avatarsDir, oldAvatar + ".webp"));
                fs.unlinkSync(path.join(avatarsDir, oldAvatar + ".webp"));
            } catch (err) {}
        }

        await db
            .update(usersTable)
            .set({ avatar: `${userId}_${suffix}` })
            .where(eq(usersTable.id, userId));

        res.json({ success: true, url: `/avatars/${userId}_${suffix}.webp`, avatar: `${userId}_${suffix}` });
        logger.info(`${formatUser({ id: userId, name: req.userName })} uploaded their avatar`);
    } catch (err) {
        logger.error(`Error loading avatar for user ${formatUser({ id: req.userId, name: req.userName })}:\n${err}`);
        res.status(500).json({ success: false, msg: "Error loading" });
    }
});

// Hosting avatars
app.get("/avatars/:id.webp", (req, res) => {
    /*if (req.params.id.split("_").length <= 1) {
        const avatarName = await connection.query("SELECT avatar FROM users WHERE id = ?", [req.params.id]);
        req.params.id = avatarName[0][0].avatar;
    }*/
    const filePath = path.join(avatarsDir, req.params.id + ".webp");
    if (fs.existsSync(filePath)) {
        res.sendFile(path.resolve(filePath));
    } else {
        res.sendFile(path.resolve(defaultAvatar));
    }
});

// Hosting avatars for push messages
app.get("/avatars/:id.png", (req, res) => {
    const filePath = path.join(avatarsDir, req.params.id + ".webp");
    let mypath: string;

    if (fs.existsSync(filePath)) {
        mypath = path.resolve(filePath);
    } else {
        mypath = path.resolve(defaultAvatar);
    }

    sharp(mypath)
        .resize(64, 64)
        .toFormat("png")
        .toBuffer()
        .then(buffer => {
            res.type("image/png");
            res.send(buffer);
        })
        .catch(err => {
            logger.error(`Error resizing avatar for someone:\n${err}`);
            res.status(500).json({ success: false, msg: "Error resizing" });
        });
});

// Route for loading attachments
app.post("/attach", authMiddleware, upload.array("attachments", 5), async (req: AuthRequest, res: Response) => {
    try {
        if (!req.files || req.files.length === 0) return res.status(400).json({ success: false, msg: "Files are not loaded" });
        const userId = req.userId;
        const urls = [];

        const imageExts = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff"]);

        if (!Array.isArray(req.files)) return res.status(400).json({ success: false, msg: "Files are not loaded" });
        for (let file of req.files) {
            const ext = path.extname(file.originalname).toLowerCase();
            const isImage = imageExts.has(ext);
            const newFilename = `${Date.now()}-${Math.round(Math.random() * 1e9)}${isImage ? ".webp" : ext}`;
            const outPath = path.join(attachmentsDir, newFilename);

            if (isImage) {
                await sharp(file.path)
                    .rotate()
                    .resize({
                        width: MAX_ATTACHMENT_SIZE,
                        height: MAX_ATTACHMENT_SIZE,
                        fit: sharp.fit.inside,
                        withoutEnlargement: true,
                    })
                    .webp({ quality: 85 })
                    .toFile(outPath);
                fs.unlinkSync(file.path);
            } else {
                // fs.renameSync(file.path, outPath);
                fs.unlinkSync(file.path);
            }

            urls.push(`/attachments/${newFilename}`);
            logger.info(`${formatUser({ id: userId, name: req.userName })} uploaded attachment ${newFilename}`);
        }

        res.json({ success: true, urls: urls });
    } catch (err) {
        logger.error(`Error loading attachments for ${formatUser({ id: req.userId, name: req.userName })}:\n${err}`);

        if (!Array.isArray(req.files)) return res.status(500).json({ success: false, msg: "Error loading" });
        for (const file of req.files ?? []) {
            if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
        }

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

// Route for uploading custom emojis
app.post("/upload-emoji", authMiddleware, upload.single("emoji"), async (req: AuthRequest, res: Response) => {
    try {
        if (!req.file) return res.status(400).json({ success: false, msg: "File is not loaded" });
        const { name } = req.body;
        if (!validateString(name, "username", 1, 32))
            return res.status(400).json({ success: false, msg: "Invalid emoji name" });

        const insertedEmoji = await db.insert(emojisTable).values({ name, uploaderId: req.userId }).$returningId();
        const outPath = path.join(emojisDir, `${insertedEmoji[0].id}.webp`);

        // Converting and resizing image
        await sharp(req.file.path)
            .resize(EMOJI_SIZE, EMOJI_SIZE, { fit: "cover" })
            .toFormat("webp", { quality: 80 })
            .toFile(outPath);

        fs.unlinkSync(req.file.path);

        res.json({ success: true, url: `/emojis/${insertedEmoji[0].id}.webp` });
        logger.info(`${formatUser({ id: req.userId, name: req.userName })} uploaded their custom emoji`);
    } catch (err) {
        logger.error(`Error loading custom emoji by user ${formatUser({ id: req.userId, name: req.userName })}:\n${err}`);
        res.status(500).json({ success: false, msg: "Error loading" });
    }
});

// Hosting custom emojis
app.get("/emojis/:id.webp", (req, res) => {
    const filePath = path.join(emojisDir, req.params.id + ".webp");
    if (fs.existsSync(filePath)) {
        res.sendFile(path.resolve(filePath));
    } else {
        res.sendFile(path.resolve(defaultEmoji));
    }
});

// Signing up
app.post("/register", async (req, res) => {
    try {
        const { email, username, password } = req.body;
        if (!validateString(email, "email", 1, 256)) return res.status(400).json({ msg: "Please enter valid email" });
        if (!validateString(username, "username", 1, 64))
            return res.status(400).json({ msg: "Username must be 1-64 characters and must consist of a-z A-Z 0-9 _ -" });
        if (!validateString(password, "password", 6, 64))
            return res
                .status(400)
                .json({ msg: "Password must be 6-64 characters long and not contain any prohibited characters" });
        const results = await db.query.usersTable.findMany({
            where: or(eq(usersTable.name, username), eq(usersTable.email, email)),
        });
        if (results.length > 0) {
            return res.status(400).json({ msg: "User with such username or email exists" });
        }
        bcrypt.hash(password, 10, async (error, hash) => {
            if (error) {
                return res.status(400).json({ msg: "Error hashing password!" });
            }
            const inserted = await db.insert(usersTable).values({ name: username, email, password: hash }).$returningId();
            const token = jwt.sign({ id: inserted[0].id, name: username, email: email }, JWT_SECRET, { expiresIn: "7d" });
            logger.info(`${formatUser({ id: inserted[0].id, name: username })} just created an account!`);
            return res.json({ id: inserted[0].id, token: token });
        });
    } catch (err) {
        logger.error(`Unexpected error happend while registering user account with data ${objectToJson(req.body)}`);
        return res.status(400).json({ msg: "Unexpected error while registering" });
    }
});

// Signing in
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const results = await db.query.usersTable.findMany({ where: eq(usersTable.email, email) });
        if (results.length === 0) {
            return res.status(400).json({ msg: "User with such email does not exist" });
        }
        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).json({ msg: "Error comparing password" });
            }
            if (!isMatch) {
                return res.status(400).json({ msg: "Incorrect password" });
            }
            const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
            if (!token) {
                return res.status(500).json({ msg: "Error generating token" });
            }
            return res.json({ token: token, username: user.name, id: user.id });
        });
    } catch (err) {
        logger.error(`Unexpected error happend while logining user with data ${objectToJson(req.body)}`);
        return res.status(400).json({ msg: "Unexpected error while logining" });
    }
});

// Verify token
app.post("/verify", (req, res) => {
    try {
        const token = req.body.token;
        if (!token) {
            return res.status(400).json({ msg: "No token provided" });
        }
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            return res.json({ valid: true, user: decoded });
        } catch (err) {
            return res.status(400).json({ valid: false, msg: "Invalid token" });
        }
    } catch (err) {
        return res.status(400).json({ msg: "Unexpected error while verifying" });
    }
});

// Route for subscribing to web push
app.post("/subscribe", async (req, res) => {
    try {
        const subscription = req.body.subscription;
        const token = req.body.token;
        if (!token) {
            return res.status(400).json({ ok: false, msg: "No token provided" });
        }
        const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
        const subscriptions = await db.query.subscriptionsTable.findMany({ where: eq(subscriptionsTable.userId, decoded.id) });
        let contin = true;
        subscriptions.forEach(row => {
            if (jsonToObject(row.subscription).endpoint == subscription.endpoint) {
                contin = false;
            }
        });
        if (!contin) return res.status(400).json({ ok: false, msg: "This device has already subscribed" });
        await db.insert(subscriptionsTable).values({ userId: decoded.id, subscription: JSON.stringify(subscription) });
        return res.json({ ok: true });
    } catch (err) {
        logger.error(`Unexpected error happend while subscribing user to push messages with data ${objectToJson(req.body)}`);
        return res.status(400).json({ ok: false, msg: "Unexpected error while subscribing" });
    }
});

io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;

    if (!token) {
        return next(new Error("No token provided (╯°□°）╯︵ ┻━┻"));
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
        socket.user = decoded;
        const chat_ids = await db.query.chatUsersTable.findMany({
            where: eq(chatUsersTable.userId, decoded.id),
            columns: { chatId: true },
        });
        chat_ids.forEach(chat => {
            socket.join(`chat:${chat.chatId}`);
        });
        socket.join("chat:1");
        next();
    } catch (err) {
        return next(new Error("Invalid token (╯°□°）╯︵ ┻━┻"));
    }
});

io.on("connection", socket => {
    socket.on("msg", async data => {
        try {
            if (!data || !data.text || !data.chat) {
                socket.emit("error", { msg: "Message is empty or some required arguments are missing" });
                return;
            }

            // Saving to db
            const inserted = await db
                .insert(messagesTable)
                .values({ chatId: data.chat, senderId: socket.user.id, content: data.text })
                .$returningId();
            const inserted_data = await db.query.messagesTable.findFirst({
                where: eq(messagesTable.id, inserted[0].id),
            });

            // Getting avatar
            const avatar = await db.query.usersTable.findFirst({
                where: eq(usersTable.id, socket.user.id),
                columns: { avatar: true },
            });
            const author_avatar = avatar?.avatar || null;

            // Sending to everyone
            const to_send = {
                id: inserted[0].id,
                text: data.text,
                author_id: socket.user.id,
                author_avatar: author_avatar,
                author: socket.user.name,
                chat: data.chat,
                sent_at: inserted_data.sentAt.getTime() / 1000,
            };
            io.to(`chat:${data.chat}`).emit("message", to_send);

            // Sending webpush messages
            const chat_users = await db.query.chatUsersTable.findMany({
                where: eq(chatUsersTable.chatId, data.chat),
                columns: { userId: true },
            });
            chat_users.forEach(async row => {
                const subscriptions = await db.query.subscriptionsTable.findMany({
                    where: eq(subscriptionsTable.userId, row.userId),
                    columns: { id: true, subscription: true },
                });
                if (row.userId != socket.user.id) {
                    const results = await db
                        .select({
                            name: sql<string>`
                                CASE
                                    WHEN ${chatsTable.type} = 'private' THEN (
                                    SELECT ${usersTable.name}
                                    FROM ${chatUsersTable}
                                    JOIN ${usersTable} ON ${chatUsersTable.userId} = ${usersTable.id}
                                    WHERE ${chatUsersTable.chatId} = ${chatsTable.id}
                                        AND ${chatUsersTable.userId} != ${row.userId}
                                    LIMIT 1
                                    )
                                    ELSE ${chatsTable.name}
                                END
                            `,
                        })
                        .from(chatsTable)
                        .where(
                            inArray(
                                chatsTable.id,
                                db
                                    .select({ chatId: chatUsersTable.chatId })
                                    .from(chatUsersTable)
                                    .where(and(eq(chatUsersTable.userId, row.userId), eq(chatUsersTable.chatId, data.chat))),
                            ),
                        );
                    if (results.length > 0) {
                        const payload = JSON.stringify({
                            chat: results[0].name,
                            author: socket.user.id,
                            authorAvatar: author_avatar,
                            message: data.text,
                        });
                        let sentCount = 0;

                        subscriptions.forEach(sub => {
                            let subscription: any;
                            try {
                                if (typeof sub.subscription == "string") {
                                    subscription = JSON.parse(sub.subscription);
                                } else {
                                    subscription = sub.subscription;
                                }
                                webpush
                                    .sendNotification(subscription, payload)
                                    .then(() => {
                                        sentCount++;
                                    })
                                    .catch(err => {
                                        console.error("Push failed for", subscription.endpoint, err);
                                        db.delete(subscriptionsTable)
                                            .where(eq(subscriptionsTable.id, sub.id))
                                            .execute()
                                            .catch();
                                    });
                            } catch (error) {
                                console.log(error);
                            }
                        });
                    }
                }
            });

            // Sending FCM messages
            const users = await db.query.chatUsersTable.findMany({
                where: and(eq(chatUsersTable.chatId, data.chat), ne(chatUsersTable.userId, socket.user.id)),
                columns: { userId: true },
            });
            if (users.length) {
                const tokens = await db.query.fcmTokensTable.findMany({
                    where: inArray(
                        fcmTokensTable.userId,
                        users.map(user => user.userId),
                    ),
                    columns: {
                        token: true,
                    },
                });

                if (tokens.length) {
                    await fcm.sendEachForMulticast({
                        data: {
                            authorName: String(to_send.author),
                            text: String(to_send.text),
                            authorId: String(to_send.author_id),
                            authorAvatar: String(author_avatar),
                            chatId: String(data.chat),
                            messageId: String(to_send.id),
                            sentAt: String(to_send.sent_at),
                        },
                        android: {
                            priority: "high",
                        },
                        tokens: tokens.map(token => token.token),
                    });
                }
            }
        } catch (error) {
            socket.emit("error", { msg: "Unexpected error while sending your message" });
            logger.error(`Unexpected error happend while sending message by ${formatUser(socket.user)}:\n${error}`);
            return;
        }
    });

    socket.on("getChatHistory", async data => {
        try {
            if (!data || !data.chat) {
                socket.emit("error", { msg: "Chat ID is required to get chat history" });
                return;
            }
            logger.info(`${formatUser(socket.user)} requested history of chat ${data.chat || "Unknown"}`);
            const sub = db
                .select({
                    id: messagesTable.id,
                    chatId: messagesTable.chatId,
                    content: messagesTable.content,
                    sentAt: sql<number>`UNIX_TIMESTAMP(${messagesTable.sentAt})`.as("sent_at"),
                    senderId: messagesTable.senderId,
                    seen: messagesTable.seen,
                    senderName: usersTable.name,
                    senderAvatar: usersTable.avatar,
                })
                .from(messagesTable)
                .innerJoin(usersTable, eq(messagesTable.senderId, usersTable.id))
                .where(eq(messagesTable.chatId, data.chat))
                .orderBy(desc(messagesTable.sentAt))
                .limit(100)
                .offset(data.currentMessages || 0)
                .as("sub");

            const history = await db.select().from(sub).orderBy(asc(sub.sentAt));

            const maxId = Math.max(...history.map(hist => hist.id));
            const messages = history.map(msg => ({
                id: msg.id,
                chat_id: msg.chatId,
                author_id: msg.senderId,
                author_avatar: msg.senderAvatar,
                author: msg.senderName,
                text: msg.content,
                sent_at: msg.sentAt,
                seen: msg.seen,
            }));
            socket.emit("history", { chat: data.chat, messages: messages, lastIndex: maxId });
        } catch (err) {
            logger.error(`Unexpected error happend while sending chat history to ${formatUser(socket.user)}:\n${err}`);
            socket.emit("error", { msg: "Unexpected error happend while sending chat history" });
        }
    });

    socket.on("getName", async data => {
        try {
            socket.emit("username", socket.user.name);
        } catch (error) {
            socket.emit("error", { msg: "Error getting username" });
        }
    });

    socket.on("createChat", async data => {
        try {
            if (!data || !data.nickname) {
                socket.emit("createChatResult", { success: false, msg: "Nickname is required" });
                return;
            }
            if (data.nickname === socket.user.name) {
                socket.emit("createChatResult", { success: false, msg: "Cannot create chat with yourself" });
                return;
            }
            const userIds = await db.query.usersTable.findMany({
                where: eq(usersTable.name, data.nickname),
                columns: { id: true },
            });
            if (userIds.length === 0) {
                socket.emit("createChatResult", { success: false, msg: "No such user" });
                return;
            }
            const userId = userIds[0].id;
            const chatUsers = [socket.user.id, userId];
            const chatName = chatUsers.sort().join("-");
            const chat_id = await db.query.chatsTable.findFirst({
                where: eq(chatsTable.name, chatName),
                columns: { id: true },
            });
            if (chat_id) {
                socket.emit("createChatResult", { success: false, msg: "Chat already exists" });
                return;
            }
            const insertedChat = await db.insert(chatsTable).values({ type: "private", name: chatName }).$returningId();
            for (let id of chatUsers) {
                await db.insert(chatUsersTable).values({ chatId: insertedChat[0].id, userId: id });
            }
            socket.emit("createChatResult", {
                success: true,
                chatId: insertedChat[0].id,
                chatName: chatName,
                users: chatUsers,
            });
        } catch (error) {
            socket.emit("createChatResult", { success: false, msg: "Unexpected error while creating chat" });
            logger.error(
                `Unexpected error happend while trying to create chat by ${formatUser(socket.user)} with ${data.nickname || "Unknown"}:\n${error}`,
            );
        }
    });

    socket.on("getChats", async data => {
        try {
            // logger.info(`Gettings chats for user ${formatUser(socket.user)}...`);

            const otherUser = db
                .select({
                    chatId: chatUsersTable.chatId,
                    name: usersTable.name,
                })
                .from(chatUsersTable)
                .innerJoin(usersTable, eq(chatUsersTable.userId, usersTable.id))
                .where(ne(chatUsersTable.userId, socket.user.id))
                .as("other_user");

            const chats = await db
                .select({
                    id: chatsTable.id,
                    type: chatsTable.type,
                    name: sql<string>`
                  CASE
                    WHEN ${chatsTable.type} = 'private' THEN ${otherUser.name}
                    ELSE ${chatsTable.name}
                  END
                `.as("name"),
                })
                .from(chatsTable)
                .leftJoin(otherUser, eq(otherUser.chatId, chatsTable.id))
                .where(
                    inArray(
                        chatsTable.id,
                        db
                            .select({ chatId: chatUsersTable.chatId })
                            .from(chatUsersTable)
                            .where(eq(chatUsersTable.userId, socket.user.id)),
                    ),
                );

            // logger.info(`Gettings chats for user ${formatUser(socket.user)}: Database query executed`);
            if (chats.length <= 0) {
                socket.emit("chats", { chats: [] });
                return;
            }
            // logger.info(`Gettings chats for user ${formatUser(socket.user)}: User has chats`);
            const chatIds = chats.map(c => c.id);
            const participants = await db
                .select({
                    chatId: chatUsersTable.chatId,
                    userId: usersTable.id,
                    username: usersTable.name,
                    avatar: usersTable.avatar,
                })
                .from(chatUsersTable)
                .leftJoin(usersTable, eq(chatUsersTable.userId, usersTable.id))
                .where(inArray(chatUsersTable.chatId, chatIds));
            // logger.info(`Getting chats for user ${formatUser(socket.user)}: Participants fetched`);
            const participantsByChat = {};
            for (const p of participants) {
                if (!participantsByChat[p.chatId]) participantsByChat[p.chatId] = [];
                participantsByChat[p.chatId].push({ id: p.userId, name: p.username, avatar: p.avatar });
            }
            const chatsWithParticipants = chats.map(chat => ({
                ...chat,
                participants: participantsByChat[chat.id] || [],
            }));
            socket.emit("chats", { chats: chatsWithParticipants });
            // logger.info(`Getting chats for user ${formatUser(socket.user)}: Chats sent`);
        } catch (error) {
            socket.emit("error", { msg: "Unexpected error getting chats" });
            logger.error(`Unexpected error happend while getting chats by ${formatUser(socket.user)}:\n${error}`);
            return;
        }
    });

    socket.on("getUserInfo", async data => {
        if (!data || (!data.id && !data.name)) {
            socket.emit("error", { msg: "No data provided" });
            return;
        }
        const user = await db.query.usersTable.findFirst({
            where: or(eq(usersTable.id, data.id || 0), eq(usersTable.name, data.name || "")),
            columns: { id: true, name: true, avatar: true },
        });
        socket.emit("userInfo", { user });
    });

    socket.on("getChatWith", async data => {
        if (!data || (!data.id && !data.name)) {
            socket.emit("error", { msg: "No data provided" });
            return;
        }
        const user_id = await db.query.usersTable.findFirst({
            where: or(eq(usersTable.id, data.id || 0), eq(usersTable.name, data.name || "")),
            columns: { id: true },
        });
        data.id = user_id.id;
        const chatUsers = [socket.user.id, data.id];
        const chatName = chatUsers.sort().join("-");
        const chat = await db.query.chatsTable.findFirst({ where: eq(chatsTable.name, chatName), columns: { id: true } });
        if (chat) {
            socket.emit("getChatWithResult", { chatId: chat.id });
            return;
        } else {
            socket.emit("getChatWithResult", { chatId: -1 });
            return;
        }
    });

    socket.on("getCustomEmojis", async data => {
        try {
            const emojis = await db.query.emojisTable.findMany({ where: eq(emojisTable.uploaderId, socket.user.id) });
            socket.emit("customEmojis", { emojis: emojis });
        } catch (error) {
            socket.emit("error", { msg: "Unexpected error while getting custom emojis" });
            logger.error(`Unexpected error happend while getting custom emojis by ${formatUser(socket.user)}:\n${error}`);
        }
    });

    socket.on("seenAll", async data => {
        try {
            if (!data || !data.chat) {
                socket.emit("error", { msg: "Chat ID is required" });
                return;
            }
            await db
                .update(messagesTable)
                .set({ seen: true, seenAt: sql`CURRENT_TIMESTAMP` })
                .where(and(eq(messagesTable.chatId, data.chat), ne(messagesTable.senderId, socket.user.id)));
            io.to(`chat:${data.chat}`).emit("seenAll", { chat: data.chat });
        } catch (error) {
            socket.emit("error", { msg: "Unexpected error happend while marking messages as seen" });
            logger.error(`Unexpected error happend while marking messages as seen by ${formatUser(socket.user)}:\n${error}`);
        }
    });

    // Command for deleting messages
    socket.on("deleteMessage", async data => {
        try {
            if (!data || !data.message) return socket.emit("error", { msg: "Message ID is required" });

            const messageToDelete = await db.query.messagesTable.findFirst({ where: eq(messagesTable.id, data.message) });
            if (!messageToDelete) return socket.emit("error", { msg: "No such message" });
            await db.delete(messagesTable).where(eq(messagesTable.id, messageToDelete.id));
            io.to(`chat:${messageToDelete.chatId}`).emit("deleteMessage", { message: messageToDelete.id });
        } catch (error) {
            socket.emit("error", { msg: "Unexpected error happend while deleting message" });
            logger.error(
                `Unexpected error happend while deleting message with id ${data.message || "Unknown"} by ${formatUser(socket.user)}:\n${error}`,
            );
        }
    });

    // For voice chat
    socket.on("joinVoice", async data => {
        if (!data || !data.chat) {
            socket.emit("error", { msg: "Chat ID is required" });
            return;
        }
        socket.join(`voice:${data.chat}`);
        const sockets = await io.in(`voice:${data.chat}`).fetchSockets();
        const participants = sockets.map((socket: any) => {
            return { id: socket.user.id, name: socket.user.name };
        });
        socket.emit("joinedVoice", {
            role: (io.sockets.adapter.rooms.get(`voice:${data.chat}`)?.size || 0) >= 2 ? "answer" : "offer",
            participants,
        });
        socket.to(`voice:${data.chat}`).emit("userJoined", { user: socket.user });
    });

    socket.on("voiceAction", data => {
        socket.to(`voice:${data.chat}`).emit("voiceAction", data);
    });

    // Getting turn credentials for specific chat
    socket.on("getTurnUrls", async data => {
        try {
            if (!data || !data.chat) {
                return socket.emit("error", { msg: "Chat ID is required" });
            }
            const chatExists = await db.query.chatsTable.findFirst({
                where: eq(chatsTable.id, data.chat),
                columns: { id: true },
            });
            if (chatExists) {
                return socket.emit("error", { msg: "No such chat" });
            }
            if (data.chat !== 1) {
                const isInChat = await db.query.chatUsersTable.findFirst({
                    where: and(eq(chatUsersTable.chatId, data.chat), eq(chatUsersTable.userId, socket.user.id)),
                });
                if (!isInChat) {
                    return socket.emit("error", { msg: "You are not in this chat" });
                }
            }
            const urls = await turn.getTurnUrls(data.chat);
            socket.emit("turnUrls", { urls: urls });
        } catch (error) {
            socket.emit("error", { msg: "Unexpected error while getting turn credentials" });
            logger.error(
                `Unexpected error while getting turn credentials for chat ${data.chat} by ${formatUser(socket.user)}:\n${error}`,
            );
        }
    });

    // Adding FCM token
    socket.on("addFcmToken", async data => {
        try {
            const tokenExists = await db.query.fcmTokensTable.findFirst({
                where: eq(fcmTokensTable.token, data.token),
                columns: { id: true },
            });
            if (tokenExists) {
                return socket.emit("error", { msg: "Token already exists", hidden: true });
            }
            await db.insert(fcmTokensTable).values({ token: data.token, userId: socket.user.id });
        } catch (error) {
            socket.emit("error", { msg: "Unexpected error while adding FCM token" });
            logger.error(`Unexpected error while adding FCM token by ${formatUser(socket.user)}:\n${error}`);
        }
    });

    // Get only one message from specific chat
    socket.on("getMessage", async data => {
        try {
            if (!data || !data.messageId) {
                return socket.emit("error", { msg: "messageId is required" });
            }
            const message = await db.query.messagesTable.findFirst({ where: eq(messagesTable.id, data.messageId) });
            if (!message) {
                return socket.emit("error", { msg: "Message not found", hidden: true });
            }
            if (message.chatId !== 1) {
                const inChat = await db.query.chatUsersTable.findFirst({
                    where: and(eq(chatUsersTable.chatId, message.chatId), eq(chatUsersTable.userId, socket.user.id)),
                });
                if (!inChat) {
                    return socket.emit("error", { msg: "You are not in this chat" });
                }
            }
            socket.emit("requestedMessage", { message: message[0] });
        } catch (error) {
            socket.emit("error", { msg: "Unexpected error while getting message" });
            logger.error(
                `Unexpected error while getting message from chat ${data.chat} by ${formatUser(socket.user)}:\n${error}`,
            );
        }
    });
});

// Starting server
const PORT = process.env.PORT || 5000;
server.listen({ port: PORT, hostname: "0.0.0.0" }, () => {
    logger.info(`Server is successfully started and runs on ${PORT} port!`);
});
