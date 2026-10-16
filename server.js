require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const axios = require("axios");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET must be configured with at least 32 characters.");
}

app.use(express.json({ limit: "1mb" }));
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);
app.use(cors({
    origin(origin, callback) {
        // Requests without an Origin header include server-to-server and local tooling.
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("Origin not allowed by CORS"));
    }
}));

// Do not serve the project root: it contains the SQLite database and source files.
const db = new sqlite3.Database("./database.db");

function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (error) {
            if (error) return reject(error);
            resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

function get(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (error, row) => error ? reject(error) : resolve(row));
    });
}

function all(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows));
    });
}

function auth(req, res, next) {
    const authorization = req.headers.authorization || "";
    const [scheme, token] = authorization.split(" ");
    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({ error: "Authentication required" });
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        if (!Number.isInteger(req.user.id)) {
            return res.status(401).json({ error: "Invalid token" });
        }
        return next();
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
}

function validEmail(email) {
    return typeof email === "string" &&
        email.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// REGISTER
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body || {};
    if (typeof username !== "string" || username.trim().length < 2 || username.trim().length > 60) {
        return res.status(400).json({ error: "Username must be 2–60 characters." });
    }
    if (!validEmail(email)) return res.status(400).json({ error: "Enter a valid email address." });
    if (typeof password !== "string" || password.length < 12 || password.length > 128) {
        return res.status(400).json({ error: "Password must be 12–128 characters." });
    }

    try {
        const hash = await bcrypt.hash(password, 12);
        await run(
            "INSERT INTO users(username,email,password) VALUES(?,?,?)",
            [username.trim(), email.trim().toLowerCase(), hash]
        );
        return res.status(201).json({ status: "registered" });
    } catch (error) {
        if (error && error.code === "SQLITE_CONSTRAINT") {
            return res.status(409).json({ error: "An account with this email already exists." });
        }
        console.error("Registration failed:", error);
        return res.status(500).json({ error: "Could not create account." });
    }
});

// LOGIN
app.post("/login", async (req, res) => {
    const { email, password } = req.body || {};
    if (!validEmail(email) || typeof password !== "string" || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    try {
        const user = await get("SELECT id, password FROM users WHERE email = ?", [email.trim().toLowerCase()]);
        const match = user ? await bcrypt.compare(password, user.password) : false;
        if (!match) return res.status(401).json({ error: "Invalid email or password." });

        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "12h" });
        return res.json({ token });
    } catch (error) {
        console.error("Login failed:", error);
        return res.status(500).json({ error: "Could not log in." });
    }
});

// CREATE CHAT
app.post("/chat", auth, async (req, res) => {
    try {
        const result = await run("INSERT INTO chats(user_id,title) VALUES(?,?)", [req.user.id, "New Chat"]);
        return res.status(201).json({ chatId: result.lastID });
    } catch (error) {
        console.error("Create chat failed:", error);
        return res.status(500).json({ error: "Could not create chat." });
    }
});

// GET ONLY THE AUTHENTICATED USER'S CHATS
app.get("/chats", auth, async (req, res) => {
    try {
        return res.json(await all("SELECT id, title FROM chats WHERE user_id = ? ORDER BY id DESC", [req.user.id]));
    } catch (error) {
        console.error("Get chats failed:", error);
        return res.status(500).json({ error: "Could not load chats." });
    }
});

// SEND MESSAGE only to a chat owned by this user.
app.post("/message", auth, async (req, res) => {
    const { chatId, message } = req.body || {};
    const id = Number(chatId);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Invalid chat ID." });
    if (typeof message !== "string" || !message.trim() || message.length > 10000) {
        return res.status(400).json({ error: "Message must contain 1–10,000 characters." });
    }
    if (!GEMINI_API_KEY) return res.status(503).json({ error: "AI service is not configured." });

    try {
        const chat = await get("SELECT id FROM chats WHERE id = ? AND user_id = ?", [id, req.user.id]);
        if (!chat) return res.status(404).json({ error: "Chat not found." });

        const ai = await axios.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
            { contents: [{ parts: [{ text: message.trim() }] }] },
            {
                params: { key: GEMINI_API_KEY },
                timeout: 30000,
                headers: { "Content-Type": "application/json" }
            }
        );
        const reply = ai.data?.candidates?.[0]?.content?.parts?.map(part => part.text || "").join("").trim();
        if (!reply) return res.status(502).json({ error: "AI service returned an empty response." });

        await run("INSERT INTO messages(chat_id,role,content) VALUES(?,?,?)", [id, "user", message.trim()]);
        await run("INSERT INTO messages(chat_id,role,content) VALUES(?,?,?)", [id, "assistant", reply]);
        return res.json({ reply });
    } catch (error) {
        console.error("Message generation failed:", error.response?.status || error.message);
        return res.status(error.response ? 502 : 500).json({ error: "Could not generate a reply. Please try again." });
    }
});

// GET MESSAGES only when the chat belongs to the authenticated user.
app.get("/messages/:chatId", auth, async (req, res) => {
    const id = Number(req.params.chatId);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Invalid chat ID." });

    try {
        const chat = await get("SELECT id FROM chats WHERE id = ? AND user_id = ?", [id, req.user.id]);
        if (!chat) return res.status(404).json({ error: "Chat not found." });
        return res.json(await all(
            "SELECT id, role, content FROM messages WHERE chat_id = ? ORDER BY id ASC",
            [id]
        ));
    } catch (error) {
        console.error("Get messages failed:", error);
        return res.status(500).json({ error: "Could not load messages." });
    }
});

app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.message === "Origin not allowed by CORS") {
        return res.status(403).json({ error: "Origin not allowed." });
    }
    console.error("Request failed:", error);
    return res.status(500).json({ error: "Internal server error." });
});

app.listen(PORT, () => console.log("Server running on port", PORT));
