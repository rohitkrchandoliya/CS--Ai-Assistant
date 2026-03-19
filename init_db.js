const sqlite3 = require("sqlite3").verbose()

const db = new sqlite3.Database("./database.db")

db.serialize(()=>{

db.run(`
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
email TEXT UNIQUE,
password TEXT
)
`)

db.run(`
CREATE TABLE IF NOT EXISTS chats(
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER,
title TEXT
)
`)

db.run(`
CREATE TABLE IF NOT EXISTS messages(
id INTEGER PRIMARY KEY AUTOINCREMENT,
chat_id INTEGER,
role TEXT,
content TEXT
)
`)

})

console.log("Database initialized")
