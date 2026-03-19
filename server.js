require("dotenv").config()

const express = require("express")
const sqlite3 = require("sqlite3").verbose()
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cors = require("cors")
const axios = require("axios")

const app = express()

app.use(express.json())
app.use(cors())
app.use(express.static("."))

const db = new sqlite3.Database("./database.db")

// REGISTER
app.post("/register", async (req,res)=>{

const {username,email,password}=req.body

const hash=await bcrypt.hash(password,10)

db.run(
"INSERT INTO users(username,email,password) VALUES(?,?,?)",
[username,email,hash],
(err)=>{
if(err)return res.json({error:"User exists"})
res.json({status:"registered"})
})

})

// LOGIN
app.post("/login",(req,res)=>{

const {email,password}=req.body

db.get(
"SELECT * FROM users WHERE email=?",
[email],
async (err,user)=>{

if(!user)return res.json({error:"User not found"})

const match=await bcrypt.compare(password,user.password)

if(!match)return res.json({error:"Wrong password"})

const token=jwt.sign({id:user.id},process.env.JWT_SECRET)

res.json({token})

})

})

// AUTH
function auth(req,res,next){

const token=req.headers.authorization

if(!token)return res.status(401).send()

try{
req.user=jwt.verify(token,process.env.JWT_SECRET)
next()
}catch{
res.status(401).send()
}

}

// CREATE CHAT
app.post("/chat",auth,(req,res)=>{

db.run(
"INSERT INTO chats(user_id,title) VALUES(?,?)",
[req.user.id,"New Chat"],
function(){
res.json({chatId:this.lastID})
})

})

// GET CHATS
app.get("/chats",auth,(req,res)=>{

db.all(
"SELECT * FROM chats WHERE user_id=?",
[req.user.id],
(err,rows)=>{

res.json(rows)

})

})

// SEND MESSAGE
app.post("/message",auth,async(req,res)=>{

const {chatId,message}=req.body

db.run(
"INSERT INTO messages(chat_id,role,content) VALUES(?,?,?)",
[chatId,"user",message]
)

const ai=await axios.post(
`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${process.env.GEMINI_API_KEY}`,
{
contents:[{parts:[{text:message}]}]
}
)

const reply=ai.data.candidates[0].content.parts[0].text

db.run(
"INSERT INTO messages(chat_id,role,content) VALUES(?,?,?)",
[chatId,"assistant",reply]
)

res.json({reply})

})

// GET MESSAGES
app.get("/messages/:chatId",auth,(req,res)=>{

db.all(
"SELECT * FROM messages WHERE chat_id=?",
[req.params.chatId],
(err,rows)=>{
res.json(rows)
})

})

app.listen(process.env.PORT,()=>{
console.log("Server running")
})
