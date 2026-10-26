require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false } : false
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "dev-only-change-this-secret",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 86400000 }
}));
app.use(express.static(path.join(__dirname, "public")));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
      demo_balance NUMERIC(12,2) NOT NULL DEFAULT 10000,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS trades (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      asset TEXT NOT NULL,
      direction TEXT NOT NULL CHECK (direction IN ('UP','DOWN')),
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      duration_seconds INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      result TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS demo_candles (
      id SERIAL PRIMARY KEY, asset TEXT NOT NULL, candle_time TIMESTAMPTZ NOT NULL,
      open NUMERIC(14,5) NOT NULL, high NUMERIC(14,5) NOT NULL,
      low NUMERIC(14,5) NOT NULL, close NUMERIC(14,5) NOT NULL,
      source TEXT NOT NULL DEFAULT 'SIMULATED',
      UNIQUE(asset, candle_time)
    );
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS user_demo_candles (
      id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      asset TEXT NOT NULL, candle_time TIMESTAMPTZ NOT NULL,
      open NUMERIC(14,5) NOT NULL, high NUMERIC(14,5) NOT NULL,
      low NUMERIC(14,5) NOT NULL, close NUMERIC(14,5) NOT NULL,
      source TEXT NOT NULL DEFAULT 'SIMULATED', UNIQUE(user_id,asset,candle_time)
    );
    CREATE TABLE IF NOT EXISTS payment_requests (
      id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      request_type TEXT NOT NULL CHECK(request_type IN ('deposit','withdrawal')),
      amount NUMERIC(12,2) NOT NULL CHECK(amount > 0), network TEXT NOT NULL DEFAULT 'TRC20',
      tx_hash TEXT, wallet_address TEXT, status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(status IN ('PENDING','APPROVED','REJECTED')),
      admin_note TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS admin_audit_log (
      id SERIAL PRIMARY KEY, admin_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL,
      details JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    INSERT INTO app_settings(key,value) VALUES ('candle_mode','auto') ON CONFLICT(key) DO NOTHING;
  `);
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (email && password) {
    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email.toLowerCase()]);
    if (!exists.rowCount) {
      const hash = await bcrypt.hash(password, 12);
      await pool.query("INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,'admin')",
        ["Administrator", email.toLowerCase(), hash]);
      console.log("Admin account created from environment settings.");
    }
  }
}
function safeUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, demoBalance: Number(u.demo_balance) };
}
async function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Please log in first." });
  const result = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
  if (!result.rowCount) { req.session.destroy(()=>{}); return res.status(401).json({error:"Session expired"}); }
  req.user = result.rows[0]; next();
}
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required." });
  next();
}

app.post("/api/register", async (req,res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2 || !email.includes("@") || password.length < 8)
      return res.status(400).json({error:"Enter a name, valid email and password (8+ characters)."});
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      "INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING *",
      [name,email,hash]);
    req.session.userId = r.rows[0].id;
    res.json({user:safeUser(r.rows[0])});
  } catch(e) {
    if (e.code === "23505") return res.status(409).json({error:"Email is already registered."});
    console.error(e); res.status(500).json({error:"Could not register."});
  }
});
app.post("/api/login", async (req,res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const r = await pool.query("SELECT * FROM users WHERE email=$1",[email]);
    if (!r.rowCount || !(await bcrypt.compare(password,r.rows[0].password_hash)))
      return res.status(401).json({error:"Incorrect email or password."});
    req.session.userId = r.rows[0].id;
    res.json({user:safeUser(r.rows[0])});
  } catch(e) { console.error(e); res.status(500).json({error:"Login failed."}); }
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",requireAuth,(req,res)=>res.json({user:safeUser(req.user)}));
app.get("/api/trades",requireAuth,async(req,res)=>{
  const r=await pool.query("SELECT id,asset,direction,amount,duration_seconds,status,result,created_at FROM trades WHERE user_id=$1 ORDER BY id DESC LIMIT 50",[req.user.id]);
  res.json({trades:r.rows});
});
app.post("/api/trades",requireAuth,async(req,res)=>{
  try {
    const asset=String(req.body.asset||"").slice(0,30);
    const direction=String(req.body.direction||"");
    const amount=Number(req.body.amount);
    const duration=Number(req.body.duration);
    if (!["EUR/USD","GBP/USD","BTC/USD","ETH/USD"].includes(asset) ||
        !["UP","DOWN"].includes(direction) || !Number.isFinite(amount) ||
        amount < 1 || amount > 10000 || ![30,60,120,300].includes(duration))
      return res.status(400).json({error:"Invalid demo trade settings."});
    const client=await pool.connect();
    try {
      await client.query("BEGIN");
      const ur=await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE",[req.user.id]);
      const balance=Number(ur.rows[0].demo_balance);
      if(amount>balance){await client.query("ROLLBACK");return res.status(400).json({error:"Not enough demo balance."});}
      await client.query("UPDATE users SET demo_balance=demo_balance-$1 WHERE id=$2",[amount,req.user.id]);
      const tr=await client.query(
        "INSERT INTO trades(user_id,asset,direction,amount,duration_seconds,status,result) VALUES($1,$2,$3,$4,$5,'COMPLETED','SIMULATED') RETURNING *",
        [req.user.id,asset,direction,amount,duration]);
      // Demo-only: illustrative 50/50 outcome, not a market prediction or live quote.
      const win=Math.random()>=0.5;
      const payout=win ? amount*1.8 : 0;
      await client.query("UPDATE users SET demo_balance=demo_balance+$1 WHERE id=$2",[payout,req.user.id]);
      await client.query("UPDATE trades SET result=$1 WHERE id=$2",[win?"DEMO_WIN":"DEMO_LOSS",tr.rows[0].id]);
      await client.query("COMMIT");
      const latest=await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id]);
      res.json({trade:{id:tr.rows[0].id,asset,direction,amount,duration,status:"COMPLETED",result:win?"DEMO_WIN":"DEMO_LOSS"},user:safeUser(latest.rows[0])});
    } catch(e){await client.query("ROLLBACK");throw e;} finally{client.release();}
  } catch(e){console.error(e);res.status(500).json({error:"Could not create demo trade."});}
});
app.get("/api/admin/users",requireAuth,requireAdmin,async(req,res)=>{
  const r=await pool.query("SELECT id,name,email,role,demo_balance,created_at FROM users ORDER BY id DESC LIMIT 200");
  res.json({users:r.rows});
});
app.post("/api/admin/balance",requireAuth,requireAdmin,async(req,res)=>{
  const userId=Number(req.body.userId), balance=Number(req.body.balance);
  if(!Number.isInteger(userId)||!Number.isFinite(balance)||balance<0||balance>100000000)
    return res.status(400).json({error:"Invalid user ID or demo balance."});
  const r=await pool.query("UPDATE users SET demo_balance=$1 WHERE id=$2 RETURNING id,email,demo_balance",[balance,userId]);
  if(!r.rowCount)return res.status(404).json({error:"User not found."});
  res.json({user:r.rows[0]});
});

const DEMO_ASSETS = {"EUR/USD":1.08450,"GBP/USD":1.27100,"BTC/USD":67250,"ETH/USD":3420};
async function seedDemoCandles() {
  for (const [asset, base] of Object.entries(DEMO_ASSETS)) {
    const count = await pool.query("SELECT COUNT(*)::int AS n FROM demo_candles WHERE asset=$1", [asset]);
    if (count.rows[0].n) continue;
    let p = base;
    for (let i=59; i>=0; i--) {
      const scale = asset==="BTC/USD" || asset==="ETH/USD" ? 0.002 : 0.0008;
      const o=p, c=Math.max(0.00001,p+(Math.random()-0.5)*p*scale*2);
      const h=Math.max(o,c)*(1+Math.random()*scale*0.3), l=Math.min(o,c)*(1-Math.random()*scale*0.3);
      const t=new Date(Math.floor(Date.now()/60000)*60000-i*60000);
      await pool.query("INSERT INTO demo_candles(asset,candle_time,open,high,low,close) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",[asset,t,o,h,l,c]);
      p=c;
    }
  }
}
// Every account gets an independent simulated candle series. No live prices are used.
app.get("/api/candles", requireAuth, async (req,res) => {
  try {
    const asset=String(req.query.asset||"EUR/USD");
    if (!DEMO_ASSETS[asset]) return res.status(400).json({error:"Unknown asset"});
    const userId=req.user.id;
    const modeR=await pool.query("SELECT value FROM app_settings WHERE key='candle_mode'");
    const globalMode=modeR.rows[0]?.value||"auto";
    const setting=await pool.query("SELECT value FROM app_settings WHERE key=$1",[`candle_mode_user_${userId}`]);
    const mode=setting.rows[0]?.value||globalMode;
    const latest=await pool.query("SELECT * FROM user_demo_candles WHERE user_id=$1 AND asset=$2 ORDER BY candle_time DESC LIMIT 1",[userId,asset]);
    if (mode==="auto" && (!latest.rows[0] || Date.now()-new Date(latest.rows[0].candle_time).getTime()>=60000)) {
      const p=latest.rows[0]?Number(latest.rows[0].close):DEMO_ASSETS[asset];
      const scale=asset==="BTC/USD"||asset==="ETH/USD"?0.0015:0.0005;
      const o=p,c=Math.max(0.00001,p+(Math.random()-0.5)*p*scale*2);
      const h=Math.max(o,c)*(1+Math.random()*scale*0.25),l=Math.min(o,c)*(1-Math.random()*scale*0.25);
      const t=new Date(Math.floor(Date.now()/60000)*60000);
      await pool.query("INSERT INTO user_demo_candles(user_id,asset,candle_time,open,high,low,close,source) VALUES($1,$2,$3,$4,$5,$6,$7,'SIMULATED') ON CONFLICT(user_id,asset,candle_time) DO NOTHING",[userId,asset,t,o,h,l,c]);
    }
    const r=await pool.query("SELECT candle_time,open,high,low,close,source FROM user_demo_candles WHERE user_id=$1 AND asset=$2 ORDER BY candle_time DESC LIMIT 60",[userId,asset]);
    res.json({asset,mode,candles:r.rows.reverse().map(c=>({...c,open:Number(c.open),high:Number(c.high),low:Number(c.low),close:Number(c.close)})),notice:"SIMULATED DEMO DATA — NOT LIVE MARKET PRICES"});
  } catch(e){console.error(e);res.status(500).json({error:"Could not load demo candles"});}
});
app.get("/api/admin/candles/mode", requireAuth, requireAdmin, async(req,res)=>{
  const r=await pool.query("SELECT value FROM app_settings WHERE key='candle_mode'");
  res.json({mode:r.rows[0]?.value||"auto"});
});
app.post("/api/admin/candles/mode", requireAuth, requireAdmin, async(req,res)=>{
  const mode=String(req.body.mode||"");
  if(!["auto","manual"].includes(mode))return res.status(400).json({error:"Mode must be auto or manual."});
  await pool.query("INSERT INTO app_settings(key,value,updated_at) VALUES('candle_mode',$1,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()",[mode]);
  res.json({mode,message:"Default demo candle mode saved."});
});
app.post("/api/admin/user-candles/mode", requireAuth, requireAdmin, async(req,res)=>{
  const userId=Number(req.body.userId),mode=String(req.body.mode||"");
  if(!Number.isInteger(userId)||!["auto","manual"].includes(mode))return res.status(400).json({error:"Choose a valid user and mode."});
  const u=await pool.query("SELECT id FROM users WHERE id=$1",[userId]);if(!u.rowCount)return res.status(404).json({error:"User not found."});
  await pool.query("INSERT INTO app_settings(key,value,updated_at) VALUES($1,$2,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()",[`candle_mode_user_${userId}`,mode]);
  await pool.query("INSERT INTO admin_audit_log(admin_user_id,target_user_id,action,details) VALUES($1,$2,'USER_CANDLE_MODE',$3)",[req.user.id,userId,JSON.stringify({mode})]);
  res.json({message:`Demo candle mode for user #${userId} set to ${mode}.`});
});
app.post("/api/admin/user-candles", requireAuth, requireAdmin, async(req,res)=>{
  try{
    const userId=Number(req.body.userId),asset=String(req.body.asset||""),o=Number(req.body.open),h=Number(req.body.high),l=Number(req.body.low),c=Number(req.body.close);
    if(!Number.isInteger(userId)||!DEMO_ASSETS[asset]||![o,h,l,c].every(Number.isFinite)||Math.min(o,h,l,c)<=0||h<Math.max(o,c,l)||l>Math.min(o,c,h))return res.status(400).json({error:"Invalid user or OHLC values."});
    const u=await pool.query("SELECT id FROM users WHERE id=$1",[userId]);if(!u.rowCount)return res.status(404).json({error:"User not found."});
    const mode=await pool.query("SELECT value FROM app_settings WHERE key=$1",[`candle_mode_user_${userId}`]);
    if((mode.rows[0]?.value||"auto")!=="manual")return res.status(409).json({error:"Set this user's candle mode to Manual first."});
    const t=new Date(Math.floor(Date.now()/60000)*60000);
    await pool.query("INSERT INTO user_demo_candles(user_id,asset,candle_time,open,high,low,close,source) VALUES($1,$2,$3,$4,$5,$6,$7,'ADMIN_SIMULATION') ON CONFLICT(user_id,asset,candle_time) DO UPDATE SET open=EXCLUDED.open,high=EXCLUDED.high,low=EXCLUDED.low,close=EXCLUDED.close,source='ADMIN_SIMULATION'",[userId,asset,t,o,h,l,c]);
    await pool.query("INSERT INTO admin_audit_log(admin_user_id,target_user_id,action,details) VALUES($1,$2,'USER_CANDLE_SET',$3)",[req.user.id,userId,JSON.stringify({asset,open:o,high:h,low:l,close:c})]);
    res.json({message:`Demo candle saved for user #${userId}.`});
  }catch(e){console.error(e);res.status(500).json({error:"Could not save user demo candle."});}
});
// TRC20 screens are simulation-only: no real wallet address, chain check or transfer is provided.
app.get("/api/payments", requireAuth, async(req,res)=>{
  const r=await pool.query("SELECT id,request_type,amount,network,tx_hash,wallet_address,status,admin_note,created_at,reviewed_at FROM payment_requests WHERE user_id=$1 ORDER BY id DESC LIMIT 100",[req.user.id]);
  res.json({requests:r.rows,notice:"DEMO ONLY — no blockchain transaction or real USDT transfer occurs."});
});
app.post("/api/payments", requireAuth, async(req,res)=>{
  try{
    const type=String(req.body.type||""),amount=Number(req.body.amount),network=String(req.body.network||"TRC20");
    const txHash=String(req.body.txHash||"").trim().slice(0,160),wallet=String(req.body.walletAddress||"").trim().slice(0,160);
    if(!["deposit","withdrawal"].includes(type)||network!=="TRC20"||!Number.isFinite(amount)||amount<1||amount>1000000)return res.status(400).json({error:"Enter a valid amount and TRC20 network."});
    if(type==="deposit" && !txHash)return res.status(400).json({error:"Enter a demo transaction reference."});
    if(type==="withdrawal" && !/^T[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(wallet))return res.status(400).json({error:"Enter a TRON-style address for this demo request."});
    if(type==="withdrawal" && Number(req.user.demo_balance)<amount)return res.status(400).json({error:"Insufficient virtual demo balance."});
    const r=await pool.query("INSERT INTO payment_requests(user_id,request_type,amount,network,tx_hash,wallet_address) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,request_type,amount,network,tx_hash,wallet_address,status,created_at",[req.user.id,type,amount,network,txHash||null,wallet||null]);
    res.json({request:r.rows[0],message:"Demo request submitted. This does not send or receive real USDT."});
  }catch(e){console.error(e);res.status(500).json({error:"Could not submit demo request."});}
});
app.get("/api/admin/payments", requireAuth, requireAdmin, async(req,res)=>{
  const r=await pool.query("SELECT p.*,u.name AS username,u.email FROM payment_requests p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 300");res.json({requests:r.rows});
});
app.post("/api/admin/payments/:id/review", requireAuth, requireAdmin, async(req,res)=>{
  const id=Number(req.params.id),decision=String(req.body.decision||""),note=String(req.body.note||"").slice(0,300);
  if(!Number.isInteger(id)||!["APPROVED","REJECTED"].includes(decision))return res.status(400).json({error:"Invalid request or decision."});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");const pr=await client.query("SELECT * FROM payment_requests WHERE id=$1 FOR UPDATE",[id]);
    if(!pr.rowCount){await client.query("ROLLBACK");return res.status(404).json({error:"Request not found."});}
    const p=pr.rows[0];if(p.status!=="PENDING"){await client.query("ROLLBACK");return res.status(409).json({error:"This request has already been reviewed."});}
    if(decision==="APPROVED"&&p.request_type==="withdrawal"){
      const u=await client.query("SELECT demo_balance FROM users WHERE id=$1 FOR UPDATE",[p.user_id]);
      if(Number(u.rows[0].demo_balance)<Number(p.amount)){await client.query("ROLLBACK");return res.status(409).json({error:"User no longer has enough virtual demo balance."});}
      await client.query("UPDATE users SET demo_balance=demo_balance-$1 WHERE id=$2",[p.amount,p.user_id]);
    }
    if(decision==="APPROVED"&&p.request_type==="deposit")await client.query("UPDATE users SET demo_balance=demo_balance+$1 WHERE id=$2",[p.amount,p.user_id]);
    await client.query("UPDATE payment_requests SET status=$1,admin_note=$2,reviewed_at=NOW() WHERE id=$3",[decision,note||null,id]);
    await client.query("INSERT INTO admin_audit_log(admin_user_id,target_user_id,action,details) VALUES($1,$2,'PAYMENT_REVIEW',$3)",[req.user.id,p.user_id,JSON.stringify({requestId:id,decision,type:p.request_type,amount:p.amount})]);
    await client.query("COMMIT");res.json({message:`Demo request ${decision.toLowerCase()}.`});
  }catch(e){await client.query("ROLLBACK");console.error(e);res.status(500).json({error:"Could not review request."});}finally{client.release();}
});
app.get("/api/health",(_req,res)=>res.json({ok:true,mode:"demo-only"}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

const port=process.env.PORT||3000;
initDb().then(async()=>{ await seedDemoCandles(); app.listen(port,()=>console.log(`DOJI TRADE demo running on ${port}`)); })
  .catch(e=>{console.error("Database initialization failed:",e);process.exit(1);});
