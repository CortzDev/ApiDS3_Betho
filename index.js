require('dotenv').config();
const express = require('express');
const path = require('path');
const jsonwebtoken = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===============================
// CORS
// ===============================
app.use(cors({ origin: true, credentials: true }));

// ===============================
// HELMET + CSP
// ===============================
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:"],
      "connect-src": ["'self'"]
    }
  }
}));

// ===============================
// RATE LIMIT
// ===============================
app.use(rateLimit({ windowMs: 15*60*1000, max:200, standardHeaders:true, legacyHeaders:false }));

// ===============================
// SERVIR FRONTEND
// ===============================
app.use(express.static(path.join(__dirname,'public')));

// ===============================
// BASE DE DATOS
// ===============================
let db;
try{
  db = new Pool({
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD || 'SccSUkutVxtIRJwcfrLsmZBYDYPxGEbP',
    database: process.env.PGDATABASE || 'railway',
    host: process.env.PGHOST || 'turntable.proxy.rlwy.net',
    port: parseInt(process.env.PGPORT||'40300',10)
  });
  console.log("PostgreSQL listo");
}catch(err){ console.error("DB ERROR ❌",err); }

// ===============================
// SESIONES
// ===============================
app.use(session({
  store: new pgSession({ pool: db, tableName:'session' }),
  secret: process.env.SESSION_SECRET || 'supersecreto123',
  resave:false,
  saveUninitialized:false,
  cookie:{ maxAge:1000*60*60*2, secure: process.env.NODE_ENV==='production', httpOnly:true, sameSite:'lax'}
}));

function sessionAuth(req,res,next){
  if(!req.session.user) return res.status(401).json({ ok:false, error:'No autorizado' });
  next();
}

// ===============================
// SMTP OTP
// ===============================
let smtpTransport, smtpReady=false;
try{
  smtpTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT||'465',10),
    secure: process.env.SMTP_SECURE==='true',
    auth:{ user:process.env.SMTP_USER, pass:process.env.SMTP_PASS }
  });
  smtpTransport.verify(err=>{
    if(err) console.error("SMTP ERROR ❌",err);
    else { smtpReady=true; console.log("SMTP READY ✅"); }
  });
}catch(err){ console.error("SMTP CONFIG ❌",err); }

async function sendOtpEmail(email,otp){
  if(!smtpReady){ console.warn("SMTP no configurado, OTP devuelto"); return false; }
  try{
    await smtpTransport.sendMail({
      from:process.env.SMTP_FROM||process.env.SMTP_USER,
      to: email,
      subject:"Tu código de verificación (OTP)",
      text:`Tu código es: ${otp}`
    });
    return true;
  }catch(err){ console.error(err); return false; }
}

// ===============================
// REGISTRO
// ===============================
app.post("/register", async (req,res)=>{
  const { email,password } = req.body;
  if(!email||!password) return res.status(400).json({ ok:false,error:"Email y password obligatorios" });
  try{
    const exist = await db.query("SELECT * FROM usuarios WHERE email=$1",[email]);
    if(exist.rows.length>0) return res.status(400).json({ ok:false,error:"Usuario ya existe" });

    const hashed = await bcrypt.hash(password,10);
    const otp = Math.floor(100000+Math.random()*900000).toString();
    const expires = new Date(Date.now()+10*60000);

    await db.query(
      "INSERT INTO usuarios(email,password,verified,otp_code,otp_expires) VALUES($1,$2,$3,$4,$5)",
      [email,hashed,false,otp,expires]
    );

    await sendOtpEmail(email,otp);
    res.json({ ok:true, message:"Usuario registrado. Verifica tu correo", otp: smtpReady?undefined:otp });
  }catch(err){ console.error(err); res.status(500).json({ ok:false,error:"Error en servidor" }); }
});

// ===============================
// VERIFICAR OTP
// ===============================
app.post("/verify", async (req,res)=>{
  const { email, otp } = req.body;
  try{
    const r = await db.query("SELECT * FROM usuarios WHERE email=$1",[email]);
    if(r.rows.length===0) return res.status(400).json({ ok:false,error:"Usuario no encontrado" });
    const u = r.rows[0];
    if(u.otp_code!==otp || new Date(u.otp_expires)<new Date())
      return res.status(400).json({ ok:false,error:"OTP inválido o expirado" });

    await db.query("UPDATE usuarios SET verified=true,otp_code=NULL,otp_expires=NULL WHERE email=$1",[email]);
    res.json({ ok:true,message:"Cuenta verificada" });
  }catch(err){ console.error(err); res.status(500).json({ ok:false,error:"Error en servidor" }); }
});

// ===============================
// LOGIN
// ===============================
app.post("/login", async (req,res)=>{
  const { email,password } = req.body;
  try{
    const r = await db.query("SELECT * FROM usuarios WHERE email=$1",[email]);
    if(r.rows.length===0) return res.status(400).json({ ok:false,error:"Usuario no existe" });
    const u = r.rows[0];
    const match = await bcrypt.compare(password,u.password);
    if(!match) return res.status(400).json({ ok:false,error:"Password incorrecto" });
    if(!u.verified) return res.status(400).json({ ok:false,error:"Debes verificar tu correo" });

    req.session.user={ id:u.id, email:u.email };
    const token = jsonwebtoken.sign({ id:u.id }, process.env.JWT_SECRET, { expiresIn:"1h" });
    res.json({ ok:true, token });
  }catch(err){ console.error(err); res.status(500).json({ ok:false,error:"Error en servidor" }); }
});

// ===============================
// PERFIL
// ===============================
app.get("/perfil", sessionAuth, (req,res)=>{
  res.json({ ok:true, usuario:req.session.user });
});

// ===============================
// LOGOUT
// ===============================
app.post("/logout", (req,res)=>{
  req.session.destroy(err=>{
    if(err) return res.status(500).json({ ok:false,error:"No se pudo cerrar la sesión" });
    res.clearCookie("connect.sid");
    res.json({ ok:true,message:"Sesión cerrada" });
  });
});

// ===============================
// BLOCKCHAIN + PERSISTENCIA EN DB
// ===============================
let cadena = [];

function hash(data){ return crypto.createHash('sha256').update(data).digest('hex'); }

app.get("/cadena", sessionAuth, (req,res)=>res.json(cadena));

app.post("/crearBloque", sessionAuth, async (req,res)=>{
  const { nonce } = req.body;
  if(!nonce) return res.status(400).json({ ok:false,error:"Nonce requerido" });

  const prevHash = cadena.length===0 ? '0'.repeat(64) : cadena[cadena.length-1].hash;
  const bloque = {
    block_id: cadena.length+1,
    nonce,
    previous_hash: prevHash
  };
  bloque.hash = hash(JSON.stringify(bloque));
  bloque.valido = true;
  cadena.push(bloque);

  try {
    await db.query(
      `INSERT INTO bloques (nonce, previous_hash, hash, valido) 
       VALUES ($1,$2,$3,$4)`,
      [bloque.nonce, bloque.previous_hash, bloque.hash, bloque.valido]
    );
    res.json({ ok:true, bloque });
  } catch (err) {
    console.error("Error insertando bloque:", err);
    res.status(500).json({ ok:false, error:"Error al registrar bloque en DB" });
  }
});

// ===============================
// NUEVO ENDPOINT: OBTENER BLOQUES
// ===============================
app.get("/bloques", sessionAuth, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM bloques ORDER BY block_id ASC");
    res.json({ ok: true, bloques: r.rows });
  } catch (err) {
    console.error("Error obteniendo bloques:", err);
    res.status(500).json({ ok: false, error: "Error obteniendo bloques" });
  }
});

// ===============================
// VALIDAR BLOCKCHAIN
// ===============================
app.get("/validar", sessionAuth, (req,res)=>{
  for(let i=0;i<cadena.length;i++){
    const b = cadena[i];
    const expectedHash = hash(JSON.stringify({ block_id:b.block_id, nonce:b.nonce, previous_hash:b.previous_hash }));
    b.valido = b.hash===expectedHash;
    if(i>0 && b.previous_hash!==cadena[i-1].hash) b.valido=false;
  }
  res.json({ ok:true, message:"Cadena validada" });
});

// ===============================
// REPORTES JSON / PDF
// ===============================
app.get("/reporte-json", sessionAuth, (req,res)=>{
  const data = JSON.stringify(cadena,null,2);
  res.setHeader("Content-Disposition","attachment; filename=blockchain.json");
  res.setHeader("Content-Type","application/json");
  res.send(data);
});

app.get("/reporte-pdf", sessionAuth, (req,res)=>{
  const pdfText = JSON.stringify(cadena,null,2);
  res.setHeader("Content-Disposition","attachment; filename=blockchain.pdf");
  res.setHeader("Content-Type","application/pdf");
  res.send(pdfText);
});

// ===============================
// SERVIDOR
// ===============================
const PORT = process.env.PORT||3000;
app.listen(PORT,()=>console.log(`Servidor corriendo en puerto ${PORT}`));
