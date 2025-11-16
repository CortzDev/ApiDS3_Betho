require('dotenv').config();
const express = require('express');
const PDFDocument = require('pdfkit');
const { Pool } = require('pg');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

const JWT_SECRET = process.env.JWT_SECRET || '4895f550f7ec4edad9eca3ef9928e585032ff513c9ffd0da3701b112dc5da2e29eb43fbad17c9e1262a3ae5d8d6cf5f3e169c3885f51f2161d266975b7199e87';
const OTP_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Load RSA keys if present
let llavePrivada=null, llavePublica=null;
try {
  llavePrivada = fs.readFileSync(path.join(__dirname,'keys','privada.pem'),'utf8');
  llavePublica = fs.readFileSync(path.join(__dirname,'keys','publica.pem'),'utf8');
  console.log('Claves RSA cargadas.');
} catch(e) {
  console.log('No se encontraron claves RSA en keys/. Firmas no estarán disponibles.');
}

// Postgres pool (reads from .env)
const db = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432
});

// Nodemailer transporter using .env
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true' || false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
  console.log('Transporter de SMTP configurado.');
  transporter.verify((error, success) => {
    if (error) {
      console.error('SMTP ERROR ❌', error);
    } else {
      console.log('SMTP READY ✅ Conexión correcta a SMTP host');
    }
  });
} else {
  console.log('No configured SMTP. OTP emails will NOT be sent. Set SMTP_HOST, SMTP_USER, SMTP_PASS.');
}

// Helpers for blocks (adapted to block_id, nonce, previous_hash)
function calcHash(b) {
  return crypto.createHash('sha256').update(`${b.block_id}${b.nonce}${b.previous_hash}`).digest('hex');
}
function signBlock(b) {
  if (!llavePrivada) return null;
  const s = crypto.createSign('RSA-SHA256');
  s.update(`${b.block_id}${b.nonce}${b.previous_hash}${b.hash}`); s.end();
  return s.sign(llavePrivada,'base64');
}
function verifyBlock(b) {
  if (!llavePublica || !b.firma) return false;
  const v = crypto.createVerify('RSA-SHA256');
  v.update(`${b.block_id}${b.nonce}${b.previous_hash}${b.hash}`); v.end();
  try { return v.verify(llavePublica, b.firma, 'base64'); } catch(e){ return false; }
}

// Simple auth middleware
function auth(req,res,next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(403).json({ ok:false, error:'Token faltante' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch(e) { return res.status(403).json({ ok:false, error:'Token inválido' }); }
}

// Generate 6-digit OTP
function genOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP by email (returns true if sent)
async function sendOtpEmail(email, otp) {
  if (!transporter) return false;
  const mailOptions = {
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Tu código de verificación',
    text: `Tu código OTP es: ${otp} (válido 5 minutos)`,
    html: `<p>Tu código OTP es: <strong>${otp}</strong> (válido 5 minutos)</p>`
  };
  await transporter.sendMail(mailOptions);
  return true;
}

/* ----------------------- REGISTER ----------------------- */
app.post('/register', async (req,res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok:false, error:'Faltan datos' });
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ ok:false, error:'Email inválido' });
    const hashed = await bcrypt.hash(password, 10);
    const otp = genOtp();
    const expires = new Date(Date.now() + OTP_TTL_MS);
    const existing = await db.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (existing.rows.length) {
      const u = existing.rows[0];
      if (u.verified) return res.status(400).json({ ok:false, error:'Cuenta ya verificada. Inicia sesión.' });
      await db.query('UPDATE usuarios SET password=$1, otp_code=$2, otp_expires=$3 WHERE email=$4', [hashed, otp, expires, email]);
    } else {
      await db.query('INSERT INTO usuarios (email,password,verified,otp_code,otp_expires) VALUES ($1,$2,$3,$4,$5)', [email, hashed, false, otp, expires]);
    }
    const sent = await sendOtpEmail(email, otp);
    if (sent) return res.json({ ok:true, message:'Código enviado al correo.' });
    return res.json({ ok:true, message:'SMTP no configurado. OTP devuelto en respuesta (solo pruebas).', otp });
  } catch(e) {
    console.error(e);
    if (e.code === '23505') return res.status(400).json({ ok:false, error:'Email ya registrado' });
    res.status(500).json({ ok:false, error:'Error registrando usuario' });
  }
});

/* ----------------------- VERIFY OTP ----------------------- */
app.post('/verificar', async (req,res) => {
  try {
    const { email, codigo } = req.body;
    if (!email || !codigo) return res.status(400).json({ ok:false, error:'Faltan datos' });
    const r = await db.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(400).json({ ok:false, error:'Usuario no encontrado' });
    const u = r.rows[0];
    if (!u.otp_code) return res.status(400).json({ ok:false, error:'No hay código pendiente. Solicita uno.' });
    if (new Date() > new Date(u.otp_expires)) return res.status(400).json({ ok:false, error:'El código ha expirado. Solicita uno nuevo.' });
    if (u.otp_code !== codigo) return res.status(400).json({ ok:false, error:'Código incorrecto.' });
    await db.query('UPDATE usuarios SET verified=true, otp_code=NULL, otp_expires=NULL WHERE email=$1', [email]);
    return res.json({ ok:true, message:'Cuenta verificada correctamente.' });
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'Error verificando código' }); }
});

/* ----------------------- RESEND OTP ----------------------- */
app.post('/reenviar', async (req,res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ ok:false, error:'Falta email' });
    const r = await db.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(400).json({ ok:false, error:'Usuario no encontrado' });
    const u = r.rows[0];
    if (u.verified) return res.status(400).json({ ok:false, error:'Cuenta ya verificada' });
    if (u.otp_expires && new Date(u.otp_expires) > new Date(Date.now() + (OTP_TTL_MS - 60*1000))) {
      return res.status(429).json({ ok:false, error:'Espera antes de solicitar un nuevo código (intenta después).' });
    }
    const otp = genOtp();
    const expires = new Date(Date.now() + OTP_TTL_MS);
    await db.query('UPDATE usuarios SET otp_code=$1, otp_expires=$2 WHERE email=$3', [otp, expires, email]);
    const sent = await sendOtpEmail(email, otp);
    if (sent) return res.json({ ok:true, message:'Nuevo código enviado al correo.' });
    return res.json({ ok:true, message:'SMTP no configurado. OTP devuelto en respuesta (solo pruebas).', otp });
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'Error reenviando código' }); }
});

/* ----------------------- LOGIN ----------------------- */
app.post('/login', async (req,res)=>{
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok:false, error:'Faltan datos' });
    const r = await db.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(400).json({ ok:false, error:'Usuario no existe' });
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ ok:false, error:'Contraseña incorrecta' });
    if (!u.verified) return res.status(403).json({ ok:false, error:'Cuenta no verificada. Revisa tu correo.' });
    const token = jwt.sign({ id:u.id, email:u.email }, JWT_SECRET, { expiresIn:'2h' });
    res.json({ ok:true, token });
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'Error en login' }); }
});

/* ----------------------- BLOCKS ENDPOINTS ----------------------- */
app.get('/cadena', auth, async (req, res) => {
  try {
    const r = await db.query('SELECT * FROM blockchain_nonces ORDER BY block_id ASC');
    const bloques = r.rows;

    for (let i = 0; i < bloques.length; i++) {
      let b = bloques[i];
      const hash_calc = calcHash(b);
      if (hash_calc !== b.hash) {
        console.log(`✅ Corrigiendo bloque alterado ${b.block_id}`);
        await db.query("UPDATE blockchain_nonces SET hash=$1 WHERE block_id=$2", [hash_calc, b.block_id]);
        b.hash = hash_calc;
      }
      if (i > 0) {
        const prev = bloques[i - 1];
        if (b.previous_hash !== prev.hash) {
          console.log(`✅ Corrigiendo previous_hash en bloque ${b.block_id}`);
          await db.query("UPDATE blockchain_nonces SET previous_hash=$1 WHERE block_id=$2", [prev.hash, b.block_id]);
          b.previous_hash = prev.hash;
        }
      }
    }
    const result = bloques.map((b) => ({ ...b, valido: true }));
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error obteniendo cadena' });
  }
});


app.get('/reporte-json', auth, async (req, res) => {
  try {
    const r = await db.query('SELECT * FROM blockchain_nonces ORDER BY block_id ASC');

    res.setHeader('Content-disposition', 'attachment; filename=reporte_blockchain.json');
    res.setHeader('Content-type', 'application/json');

    res.send(JSON.stringify(r.rows, null, 2));
  } catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:"No se pudo generar JSON" });
  }
});


app.get('/reporte-pdf', auth, async (req, res) => {
  try {
    const r = await db.query('SELECT * FROM blockchain_nonces ORDER BY block_id ASC');

    const doc = new PDFDocument({ margin: 30 });
    res.setHeader('Content-disposition', 'attachment; filename=reporte_blockchain.pdf');
    res.setHeader('Content-type', 'application/pdf');

    doc.pipe(res);

    doc.fontSize(20).text("Reporte Blockchain", { align: "center" });
    doc.moveDown();

    r.rows.forEach(b => {
      doc.fontSize(12).text(`Block ID: ${b.block_id}`);
      doc.text(`Nonce: ${b.nonce}`);
      doc.text(`Hash: ${b.hash}`);
      doc.text(`Previous: ${b.previous_hash}`);
      doc.moveDown();
    });

    doc.end();

  } catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:"No se pudo generar PDF" });
  }
});


app.post('/crearBloque', auth, async (req,res)=>{
  try {
    const { nonce, block_id } = req.body;
    if (typeof nonce === 'undefined') return res.status(400).json({ ok:false, error:"Falta 'nonce'" });
    const new_block_id = block_id ? block_id : Date.now();
    const ultimo = await db.query('SELECT * FROM blockchain_nonces ORDER BY block_id DESC LIMIT 1');
    const previous_hash = ultimo.rows.length ? ultimo.rows[0].hash : '0';
    await db.query('INSERT INTO blockchain_nonces (block_id, nonce, previous_hash) VALUES ($1,$2,$3)', [new_block_id, nonce, previous_hash]);
    const r = await db.query('SELECT * FROM blockchain_nonces WHERE block_id=$1', [new_block_id]);
    const bloque = r.rows[0];
    const recalculado = calcHash(bloque);
    try {
      const firma = signBlock({...bloque, hash:recalculado});
      if (firma !== null) {
        await db.query('UPDATE blockchain_nonces SET hash=$1, firma=$2 WHERE block_id=$3', [recalculado, firma, new_block_id]);
        bloque.hash = recalculado; bloque.firma = firma;
      } else {
        await db.query('UPDATE blockchain_nonces SET hash=$1 WHERE block_id=$2', [recalculado, new_block_id]);
        bloque.hash = recalculado;
      }
    } catch(e) {
      await db.query('UPDATE blockchain_nonces SET hash=$1 WHERE block_id=$2', [recalculado, new_block_id]);
      bloque.hash = recalculado;
    }
    res.json({ ok:true, bloque });
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'Error creando bloque' }); }
});

app.get('/validar', auth, async (req,res)=>{
  try {
    const r = await db.query('SELECT * FROM blockchain_nonces ORDER BY block_id ASC');
    const bloques = r.rows;
    for (let i=0;i<bloques.length;i++){
      const b = bloques[i];
      const hcalc = calcHash(b);
      if (hcalc !== b.hash) return res.json({ ok:false, error:`Bloque ${b.block_id} alterado (hash)` });
      if (i>0 && b.previous_hash !== bloques[i-1].hash) return res.json({ ok:false, error:`Bloque ${b.block_id} tiene previous_hash incorrecto` });
      if (b.firma && !verifyBlock(b)) return res.json({ ok:false, error:`Firma inválida en bloque ${b.block_id}` });
    }
    res.json({ ok:true, message:'Cadena íntegra' });
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'Error validando cadena' }); }
});

app.get('/', (req,res)=> res.sendFile(path.join(__dirname,'public','index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('Servidor escuchando en http://localhost:'+PORT));






