// ===============================
// SERVIDOR SEGURO CON SESIONES Y HARDENING
// Copia y pega este archivo tal cual. Ajusta .env para producción.
// ===============================

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const crypto = require('crypto');
const jsonwebtoken = require('jsonwebtoken');

// -------------------------------
// CONFIG
// -------------------------------
const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
if (TRUST_PROXY) app.set('trust proxy', 1); // if behind reverse proxy (Heroku, nginx, etc.)

// -------------------------------
// MIDDLEWARE BASICO
// -------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'cookiesecret123'));
app.use(express.static(path.join(__dirname, 'public')));

// -------------------------------
// SECURITY HEADERS (Helmet)
// -------------------------------
app.use(helmet());
// HSTS (en producción asegúrate de usar HTTPS)
if (isProduction) {
  app.use(
    helmet.hsts({
      maxAge: 31536000, // 1 año
      includeSubDomains: true,
      preload: true,
    })
  );
}

// Content Security Policy: ajusta según tus necesidades y recursos externos
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

// -------------------------------
// RATE LIMITING
// -------------------------------
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 200, // máximo de requests por IP
  standardHeaders: true,
  legacyHeaders: false,
});

// Límites más estrictos para endpoints de autenticación
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 8, // permite hasta 8 intentos cada 15 minutos
  message: { ok: false, error: 'Demasiados intentos, intenta de nuevo más tarde' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/register', authLimiter);
app.use('/login', authLimiter);
app.use('/verificar', authLimiter);
app.use('/reenviar', authLimiter);
app.use('/crearBloque', apiLimiter);
app.use('/cadena', apiLimiter);

// -------------------------------
// DATABASE (Postgres)
// -------------------------------
const db = new Pool({
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || '',
  database: process.env.PGDATABASE || 'interblockchain',
  host: process.env.PGHOST || 'localhost',
  port: parseInt(process.env.PGPORT || '5432', 10),
  max: 20,
  idleTimeoutMillis: 30000,
});

// -------------------------------
// SESSIONS (store en PostgreSQL)
// -------------------------------
const keyPath = path.join(__dirname, 'keys');
let hasHttpsCert = false;
try {
  const cert = fs.readFileSync(path.join(keyPath, 'cert.pem'));
  const key = fs.readFileSync(path.join(keyPath, 'key.pem'));
  if (cert && key) hasHttpsCert = true;
} catch (e) {
  // no certificate found; continua en modo HTTP (recomendado: usar proxy HTTPS en prod)
}

const secureCookie = isProduction || hasHttpsCert || TRUST_PROXY;

app.use(
  session({
    store: new pgSession({ pool: db, tableName: 'session' }),
    name: process.env.SESSION_NAME || 'sid',
    secret: process.env.SESSION_SECRET || 'supersecreto123',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      maxAge: Number(process.env.SESSION_MAX_AGE_MS || 1000 * 60 * 60 * 2),
      secure: secureCookie, // true si HTTPS
      httpOnly: true,
      sameSite: process.env.COOKIE_SAMESITE || 'lax',
    },
  })
);

// -------------------------------
// CSRF PROTECTION
// -------------------------------
// Usar token CSRF con cookies. Para APIs JSON, proveemos endpoint /csrf-token
const csurfProtection = csurf({ cookie: { httpOnly: true, sameSite: 'lax', secure: secureCookie } });
// Aplicar csurf solo si no estamos en modo stateless API. Si tu cliente es SPA, usa /csrf-token.
app.use((req, res, next) => {
  // Aplicar CSRF en métodos que mutan (POST/PUT/DELETE) y si la petición incluye cookies
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) return csurfProtection(req, res, next);
  return next();
});

app.get('/csrf-token', (req, res) => {
  // Genera un token si es necesario (csurf se ejecuta en mutating routes), pero podemos crear uno
  // usando el middleware directamente para obtener token
  csurfProtection(req, res, () => {
    res.json({ csrfToken: req.csrfToken() });
  });
});

// -------------------------------
// SMTP (Nodemailer)
// -------------------------------
let smtpTransport;
let smtpReady = false;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  smtpTransport = require('nodemailer').createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  smtpTransport.verify((err) => {
    if (err) console.error('SMTP ERROR ❌', err);
    else { smtpReady = true; console.log('SMTP READY ✅'); }
  });
} else {
  console.warn('SMTP no configurado. OTP se devolverá en respuesta en modo de pruebas.');
}

async function sendOtpEmail(email, otp) {
  if (!smtpReady) return false;
  const info = await smtpTransport.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Tu código de verificación',
    text: `Tu código OTP es: ${otp}`,
  });
  return !!info;
}

// -------------------------------
// Helpers
// -------------------------------
function genOtp() { return Math.floor(100000 + Math.random() * 900000).toString(); }
function calcHash(b) { return crypto.createHash('sha256').update(`${b.block_id}${b.nonce}${b.previous_hash}`).digest('hex'); }

// -------------------------------
// AUTH MIDDLEWARE (JWT + Session)
// -------------------------------
function requireSession(req, res, next) {
  if (!req.session || !req.session.user) return res.status(401).json({ ok: false, error: 'No autorizado (sesión)' });
  next();
}

function requireJwt(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ ok: false, error: 'Token faltante' });
  try { req.user = jsonwebtoken.verify(token, process.env.JWT_SECRET || 'jwtsecret'); next(); }
  catch (e) { return res.status(401).json({ ok: false, error: 'Token inválido' }); }
}

// -------------------------------
// ENDPOINTS
// -------------------------------
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, error: 'Faltan datos' });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ ok: false, error: 'Email inválido' });

    const existing = await db.query('SELECT id, verified FROM usuarios WHERE email=$1', [email]);
    if (existing.rows.length) return res.status(400).json({ ok: false, error: 'Email ya registrado' });

    const hashed = await bcrypt.hash(password, 12);
    const otp = genOtp();
    const expires = new Date(Date.now() + 5 * 60 * 1000);

    await db.query('INSERT INTO usuarios (email,password,verified,otp_code,otp_expires) VALUES ($1,$2,$3,$4,$5)', [email, hashed, false, otp, expires]);

    const sent = await sendOtpEmail(email, otp);
    return res.json({ ok: true, message: 'Registrado. Verifica tu correo', otp: sent ? undefined : otp });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Error registrando usuario' }); }
});

app.post('/verificar', async (req, res) => {
  try {
    const { email, codigo } = req.body;
    if (!email || !codigo) return res.status(400).json({ ok: false, error: 'Faltan datos' });
    const r = await db.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(400).json({ ok: false, error: 'Usuario no encontrado' });
    const u = r.rows[0];
    if (!u.otp_code) return res.status(400).json({ ok: false, error: 'No hay código pendiente' });
    if (new Date() > new Date(u.otp_expires)) return res.status(400).json({ ok: false, error: 'Código expirado' });
    if (u.otp_code !== codigo) return res.status(400).json({ ok: false, error: 'Código incorrecto' });
    await db.query('UPDATE usuarios SET verified=true, otp_code=NULL, otp_expires=NULL WHERE email=$1', [email]);
    res.json({ ok: true, message: 'Cuenta verificada' });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Error verificando código' }); }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, error: 'Faltan datos' });
    const r = await db.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(400).json({ ok: false, error: 'Usuario no existe' });
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ ok: false, error: 'Contraseña incorrecta' });
    if (!u.verified) return res.status(403).json({ ok: false, error: 'Cuenta no verificada' });

    // crear sesión
    req.session.user = { id: u.id, email: u.email };
    req.session.save(() => {});

    // token JWT opcional
    const token = jsonwebtoken.sign({ id: u.id, email: u.email }, process.env.JWT_SECRET || 'jwtsecret', { expiresIn: '2h' });
    res.json({ ok: true, token });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Error en login' }); }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ ok: false, error: 'No se pudo cerrar la sesión' });
    res.clearCookie(process.env.SESSION_NAME || 'sid');
    res.json({ ok: true, message: 'Sesión cerrada' });
  });
});

// RUTAS PROTEGIDAS (ejemplo) - usan sesión
app.get('/perfil', requireSession, (req, res) => {
  res.json({ ok: true, usuario: req.session.user });
});

// -------------------------------
// ENDPOINTS BLOCKCHAIN (ejemplos resumidos)
// -------------------------------
app.get('/cadena', requireSession, async (req, res) => {
  try {
    const r = await db.query('SELECT * FROM blockchain_nonces ORDER BY block_id ASC');
    const bloques = r.rows;
    // correcciones simples
    for (let i = 0; i < bloques.length; i++) {
      let b = bloques[i];
      const hash_calc = calcHash(b);
      if (hash_calc !== b.hash) {
        await db.query('UPDATE blockchain_nonces SET hash=$1 WHERE block_id=$2', [hash_calc, b.block_id]);
        b.hash = hash_calc;
      }
      if (i > 0) {
        const prev = bloques[i - 1];
        if (b.previous_hash !== prev.hash) {
          await db.query('UPDATE blockchain_nonces SET previous_hash=$1 WHERE block_id=$2', [prev.hash, b.block_id]);
          b.previous_hash = prev.hash;
        }
      }
    }
    res.json(bloques.map(b => ({ ...b, valido: true })));
  } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Error obteniendo cadena' }); }
});

app.post('/crearBloque', requireSession, async (req, res) => {
  try {
    const { nonce, block_id } = req.body;
    if (typeof nonce === 'undefined') return res.status(400).json({ ok: false, error: "Falta 'nonce'" });
    const new_block_id = block_id ? block_id : Date.now();
    const ultimo = await db.query('SELECT * FROM blockchain_nonces ORDER BY block_id DESC LIMIT 1');
    const previous_hash = ultimo.rows.length ? ultimo.rows[0].hash : '0';
    await db.query('INSERT INTO blockchain_nonces (block_id, nonce, previous_hash) VALUES ($1,$2,$3)', [new_block_id, nonce, previous_hash]);
    const r = await db.query('SELECT * FROM blockchain_nonces WHERE block_id=$1', [new_block_id]);
    const bloque = r.rows[0];
    const recalculado = calcHash(bloque);
    await db.query('UPDATE blockchain_nonces SET hash=$1 WHERE block_id=$2', [recalculado, new_block_id]);
    bloque.hash = recalculado;
    res.json({ ok: true, bloque });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Error creando bloque' }); }
});

// -------------------------------
// START SERVER (HTTP + optional HTTPS)
// -------------------------------
const HTTP_PORT = Number(process.env.PORT || 3000);
let httpServer;
let httpsServer;

if (hasHttpsCert) {
  // si existen certificados en /keys, inicia HTTPS
  const cert = fs.readFileSync(path.join(keyPath, 'cert.pem'));
  const key = fs.readFileSync(path.join(keyPath, 'key.pem'));
  httpsServer = https.createServer({ key, cert }, app);
  httpsServer.listen(443, () => console.log('HTTPS running on port 443'));
  // opcional: escucha HTTP y redirige a HTTPS
  httpServer = http.createServer((req, res) => {
    res.writeHead(301, { Location: 'https://' + req.headers.host + req.url });
    res.end();
  });
  httpServer.listen(80, () => console.log('HTTP redirector running on port 80 -> redirects to HTTPS'));
} else {
  // sin certificados: arranca HTTP
  httpServer = http.createServer(app);
  httpServer.listen(HTTP_PORT, () => console.log(`HTTP running on port ${HTTP_PORT}`));
  if (isProduction) console.warn('Advertencia: modo producción sin HTTPS. Usa un proxy (nginx, Cloudflare, Heroku) para TLS.');
}


