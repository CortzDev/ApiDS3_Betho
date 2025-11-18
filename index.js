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

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"],
      },
    },
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Carpeta pública
app.use(express.static(path.join(__dirname, 'public')));

let db;
try {
  db = new Pool({
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD || 'SccSUkutVxtIRJwcfrLsmZBYDYPxGEbP',
    database: process.env.PGDATABASE || 'railway',
    host: process.env.PGHOST || 'turntable.proxy.rlwy.net',
    port: parseInt(process.env.PGPORT || '40300', 10),
  });
  console.log("PostgreSQL listo");
} catch (error) {
  console.error("PostgreSQL con error", error);
}

app.use(
  session({
    store: new pgSession({
      pool: db,
      tableName: 'session',
    }),
    secret: process.env.SESSION_SECRET || '4895f550f7ec4edad9eca3ef9928e585032ff513c9ffd0da3701b112dc5da2e29eb43fbad17c9e1262a3ae5d8d6cf5f3e169c3885f51f2161d266975b7199e87',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 2,
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

function sessionAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ ok: false, error: 'No autorizado (sesión expirada o inexistente)' });
  }
  next();
}

// --- RUTAS DE USUARIO (tu código original) ---
// /register, /verify, /login, /perfil, /logout
// (Aquí irían exactamente como los tienes)

// --- NUEVAS RUTAS PARA DASHBOARD ---

// Datos de ejemplo de blockchain
let blockchain = [
  { block_id: 1, nonce: 123, hash: "abc", previous_hash: "000", valido: true },
  { block_id: 2, nonce: 456, hash: "def", previous_hash: "abc", valido: true },
  { block_id: 3, nonce: 789, hash: "ghi", previous_hash: "def", valido: false },
];

// /cadena → devuelve JSON
app.get('/cadena', sessionAuth, (req, res) => {
  res.json(blockchain);
});

// /validar → valida la cadena
app.get('/validar', sessionAuth, (req, res) => {
  const ok = blockchain.every(b => b.valido);
  res.json(ok ? { ok: true, message: 'La cadena es válida' } : { ok: false, error: 'Hay bloques alterados' });
});

// /reporte-json → descarga JSON
app.get('/reporte-json', sessionAuth, (req, res) => {
  const jsonData = JSON.stringify(blockchain, null, 2);
  res.setHeader('Content-Disposition', 'attachment; filename="blockchain.json"');
  res.setHeader('Content-Type', 'application/json');
  res.send(jsonData);
});

// /reporte-pdf → PDF mínimo de ejemplo
app.get('/reporte-pdf', sessionAuth, (req, res) => {
  const pdfPath = path.join(__dirname, 'example.pdf');
  const fs = require('fs');
  if (!fs.existsSync(pdfPath)) {
    fs.writeFileSync(pdfPath, Buffer.from('%PDF-1.4\n%EOF'));
  }
  res.setHeader('Content-Disposition', 'attachment; filename="blockchain.pdf"');
  res.setHeader('Content-Type', 'application/pdf');
  res.sendFile(pdfPath);
});

// --- FIN DE RUTAS DASHBOARD ---

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
