// ===============================
// SERVIDOR COMPLETO CON SESIONES
// ===============================

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
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

// ===============================
// HELMET + CSP COMPATIBLE
// ===============================
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": [
          "'self'",
          "'unsafe-inline'",               // permite scripts inline
          "https://cdn.tailwindcss.com"    // permite tailwind CDN
        ],
        "style-src": ["'self'", "'unsafe-inline'"], // necesario para tailwind
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"],
      },
    },
  })
);

// ===============================
// RATE LIMIT (ANTI ATAQUES)
// ===============================
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// ===============================
// SERVIR FRONTEND
// ===============================
app.use(express.static(path.join(__dirname, 'public')));

// ===============================
// BASE DE DATOS
// ===============================
let db;
try {
  db = new Pool({
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD || '',
    database: process.env.PGDATABASE || 'interblockchain',
    host: process.env.PGHOST || 'localhost',
    port: parseInt(process.env.PGPORT || '5432', 10),
  });
  console.log("PostgreSQL listo");
} catch (error) {
  console.error("PostgreSQL con error", error);
}

// ===============================
// SESIONES
// ===============================
app.use(
  session({
    store: new pgSession({
      pool: db,
      tableName: 'session',
    }),
    secret: process.env.SESSION_SECRET || 'supersecreto123',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 2, // 2 horas
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

// ===============================
// EMAIL (SMTP)
// ===============================
let smtpTransport;
let smtpReady = false;

try {
  smtpTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  smtpTransport.verify((err) => {
    if (err) {
      console.error("SMTP ERROR ❌", err);
    } else {
      smtpReady = true;
      console.log("SMTP READY ✅ Conexión correcta a SMTP host");
    }
  });
} catch (error) {
  console.error("SMTP CONFIG FAILED ❌", error);
}

// enviar OTP
async function sendOtpEmail(email, otp) {
  if (!smtpReady) {
    console.warn("SMTP no configurado. OTP devuelto en respuesta (solo pruebas)");
    return false;
  }

  try {
    await smtpTransport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: email,
      subject: "Tu código de verificación (OTP)",
      text: `Tu código es: ${otp}`,
    });

    return true;
  } catch (error) {
    console.error("Error enviando correo:", error);
    return false;
  }
}

// ===============================
// REGISTRO
// ===============================
app.post("/register", async (req, res) => {
  console.log("🔵 /register CALLED");
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ ok: false, error: "Email y password obligatorios" });
  }

  try {
    const existing = await db.query("SELECT * FROM usuarios WHERE email=$1", [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ ok: false, error: "Usuario ya existe" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60000);

    await db.query(
      "INSERT INTO usuarios (email, password, verified, otp_code, otp_expires) VALUES ($1,$2,$3,$4,$5)",
      [email, hashed, false, otp, expires]
    );

    await sendOtpEmail(email, otp);
    res.json({
      ok: true,
      message: "Usuario registrado. Verifica tu correo",
      otp: smtpReady ? undefined : otp,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Error en servidor" });
  }
});

// ===============================
// VERIFICAR OTP
// ===============================
app.post("/verify", async (req, res) => {
  console.log("🔵 /verify CALLED");
  const { email, otp } = req.body;

  try {
    const result = await db.query("SELECT * FROM usuarios WHERE email=$1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ ok: false, error: "Usuario no encontrado" });
    }

    const u = result.rows[0];
    if (u.otp_code !== otp || new Date(u.otp_expires) < new Date()) {
      return res.status(400).json({ ok: false, error: "OTP inválido o expirado" });
    }

    await db.query(
      "UPDATE usuarios SET verified=true, otp_code=NULL, otp_expires=NULL WHERE email=$1",
      [email]
    );
    res.json({ ok: true, message: "Cuenta verificada" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Error en servidor" });
  }
});

// ===============================
// LOGIN
// ===============================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM usuarios WHERE email=$1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ ok: false, error: "Usuario no existe" });
    }

    const u = result.rows[0];
    const match = await bcrypt.compare(password, u.password);
    if (!match) {
      return res.status(400).json({ ok: false, error: "Password incorrecto" });
    }

    if (!u.verified) {
      return res.status(400).json({ ok: false, error: "Debes verificar tu correo" });
    }

    req.session.user = {
      id: u.id,
      email: u.email,
    };

    const token = jsonwebtoken.sign({ id: u.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ ok: true, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Error en servidor" });
  }
});

// ===============================
// PERFIL
// ===============================
app.get("/perfil", sessionAuth, (req, res) => {
  res.json({ ok: true, usuario: req.session.user });
});

// ===============================
// LOGOUT
// ===============================
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ ok: false, error: "No se pudo cerrar la sesión" });

    res.clearCookie("connect.sid");
    res.json({ ok: true, message: "Sesión cerrada" });
  });
});

// ===============================
// SERVIDOR
// ===============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
