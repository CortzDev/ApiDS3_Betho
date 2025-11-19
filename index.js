// servidor.js
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

// CORS + SECURITY
app.use(cors({ origin: true, credentials: true }));
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false }));

// servir frontend
app.use(express.static(path.join(__dirname, 'public')));


let db;
try {
  db = new Pool({
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD ||'SccSUkutVxtIRJwcfrLsmZBYDYPxGEbP',
    database: process.env.PGDATABASE || 'railway',
    host: process.env.PGHOST || 'turntable.proxy.rlwy.net',
    port: parseInt(process.env.PGPORT || '40300', 10)
  });
  console.log("PostgreSQL listo");
} catch (err) {
  console.error("DB ERROR ❌", err);
  process.exit(1);
}


app.use(session({
  store: new pgSession({ pool: db, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || '4895f550f7ec4edad9eca3ef9928e585032ff513c9ffd0da3701b112dc5da2e29eb43fbad17c9e1262a3ae5d8d6cf5f3e169c3885f51f2161d266975b7199e87',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 2, secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax' }
}));

let smtpTransport, smtpReady = false;
try {
  smtpTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  smtpTransport.verify(err => {
    if (err) console.error("SMTP ERROR ❌", err);
    else { smtpReady = true; console.log("SMTP READY ✅"); }
  });
} catch (err) { console.error("SMTP CONFIG ❌", err); }

async function sendOtpEmail(email, otp) {
  if (!smtpReady) { console.warn("SMTP no configurado, OTP devuelto"); return false; }
  try {
    await smtpTransport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: email,
      subject: "Tu código de verificación (OTP)",
      text: `Tu código es: ${otp}`
    });
    return true;
  } catch (err) { console.error("SMTP send error:", err); return false; }
}


function sessionAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ ok: false, error: 'No autorizado' });
  next();
}

async function isAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ ok: false, error: 'No autorizado' });

  if (req.session.user.rol !== 'admin') return res.status(403).json({ ok: false, error: 'Requiere rol admin' });
  next();
}


function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

async function obtenerHashPrevio() {
  const r = await db.query("SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1");
  return (r.rows.length ? r.rows[0].hash_actual : '0'.repeat(64));
}

async function registrarEnBlockchain(operacion, dataObj) {
  const hashPrevio = await obtenerHashPrevio();
  const timestamp = new Date().toISOString();
  const payload = { operacion, data: dataObj, timestamp };
  const hashActual = sha256(hashPrevio + JSON.stringify(payload));
  await db.query(
    `INSERT INTO blockchain (nonce, data, hash_actual, hash_anterior, fecha)
     VALUES ($1,$2,$3,$4,$5)`,
    [operacion, JSON.stringify(dataObj), hashActual, hashPrevio, timestamp]
  );
  return { hashPrevio, hashActual, payload };
}


app.post("/register", async (req, res) => {
  const { nombre = '', email, password } = req.body;
  if (!email || !password) return res.status(400).json({ ok: false, error: "Email y password obligatorios" });

  try {
    const exist = await db.query("SELECT id FROM usuarios WHERE email=$1", [email]);
    if (exist.rows.length > 0) return res.status(400).json({ ok: false, error: "Usuario ya existe" });

    const hashed = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60000);

    // obtener rol 'usuario' (asumimos que tabla roles ya tiene ambos)
    const rolRow = await db.query("SELECT id FROM roles WHERE nombre='usuario' LIMIT 1");
    const rolId = (rolRow.rows[0] && rolRow.rows[0].id) ? rolRow.rows[0].id : null;

    await db.query(
      `INSERT INTO usuarios (nombre, email, password, rol_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [nombre, email, hashed, rolId, false, otp, expires]
    );

    await sendOtpEmail(email, otp);

    // Registrar evento en blockchain (opcional: no contiene password)
    await registrarEnBlockchain('CREAR_USUARIO', { email, nombre });

    res.json({ ok: true, message: "Usuario registrado. Verifica tu correo", otp: smtpReady ? undefined : otp });
  } catch (err) {
    console.error("register error:", err);
    res.status(500).json({ ok: false, error: "Error en servidor" });
  }
});

app.post("/verify", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ ok: false, error: "Email" });

  try {
    const r = await db.query("SELECT id FROM usuarios WHERE email=$1 LIMIT 1", [email]);
    if (!r.rows.length) return res.status(400).json({ ok: false, error: "Usuario no encontrado" });
    const u = r.rows[0];
    if (u.otp_code !== otp || new Date(u.otp_expires) < new Date()) return res.status(400).json({ ok: false, error: "OTP inválido o expirado" });

   // await db.query("UPDATE usuarios SET verified=true, otp_code=NULL, otp_expires=NULL WHERE id=$1", [u.id]);

    await registrarEnBlockchain('VERIFICAR_USUARIO', { email });

    res.json({ ok: true, message: "Cuenta verificada" });
  } catch (err) {
    console.error("verify error:", err);
    res.status(500).json({ ok: false, error: "Error en servidor" });
  }
});

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const query = `
            SELECT u.id, u.nombre, r.nombre AS rol, u.password 
            FROM usuarios u
            JOIN roles r ON r.id = u.rol_id
            WHERE u.email = $1
        `;

        const result = await pool.query(query, [email]);

        if (result.rows.length === 0) {
            return res.json({ ok: false });
        }

        const user = result.rows[0];

        if (user.password !== password) {
            return res.json({ ok: false });
        }

        return res.json({
            ok: true,
            usuario: {
                id: user.id,
                nombre: user.nombre,
                rol: user.rol
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ ok: false });
    }
});



app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ ok: false, error: "No se pudo cerrar la sesión" });
    res.clearCookie('connect.sid');
    res.json({ ok: true, message: 'Sesión cerrada' });
  });
});

app.get("/perfil", sessionAuth, async (req, res) => {
  try {
    // trae rol y datos
    const r = await db.query(
      `SELECT u.id, u.nombre, u.email, r.nombre AS rol
       FROM usuarios u
       LEFT JOIN roles r ON u.rol_id = r.id
       WHERE u.id = $1 LIMIT 1`,
      [req.session.user.id]
    );
    if (!r.rows.length) return res.status(404).json({ ok: false, error: 'Usuario no encontrado' });
    res.json({ ok: true, usuario: r.rows[0] });
  } catch (err) {
    console.error("perfil error:", err);
    res.status(500).json({ ok: false, error: "Error en servidor" });
  }
});


app.get("/categorias", sessionAuth, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM categorias ORDER BY id ASC");
    res.json({ ok: true, categorias: r.rows });
  } catch (err) {
    console.error("categorias GET error:", err);
    res.status(500).json({ ok: false });
  }
});

app.post("/categorias", sessionAuth, async (req, res) => {
  const { nombre, descripcion } = req.body;
  try {
    const r = await db.query("INSERT INTO categorias(nombre, descripcion) VALUES($1,$2) RETURNING *", [nombre, descripcion]);
    await registrarEnBlockchain('CREAR_CATEGORIA', { categoria: r.rows[0] });
    res.json({ ok: true, categoria: r.rows[0] });
  } catch (err) {
    console.error("categorias POST error:", err);
    res.status(500).json({ ok: false });
  }
});

app.put("/categorias/:id", sessionAuth, isAdmin, async (req, res) => {
  const id = req.params.id;
  const { nombre, descripcion } = req.body;
  try {
    const r = await db.query("UPDATE categorias SET nombre=$1, descripcion=$2 WHERE id=$3 RETURNING *", [nombre, descripcion, id]);
    await registrarEnBlockchain('ACTUALIZAR_CATEGORIA', { categoria: r.rows[0] });
    res.json({ ok: true, categoria: r.rows[0] });
  } catch (err) {
    console.error("categorias PUT error:", err);
    res.status(500).json({ ok: false });
  }
});

app.delete("/categorias/:id", sessionAuth, isAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await db.query("DELETE FROM categorias WHERE id=$1", [id]);
    await registrarEnBlockchain('ELIMINAR_CATEGORIA', { id });
    res.json({ ok: true, message: "Categoría eliminada" });
  } catch (err) {
    console.error("categorias DELETE error:", err);
    res.status(500).json({ ok: false });
  }
});


app.get("/productos", sessionAuth, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM productos ORDER BY id ASC");
    res.json({ ok: true, productos: r.rows });
  } catch (err) {
    console.error("productos GET error:", err);
    res.status(500).json({ ok: false });
  }
});

app.get("/productos/:id", sessionAuth, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM productos WHERE id=$1", [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ ok: false, error: "Producto no encontrado" });
    res.json({ ok: true, producto: r.rows[0] });
  } catch (err) {
    console.error("productos/:id error:", err);
    res.status(500).json({ ok: false });
  }
});

app.post("/productos", sessionAuth, async (req, res) => {
  const { categoria_id, nombre, descripcion, precio, stock } = req.body;
  try {
    const r = await db.query(
      `INSERT INTO productos(categoria_id, nombre, descripcion, precio, stock)
       VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [categoria_id, nombre, descripcion, precio, stock]
    );
    await registrarEnBlockchain('CREAR_PRODUCTO', { producto: r.rows[0], usuario: req.session.user.id });
    res.json({ ok: true, producto: r.rows[0] });
  } catch (err) {
    console.error("productos POST error:", err);
    res.status(500).json({ ok: false });
  }
});

app.put("/productos/:id", sessionAuth, isAdmin, async (req, res) => {
  const id = req.params.id;
  const { categoria_id, nombre, descripcion, precio, stock } = req.body;
  try {
    const r = await db.query(
      `UPDATE productos SET categoria_id=$1, nombre=$2, descripcion=$3, precio=$4, stock=$5 WHERE id=$6 RETURNING *`,
      [categoria_id, nombre, descripcion, precio, stock, id]
    );
    await registrarEnBlockchain('ACTUALIZAR_PRODUCTO', { producto: r.rows[0], admin: req.session.user.id });
    res.json({ ok: true, producto: r.rows[0] });
  } catch (err) {
    console.error("productos PUT error:", err);
    res.status(500).json({ ok: false });
  }
});

app.delete("/productos/:id", sessionAuth, isAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await db.query("DELETE FROM productos WHERE id=$1", [id]);
    await registrarEnBlockchain('ELIMINAR_PRODUCTO', { id, admin: req.session.user.id });
    res.json({ ok: true, message: "Producto eliminado" });
  } catch (err) {
    console.error("productos DELETE error:", err);
    res.status(500).json({ ok: false });
  }
});


app.post("/ventas", sessionAuth, isAdmin, async (req, res) => {
  const { detalles } = req.body; // detalles = [{ producto_id, cantidad, precio_unitario }, ...]
  if (!Array.isArray(detalles) || detalles.length === 0) return res.status(400).json({ ok: false, error: "Detalles requeridos" });

  try {
    // calcular total
    let total = 0;
    for (const it of detalles) total += Number(it.precio_unitario) * Number(it.cantidad);

    // insertar venta
    const ventaRes = await db.query("INSERT INTO ventas(usuario_id, total) VALUES($1,$2) RETURNING *", [req.session.user.id, total]);
    const ventaId = ventaRes.rows[0].id;

    // insertar detalles
    const insertDetallePromises = detalles.map(it =>
      db.query("INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario) VALUES($1,$2,$3,$4)", [ventaId, it.producto_id, it.cantidad, it.precio_unitario])
    );
    await Promise.all(insertDetallePromises);

    // opcional: reducir stock
    for (const it of detalles) {
      await db.query("UPDATE productos SET stock = GREATEST(stock - $1, 0) WHERE id=$2", [it.cantidad, it.producto_id]);
    }

    // registrar en blockchain
    const data = { venta_id: ventaId, total, usuario: req.session.user.id, detalles };
    await registrarEnBlockchain('VENTA_REGISTRADA', data);

    res.json({ ok: true, venta: ventaRes.rows[0] });
  } catch (err) {
    console.error("ventas POST error:", err);
    res.status(500).json({ ok: false, error: "Error registrando venta" });
  }
});

app.get("/ventas", sessionAuth, isAdmin, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM ventas ORDER BY id DESC");
    res.json({ ok: true, ventas: r.rows });
  } catch (err) {
    console.error("ventas GET error:", err);
    res.status(500).json({ ok: false });
  }
});

app.get("/ventas/:id", sessionAuth, isAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const r = await db.query("SELECT * FROM ventas WHERE id=$1", [id]);
    if (!r.rows.length) return res.status(404).json({ ok: false, error: "Venta no encontrada" });
    const detalles = await db.query("SELECT * FROM venta_detalle WHERE venta_id=$1", [id]);
    res.json({ ok: true, venta: r.rows[0], detalles: detalles.rows });
  } catch (err) {
    console.error("ventas/:id error:", err);
    res.status(500).json({ ok: false });
  }
});


app.get("/blockchain", sessionAuth, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM blockchain ORDER BY id ASC");
    res.json({ ok: true, blockchain: r.rows });
  } catch (err) {
    console.error("blockchain GET error:", err);
    res.status(500).json({ ok: false });
  }
});

app.get("/blockchain/validar", sessionAuth, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM blockchain ORDER BY id ASC");
    const chain = r.rows;
    let valid = true;
    for (let i = 0; i < chain.length; i++) {
      const row = chain[i];
      const computed = sha256((i === 0 ? '0'.repeat(64) : chain[i - 1].hash_actual) + JSON.stringify({ operacion: row.operacion, data: row.data, timestamp: row.fecha }));
      if (computed !== row.hash_actual) { valid = false; break; }
      if (i > 0 && row.hash_anterior !== chain[i - 1].hash_actual) { valid = false; break; }
    }
    res.json({ ok: true, valid });
  } catch (err) {
    console.error("blockchain/validar error:", err);
    res.status(500).json({ ok: false });
  }
});

async function initDb() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS roles (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(50) UNIQUE NOT NULL
      );
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(150),
        email VARCHAR(255) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol_id INT REFERENCES roles(id),
        verified BOOLEAN DEFAULT false,
        otp_code VARCHAR(10),
        otp_expires TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS categorias (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(150) UNIQUE NOT NULL,
        descripcion TEXT
      );
      CREATE TABLE IF NOT EXISTS productos (
        id SERIAL PRIMARY KEY,
        categoria_id INT REFERENCES categorias(id),
        nombre VARCHAR(255) NOT NULL,
        descripcion TEXT,
        precio NUMERIC(12,2) NOT NULL DEFAULT 0,
        stock INT NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS ventas (
        id SERIAL PRIMARY KEY,
        usuario_id INT REFERENCES usuarios(id),
        fecha TIMESTAMP DEFAULT NOW(),
        total NUMERIC(12,2) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS venta_detalle (
        id SERIAL PRIMARY KEY,
        venta_id INT REFERENCES ventas(id),
        producto_id INT REFERENCES productos(id),
        cantidad INT NOT NULL,
        precio_unitario NUMERIC(12,2) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS blockchain (
        id SERIAL PRIMARY KEY,
        nonce VARCHAR(150) NOT NULL,
        data JSONB NOT NULL,
        hash_actual TEXT NOT NULL,
        hash_anterior TEXT,
        fecha TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS session (
        sid varchar NOT NULL COLLATE "default",
        sess json NOT NULL,
        expire timestamp(6) NOT NULL
      ) WITH (OIDS=FALSE);
      CREATE INDEX IF NOT EXISTS session_expire_idx ON session (expire);
    `);

    // insertar roles si no existen
    const rolesRes = await db.query("SELECT COUNT(*) as cnt FROM roles");
    if (parseInt(rolesRes.rows[0].cnt, 10) === 0) {
      await db.query("INSERT INTO roles(nombre) VALUES('usuario'),('admin')");
      console.log("Roles iniciales creados");
    }
  } catch (err) {
    console.error("initDb error:", err);
  }
}


initDb().catch(e => console.error(e));


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
