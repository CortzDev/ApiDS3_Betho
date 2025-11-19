require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");

// Middlewares
const { authRequired, adminOnly, proveedorOnly } = require("./public/middlewares/auth.js");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: true, credentials: true }));
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));
app.use(express.static(path.join(__dirname, "public"))); // Servir archivos estáticos

// --------------------- DB ---------------------
const db = new Pool({
  user: process.env.PGUSER || "postgres",
  password: process.env.PGPASSWORD || "12345",
  database: process.env.PGDATABASE || "railway",
  host: process.env.PGHOST || "localhost",
  port: parseInt(process.env.PGPORT || "5432")
});

// --------------------- Blockchain utils ---------------------
function sha256(x) {
  return crypto.createHash("sha256").update(x).digest("hex");
}

async function obtenerHashPrevio() {
  const r = await db.query("SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1");
  return r.rows.length ? r.rows[0].hash_actual : "0".repeat(64);
}

async function registrarEnBlockchain(operacion, dataObj) {
  const previo = await obtenerHashPrevio();
  const timestamp = new Date().toISOString();
  const payload = { operacion, data: dataObj, timestamp };
  const actual = sha256(previo + JSON.stringify(payload));

  await db.query(
    `INSERT INTO blockchain (nonce, data, hash_actual, hash_anterior, fecha)
     VALUES ($1,$2,$3,$4,$5)`,
    [operacion, JSON.stringify(dataObj), actual, previo, timestamp]
  );
}

// --------------------- RUTAS ---------------------

// ======= PÁGINA POR DEFECTO: login.html =======
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Registro de usuarios
app.post("/api/register", async (req, res) => {
  const { nombre, email, password, rol } = req.body;
  try {
    const exist = await db.query("SELECT id FROM usuarios WHERE email=$1", [email]);
    if (exist.rows.length) return res.status(400).json({ ok: false, error: "Usuario ya existe" });

    const rolRow = await db.query("SELECT id FROM roles WHERE nombre=$1", [rol]);
    if (!rolRow.rows.length) return res.status(400).json({ ok: false, error: "Rol inválido" });

    const hashed = await bcrypt.hash(password, 10);

    const rUser = await db.query(
      `INSERT INTO usuarios(nombre,email,password,rol_id) 
       VALUES ($1,$2,$3,$4) RETURNING id, nombre, email`,
      [nombre, email, hashed, rolRow.rows[0].id]
    );

    await registrarEnBlockchain("CREAR_USUARIO", { nombre, email });
    res.json({ ok: true, usuario: rUser.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// Login (crea proveedor automáticamente si no existe)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const q = `
      SELECT u.id, u.nombre, u.password, r.nombre AS rol
      FROM usuarios u 
      JOIN roles r ON r.id = u.rol_id
      WHERE email=$1
    `;
    const r = await db.query(q, [email]);

    if (!r.rows.length) return res.json({ ok: false });

    const user = r.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ ok: false });

    // Crear fila proveedor si es proveedor
    if (user.rol === "proveedor") {
      await db.query(
        `INSERT INTO proveedor (usuario_id)
         VALUES ($1)
         ON CONFLICT (usuario_id) DO NOTHING`,
        [user.id]
      );
    }

    const token = jwt.sign(
      { id: user.id, nombre: user.nombre, rol: user.rol },
      process.env.JWT_SECRET || "jwtsecret",
      { expiresIn: "2h" }
    );

    res.json({ ok: true, token, usuario: { id: user.id, nombre: user.nombre, rol: user.rol } });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// Perfil
app.get("/api/perfil", authRequired, async (req, res) => {
  try {
    const r = await db.query(
      `SELECT u.id, u.nombre, u.email, r.nombre AS rol
       FROM usuarios u 
       JOIN roles r ON r.id = u.rol_id
       WHERE u.id=$1`,
      [req.user.id]
    );
    res.json({ ok: true, usuario: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// Registro proveedor
app.post("/api/register-proveedor", async (req, res) => {
  const { nombre, email, password, empresa, telefono, direccion } = req.body;

  try {
    const exist = await db.query("SELECT id FROM usuarios WHERE email=$1", [email]);
    if (exist.rows.length) return res.status(400).json({ ok: false, error: "Email ya registrado" });

    const rolProv = await db.query("SELECT id FROM roles WHERE nombre='proveedor'");
    const hashed = await bcrypt.hash(password, 10);

    const rUser = await db.query(
      `INSERT INTO usuarios(nombre,email,password,rol_id)
       VALUES ($1,$2,$3,$4) RETURNING id`,
      [nombre, email, hashed, rolProv.rows[0].id]
    );

    await db.query(
      `INSERT INTO proveedor(usuario_id, empresa, telefono, direccion)
       VALUES ($1,$2,$3,$4)`,
      [rUser.rows[0].id, empresa, telefono, direccion]
    );

    res.json({ ok: true, message: "Proveedor creado" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// CREAR PRODUCTO
app.post("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  const { nombre, descripcion, categoria_id, precio } = req.body;

  try {
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);

    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const r = await db.query(
      `INSERT INTO productos(nombre, descripcion, categoria_id, proveedor_id, precio)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [nombre, descripcion, categoria_id, proveedorId, precio]
    );

    res.json({ ok: true, producto: r.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// LISTAR PRODUCTOS DE PROVEEDOR
app.get("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  try {
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);

    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const productos = await db.query(
      "SELECT * FROM productos WHERE proveedor_id=$1",
      [proveedorId]
    );

    res.json({ ok: true, productos: productos.rows });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// ===================== DASHBOARDS =====================
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/proveedor/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "proveedor.html"));
});

// --------------------- Init DB ---------------------
async function initDb() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS roles (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(50) UNIQUE NOT NULL
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(100) NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      rol_id INT NOT NULL REFERENCES roles(id)
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS proveedor (
      id SERIAL PRIMARY KEY,
      usuario_id INT NOT NULL UNIQUE REFERENCES usuarios(id) ON DELETE CASCADE,
      empresa VARCHAR(150),
      telefono VARCHAR(30),
      direccion TEXT,
      creado_en TIMESTAMP DEFAULT NOW()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS categorias (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(100) UNIQUE NOT NULL,
      descripcion TEXT
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS productos (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(150) NOT NULL,
      descripcion TEXT,
      categoria_id INT NOT NULL REFERENCES categorias(id),
      proveedor_id INT NOT NULL REFERENCES proveedor(id),
      precio NUMERIC(12,2) NOT NULL,
      stock INT NOT NULL DEFAULT 0
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS blockchain (
      id SERIAL PRIMARY KEY,
      nonce VARCHAR(150) NOT NULL,
      data JSONB NOT NULL,
      hash_actual TEXT NOT NULL,
      hash_anterior TEXT,
      fecha TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  // Inicializar roles
  const r = await db.query("SELECT COUNT(*) FROM roles");
  if (parseInt(r.rows[0].count) === 0) {
    await db.query(`
      INSERT INTO roles(nombre) VALUES ('usuario'),('admin'),('proveedor')
    `);
  }
}

// --------------------- Main ---------------------
async function main() {
  await initDb();
  app.listen(3000, () => console.log("Servidor JWT en http://localhost:3000"));
}

main().catch(err => console.error(err));
