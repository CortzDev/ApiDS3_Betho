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
app.use(express.static(path.join(__dirname, "public")));

// --------------------- DB ---------------------
const db = new Pool({
  user: process.env.PGUSER || "postgres",
  password: process.env.PGPASSWORD || "SccSUkutVxtIRJwcfrLsmZBYDYPxGEbP",
  database: process.env.PGDATABASE || "railway",
  host: process.env.PGHOST || "turntable.proxy.rlwy.net",
  port: parseInt(process.env.PGPORT || "40300")
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

// --------------------- Rutas ---------------------

// Registro de usuarios
app.post("/api/register", async (req, res) => {
  const { nombre, email, password, rol } = req.body;
  try {
    const exist = await db.query("SELECT id FROM usuarios WHERE email=$1", [email]);
    if (exist.rows.length) return res.status(400).json({ ok: false, error: "Usuario ya existe" });

    const rolRow = await db.query("SELECT id FROM roles WHERE nombre=$1", [rol]);
    if (!rolRow.rows.length) return res.status(400).json({ ok: false, error: "Rol inválido" });

    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO usuarios(nombre,email,password,rol_id) VALUES ($1,$2,$3,$4)`,
      [nombre, email, hashed, rolRow.rows[0].id]
    );

    await registrarEnBlockchain("CREAR_USUARIO", { nombre, email });
    res.json({ ok: true, message: "Usuario registrado correctamente" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const q = `
      SELECT u.id, u.nombre, u.password, r.nombre AS rol
      FROM usuarios u 
      JOIN roles r ON r.id = u.rol_id
      WHERE email=$1`;
    const r = await db.query(q, [email]);
    if (!r.rows.length) return res.json({ ok: false });

    const user = r.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ ok: false });

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
  const { nombre, email, password } = req.body;
  try {
    const exist = await db.query("SELECT id FROM usuarios WHERE email=$1", [email]);
    if (exist.rows.length) return res.status(400).json({ ok: false, error: "Email ya registrado" });

    const rolRow = await db.query("SELECT id FROM roles WHERE nombre='proveedor'");
    if (!rolRow.rows.length) return res.status(500).json({ ok: false, error: "Rol proveedor no existe" });

    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO usuarios(nombre,email,password,rol_id) VALUES ($1,$2,$3,$4)`,
      [nombre, email, hashed, rolRow.rows[0].id]
    );

    await registrarEnBlockchain("CREAR_PROVEEDOR", { nombre, email });
    res.json({ ok: true, message: "Proveedor registrado correctamente" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// Productos proveedor
app.post("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  const { nombre, descripcion, categoria_id, precio } = req.body;
  try {
    const r = await db.query(
      `INSERT INTO productos(nombre, descripcion, categoria_id, proveedor_id, precio)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [nombre, descripcion, categoria_id, req.user.id, precio]
    );
    await registrarEnBlockchain("CREAR_PRODUCTO", { proveedor: req.user.nombre, producto: r.rows[0] });
    res.json({ ok: true, producto: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

app.get("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM productos WHERE proveedor_id=$1", [req.user.id]);
    res.json({ ok: true, productos: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// Obtener categorías
app.get("/api/categorias", authRequired, async (req, res) => {
  try {
    const r = await db.query("SELECT id, nombre FROM categorias ORDER BY id");
    res.json({ ok: true, categorias: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error al obtener categorías" });
  }
});

// CRUD roles (admin)
app.get("/roles", authRequired, adminOnly, async (req, res) => {
  const r = await db.query("SELECT * FROM roles ORDER BY id");
  res.json({ ok: true, roles: r.rows });
});

app.post("/roles", authRequired, adminOnly, async (req, res) => {
  const { nombre } = req.body;
  await db.query("INSERT INTO roles(nombre) VALUES($1)", [nombre]);
  res.json({ ok: true, message: "Rol creado" });
});

app.put("/roles/:id", authRequired, adminOnly, async (req, res) => {
  const { nombre } = req.body;
  await db.query("UPDATE roles SET nombre=$1 WHERE id=$2", [nombre, req.params.id]);
  res.json({ ok: true, message: "Rol actualizado" });
});

app.delete("/roles/:id", authRequired, adminOnly, async (req, res) => {
  await db.query("DELETE FROM roles WHERE id=$1", [req.params.id]);
  res.json({ ok: true, message: "Rol eliminado" });
});

// Dashboard admin
app.get("/dashboard", authRequired, adminOnly, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// Dashboard proveedor
app.get("/proveedor/dashboard", authRequired, proveedorOnly, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "proveedor.html"));
});

// --------------------- Init DB ---------------------
async function initDb() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS roles (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(50) UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(100) NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      rol_id INT NOT NULL REFERENCES roles(id)
    );
    CREATE TABLE IF NOT EXISTS productos (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(150) NOT NULL,
      descripcion TEXT,
      categoria_id INT NOT NULL,
      proveedor_id INT NOT NULL REFERENCES usuarios(id),
      precio NUMERIC(12,2) NOT NULL
    );
    CREATE TABLE IF NOT EXISTS blockchain (
      id SERIAL PRIMARY KEY,
      nonce VARCHAR(150) NOT NULL,
      data JSONB NOT NULL,
      hash_actual TEXT NOT NULL,
      hash_anterior TEXT,
      fecha TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS categorias (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(100) NOT NULL
    );
  `);

  const r = await db.query("SELECT COUNT(*) FROM roles");
  if (parseInt(r.rows[0].count) === 0) {
    await db.query("INSERT INTO roles(nombre) VALUES('usuario'),('admin'),('proveedor')");
  }
}

// --------------------- Main ---------------------
async function main() {
  await initDb();
  app.listen(3000, () => console.log("Servidor JWT en http://localhost:3000"));
}

// Ejecutar main
main().catch(err => console.error(err));
