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

const { authRequired, adminOnly, proveedorOnly } = require("./public/middlewares/auth.js");

// ===================== HELMET CONFIGURACIÓN SEGURA =====================
const helmetOptions = {
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],

      "style-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://www.gstatic.com"
      ],

      "script-src": [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com"
      ],

      "img-src": ["'self'", "data:", "blob:"],

      "connect-src": [
        "'self'",
        "http://localhost:3000",
        "https://www.gstatic.com",
        "data:"
      ],

      "font-src": [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com"
      ],

      "frame-src": ["'self'"],
      "object-src": ["'none'"]
    }
  },

  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false
};
// =======================================================================

const app = express();

// 🚫 Desactivar caché para evitar navegar hacia atrás
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: true, credentials: true }));
app.use(helmet(helmetOptions));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

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

async function getLastHash() {
  const r = await db.query("SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1");
  return r.rows.length ? r.rows[0].hash_actual : "0".repeat(64);
}

async function registrarBloqueVenta(ventaId, usuarioId, total, items) {
  const hash_anterior = await getLastHash();
  const timestamp = new Date().toISOString();

  const data = { venta_id: ventaId, usuario_id: usuarioId, total, productos: items };
  const nonce = crypto.randomBytes(16).toString("hex");

  const hash_actual = sha256(JSON.stringify(data) + nonce + hash_anterior);

  await db.query(
    `INSERT INTO blockchain (nonce, data, hash_actual, hash_anterior, fecha)
     VALUES ($1,$2,$3,$4,$5)`,
    [nonce, data, hash_actual, hash_anterior, timestamp]
  );
}

async function obtenerHashPrevio() {
  const r = await db.query("SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1");
  return r.rows.length ? r.rows[0].hash_actual : "0".repeat(64);
}

async function registrarEnBlockchain(operacion, dataObj) {
  const previo = await obtenerHashPrevio();
  const timestamp = new Date().toISOString();

  const payload = { operacion, data: dataObj, timestamp };
  const actual = sha256(previo + JSON.stringify(payload) + operacion);

  await db.query(
    `INSERT INTO blockchain (nonce, data, hash_actual, hash_anterior, fecha)
     VALUES ($1,$2,$3,$4,$5)`,
    [operacion, JSON.stringify(payload), actual, previo, timestamp]
  );
}

// --------------------- RUTAS API ---------------------

// LOGIN PAGE
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// ===================== AUTENTICACIÓN =====================
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

// ===================== PERFIL =====================
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

// ===================== CATEGORIAS =====================
app.get("/api/categorias", authRequired, async (req, res) => {
  try {
    const r = await db.query("SELECT id, nombre FROM categorias ORDER BY id");
    res.json({ ok: true, categorias: r.rows });
  } catch (err) {
    console.error("Error al obtener categorías:", err);
    res.status(500).json({ ok: false, error: "Error al obtener categorías" });
  }
});

// ===================== PROVEEDORES (ADMIN) =====================
app.get("/api/proveedores", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT 
        p.id,
        u.nombre,
        u.email,
        p.empresa,
        p.telefono,
        p.direccion
      FROM proveedor p
      JOIN usuarios u ON u.id = p.usuario_id
      ORDER BY p.id ASC
    `);

    res.json({ ok: true, proveedores: r.rows });
  } catch (err) {
    console.error(err);
    res.json({ ok: false, error: "Error al obtener proveedores" });
  }
});

// ===================== PRODUCTOS DEL PROVEEDOR =====================

// LISTAR
app.get("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  try {
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);
    if (!rProv.rows.length) return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const productos = await db.query(`
      SELECT 
        p.id, p.nombre, p.descripcion, p.precio, p.stock,
        p.categoria_id,
        c.nombre AS categoria
      FROM productos p
      JOIN categorias c ON c.id = p.categoria_id
      WHERE p.proveedor_id = $1
      ORDER BY p.id ASC
    `, [proveedorId]);

    res.json({ ok: true, productos: productos.rows });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// CREAR
app.post("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  const { nombre, descripcion, categoria_id, precio, stock } = req.body;

  try {
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);
    if (!rProv.rows.length) return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const r = await db.query(
      `INSERT INTO productos(nombre, descripcion, categoria_id, proveedor_id, precio, stock)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [nombre, descripcion, categoria_id, proveedorId, precio, stock]
    );

    res.json({ ok: true, producto: r.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// OBTENER UNO
app.get("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;

  try {
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);
    if (!rProv.rows.length) return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const r = await db.query(
      "SELECT * FROM productos WHERE id=$1 AND proveedor_id=$2",
      [id, proveedorId]
    );

    if (!r.rows.length)
      return res.status(404).json({ ok: false, error: "Producto no encontrado" });

    res.json({ ok: true, producto: r.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// EDITAR
app.put("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, categoria_id, precio, stock } = req.body;

  try {
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const rCheck = await db.query(
      "SELECT * FROM productos WHERE id=$1 AND proveedor_id=$2",
      [id, proveedorId]
    );

    if (!rCheck.rows.length)
      return res.status(403).json({ ok: false, error: "No autorizado" });

    await db.query(`
      UPDATE productos
      SET nombre=$1, descripcion=$2, categoria_id=$3, precio=$4, stock=$5
      WHERE id=$6
    `, [nombre, descripcion, categoria_id, precio, stock, id]);

    res.json({ ok: true, message: "Producto actualizado" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// ELIMINAR
app.delete("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);
    if (!rProv.rows.length) return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const rCheck = await db.query("SELECT * FROM productos WHERE id=$1 AND proveedor_id=$2", [id, proveedorId]);
    if (!rCheck.rows.length) return res.status(403).json({ ok: false, error: "No autorizado" });

    await db.query("DELETE FROM productos WHERE id=$1", [id]);

    res.json({ ok: true, message: "Producto eliminado" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// ===================== PRODUCTOS PÚBLICOS / TODOS =====================

app.get("/api/productos", authRequired, async (req, res) => {
  try {
    const r = await db.query(
      "SELECT id, nombre, descripcion, precio, stock FROM productos WHERE stock > 0 ORDER BY id"
    );
    res.json({ ok: true, productos: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error al obtener productos" });
  }
});

app.get("/api/todos-productos", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM productos ORDER BY id DESC");
    res.json({ ok: true, productos: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// ===================== VENTAS =====================
app.post("/api/usuario/venta", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { productos } = req.body;

  if (!productos || productos.length === 0)
    return res.status(400).json({ ok: false, error: "Debe enviar productos" });

  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const total = productos.reduce((sum, p) => sum + p.cantidad * p.precio_unitario, 0);

    const rVenta = await client.query(
      `INSERT INTO ventas(usuario_id, total)
       VALUES ($1,$2)
       RETURNING id, fecha`,
      [usuarioId, total]
    );

    const ventaId = rVenta.rows[0].id;

    for (const p of productos) {
      const rStock = await client.query(
        "SELECT stock, precio FROM productos WHERE id=$1 FOR UPDATE",
        [p.producto_id]
      );

      if (!rStock.rows.length)
        throw new Error("Producto no existe: " + p.producto_id);

      const stockActual = rStock.rows[0].stock;
      const precioActual = parseFloat(rStock.rows[0].precio);

      if (stockActual < p.cantidad)
        throw new Error("Stock insuficiente para producto " + p.producto_id);

      // Insertar detalle
      await client.query(
        `INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
         VALUES ($1,$2,$3,$4)`,
        [
          ventaId,
          p.producto_id,
          p.cantidad,
          p.precio || precioActual
        ]
      );

      await client.query(
        "UPDATE productos SET stock = stock - $1 WHERE id=$2",
        [p.cantidad, p.producto_id]
      );
    }

    await registrarBloqueVenta(ventaId, usuarioId, total, productos);

    await client.query("COMMIT");

    res.json({ ok: true, ventaId });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error registrando venta:", err);
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    client.release();
  }
});

// ===================== BLOCKCHAIN =====================
app.get("/api/blockchain", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT 
        b.id,
        b.nonce,
        b.data,
        b.hash_actual,
        b.hash_anterior,
        b.fecha,
        v.total AS total_venta
      FROM blockchain b
      LEFT JOIN ventas v
        ON CAST(b.data->>'venta_id' AS INT) = v.id
      ORDER BY b.id ASC
    `);

    res.json({ ok: true, cadena: r.rows });

  } catch (err) {
    console.error(err);
    res.json({ ok: false, error: "Error al obtener blockchain" });
  }
});

app.get("/api/blockchain/:id", authRequired, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    const r = await db.query(`
      SELECT 
        b.id,
        b.nonce,
        b.data,
        b.hash_actual,
        b.hash_anterior,
        b.fecha,
        v.total AS total_venta,
        v.usuario_id,
        u.nombre AS usuario_nombre
      FROM blockchain b
      LEFT JOIN ventas v ON CAST(b.data->>'venta_id' AS INT) = v.id
      LEFT JOIN usuarios u ON v.usuario_id = u.id
      WHERE b.id = $1
    `, [id]);

    if (!r.rows.length)
      return res.json({ ok: false, error: "Bloque no encontrado" });

    const bloque = r.rows[0];

    let productos = [];
    if (bloque.data?.data?.productos) {
      productos = bloque.data.data.productos;
    }

    res.json({ ok: true, bloque, productos });

  } catch (err) {
    console.error(err);
    res.json({ ok: false, error: "Error obteniendo detalle" });
  }
});

// ===================== DASHBOARDS — SIN AUTENTICACIÓN =====================
// ❗ ESTA ES LA VERSIÓN QUE ME PEDISTE (SIN authRequired)

app.get("/proveedor", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "proveedor.html"));
});

app.get("/proveedor/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "proveedor.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/usuario/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "usuario.html"));
});

// ===================== ARCHIVOS ESTÁTICOS =====================
app.use(express.static(path.join(__dirname, "public")));

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
    CREATE TABLE IF NOT EXISTS ventas (
      id SERIAL PRIMARY KEY,
      usuario_id INT NOT NULL REFERENCES usuarios(id),
      fecha TIMESTAMP NOT NULL DEFAULT NOW(),
      total NUMERIC(10,2) NOT NULL
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS venta_detalle (
      id SERIAL PRIMARY KEY,
      venta_id INT REFERENCES ventas(id),
      producto_id INT REFERENCES productos(id),
      cantidad INT NOT NULL,
      precio_unitario NUMERIC(10,2) NOT NULL
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
  app.listen(3000, () => console.log("Servidor JWT levantado en http://localhost:3000"));
}

main().catch(err => console.error(err));
