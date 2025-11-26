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


const app = express();

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


const db = new Pool({
  user: process.env.PGUSER || "postgres",
  password: process.env.PGPASSWORD || "12345",
  database: process.env.PGDATABASE || "railway",
  host: process.env.PGHOST || "localhost",
  port: parseInt(process.env.PGPORT || "5432")
});

function sha256(x) {
  return crypto.createHash("sha256").update(x).digest("hex");
}

// ------------------ HELPERS for signing/verification ------------------
// Canonical stringify: ordena claves recursivamente para coincidir con el cliente
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalStringify).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

// Verifica firma RSA-SHA256 (signatureBase64)
function verifySignature(publicKeyPem, message, signatureBase64) {
  try {
    const verify = crypto.createVerify("SHA256");
    verify.update(message, "utf8");
    verify.end();
    return verify.verify(publicKeyPem, signatureBase64, "base64");
  } catch (err) {
    console.error("Error en verifySignature:", err);
    return false;
  }
}

// Valida formato PEM y que sea parseable por node crypto
function validatePublicKeyPem(publicKeyPem) {
  if (typeof publicKeyPem !== "string") return { ok: false, error: "public_key_pem debe ser string" };
  const pemRegex = /-----BEGIN (?:PUBLIC KEY|RSA PUBLIC KEY)-----[A-Za-z0-9+\/=\s\r\n]+-----END (?:PUBLIC KEY|RSA PUBLIC KEY)-----/;
  if (!pemRegex.test(publicKeyPem)) return { ok: false, error: "Formato PEM inválido" };
  if (publicKeyPem.length > 4096) return { ok: false, error: "public_key_pem demasiado grande" };

  try {
    crypto.createPublicKey(publicKeyPem);
    return { ok: true };
  } catch (err) {
    console.error("createPublicKey error:", err);
    return { ok: false, error: "Clave pública no parseable" };
  }
}
// ----------------------------------------------------------------------

async function getLastHash() {
  const r = await db.query("SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1");
  return r.rows.length ? r.rows[0].hash_actual : "0".repeat(64);
}

// registrarBloqueVenta ahora acepta un objeto meta opcional que se guarda dentro de data
async function registrarBloqueVenta(ventaId, usuarioId, total, items, meta = {}) {
  const hash_anterior = await getLastHash();
  const timestamp = new Date().toISOString();

  const data = {
    venta_id: ventaId,
    usuario_id: usuarioId,
    total,
    productos: items,
    meta
  };
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


app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});


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


app.get("/api/categorias", authRequired, async (req, res) => {
  try {
    const r = await db.query("SELECT id, nombre FROM categorias ORDER BY id");
    res.json({ ok: true, categorias: r.rows });
  } catch (err) {
    console.error("Error al obtener categorías:", err);
    res.status(500).json({ ok: false, error: "Error al obtener categorías" });
  }
});

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

// POST /api/usuario/venta now supports signed flow with nonce + signature verification
app.post("/api/usuario/venta", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { productos, signature, public_key_pem, key_filename, nonce } = req.body;

  if (!productos || productos.length === 0)
    return res.status(400).json({ ok: false, error: "Debe enviar productos" });

  // If signature/public_key_pem/nonce provided => verify signature and nonce (recommended)
  if (signature || public_key_pem || nonce) {
    if (!signature || !public_key_pem || !nonce) {
      return res.status(400).json({ ok: false, error: "Faltan signature, public_key_pem o nonce" });
    }

    // Validate public key PEM format & parseability
    const vpub = validatePublicKeyPem(public_key_pem);
    if (!vpub.ok) return res.status(400).json({ ok: false, error: "public_key_pem inválida: " + vpub.error });

    try {
      // Verify nonce exists, belongs to user, not used, not expired
      const r = await db.query("SELECT id, usuario_id, expires_at, used FROM nonces WHERE nonce=$1", [nonce]);
      if (!r.rows.length) return res.status(400).json({ ok: false, error: "Nonce no encontrado" });
      const nrow = r.rows[0];
      if (nrow.usuario_id !== usuarioId) return res.status(403).json({ ok: false, error: "Nonce no pertenece al usuario" });
      if (nrow.used) return res.status(400).json({ ok: false, error: "Nonce ya fue usado" });
      if (new Date(nrow.expires_at) < new Date()) return res.status(400).json({ ok: false, error: "Nonce expirado" });

      // Reconstruct venta object exactly as client signed
      const venta = {
        productos: productos.map(p => ({
          producto_id: p.producto_id,
          cantidad: p.cantidad,
          precio_unitario: p.precio_unitario
        })),
        total: productos.reduce((sum, p) => sum + p.cantidad * p.precio_unitario, 0)
      };

      // Message to verify is canonicalStringify({ venta, nonce })
      const messageObj = { venta, nonce };
      const message = canonicalStringify(messageObj);

      // Verify signature
      const okSig = verifySignature(public_key_pem, message, signature);
      if (!okSig) {
        return res.status(400).json({ ok: false, error: "Firma inválida" });
      }

      // Replay protection: insert signature hash (unique)
      const signatureHash = sha256(signature + message);
      try {
        await db.query("INSERT INTO used_signatures(signature_hash) VALUES($1)", [signatureHash]);
      } catch (err) {
        console.error("Firma ya registrada o error en used_signatures:", err);
        return res.status(400).json({ ok: false, error: "Firma ya fue usada (replay detectado)" });
      }

      // Proceed to create venta within transaction, mark nonce used
      const client = await db.connect();
      try {
        await client.query("BEGIN");

        const total = venta.total;

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

          if (!rStock.rows.length) throw new Error("Producto no existe: " + p.producto_id);

          const stockActual = rStock.rows[0].stock;
          const precioActual = parseFloat(rStock.rows[0].precio);

          if (stockActual < p.cantidad) throw new Error("Stock insuficiente para producto " + p.producto_id);

          await client.query(
            `INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
             VALUES ($1,$2,$3,$4)`,
            [ventaId, p.producto_id, p.cantidad, p.precio_unitario || precioActual]
          );

          await client.query("UPDATE productos SET stock = stock - $1 WHERE id=$2", [p.cantidad, p.producto_id]);
        }

        // Mark nonce as used
        await client.query("UPDATE nonces SET used = true WHERE nonce = $1", [nonce]);

        // Register in blockchain with meta (signature hash and public key)
        const meta = {
          signature_hash: signatureHash,
          key_filename: key_filename || null,
          public_key_pem: public_key_pem
        };

        await registrarBloqueVenta(ventaId, usuarioId, venta.total, productos, meta);

        await client.query("COMMIT");

        res.json({ ok: true, ventaId });
      } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error registrando venta (firmada + nonce):", err);
        res.status(500).json({ ok: false, error: err.message });
      } finally {
        client.release();
      }

    } catch (err) {
      console.error("Error verificando nonce/firmas:", err);
      return res.status(500).json({ ok: false, error: "Error interno validando firma/nonce" });
    }

    return;
  }

  // If no signature/nonce provided: fallback to legacy behavior
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

      await client.query(
        `INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
         VALUES ($1,$2,$3,$4)`,
        [
          ventaId,
          p.producto_id,
          p.cantidad,
          p.precio_unitario || precioActual
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


app.use(express.static(path.join(__dirname, "public")));


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

  // Tabla para evitar reuso de firmas (replay attacks)
  await db.query(`
    CREATE TABLE IF NOT EXISTS used_signatures (
      id SERIAL PRIMARY KEY,
      signature_hash TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  // Tabla para nonces de challenge
  await db.query(`
    CREATE TABLE IF NOT EXISTS nonces (
      id SERIAL PRIMARY KEY,
      usuario_id INT NOT NULL,
      nonce VARCHAR(200) NOT NULL UNIQUE,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  const r = await db.query("SELECT COUNT(*) FROM roles");
  if (parseInt(r.rows[0].count) === 0) {
    await db.query(`
      INSERT INTO roles(nombre) VALUES ('usuario'),('admin'),('proveedor')
    `);
  }
}


// ---------------- Endpoint: generar nonce para firma (challenge) ----------------
app.post("/api/venta/nonce", authRequired, async (req, res) => {
  try {
    const usuarioId = req.user.id;
    const nonce = crypto.randomBytes(24).toString("hex");
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 minutos

    await db.query(`INSERT INTO nonces (usuario_id, nonce, expires_at, used) VALUES ($1,$2,$3,false)`, [usuarioId, nonce, expiresAt]);

    res.json({ ok: true, nonce, expires_at: expiresAt });
  } catch (err) {
    console.error("Error creando nonce:", err);
    res.status(500).json({ ok: false, error: "No se pudo generar nonce" });
  }
});

// Limpieza periódica opcional de nonces antiguos (cada hora)
setInterval(async () => {
  try {
    await db.query("DELETE FROM nonces WHERE expires_at < NOW() OR (used = true AND created_at < NOW() - INTERVAL '7 days')");
  } catch (err) {
    console.error("Error limpiando nonces:", err);
  }
}, 60 * 60 * 1000);


async function main() {
  await initDb();
  app.listen(3000, () => console.log("Servidor JWT levantado en http://localhost:3000"));
}

main().catch(err => console.error(err));
