/**
 * index.js - Versión completa, SIN HTTPS, solo HTTP.
 */

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
const { sshToPem } = require("./public/middlewares/sshToPem.js");

const zlib = require("zlib");
const { constants: cryptoConstants } = require("crypto");

// Encriptación de bloques (tu encrypt.js)
const { encryptJSON, decryptJSON } = require("./encrypt.js");

// Middlewares
const { authRequired, adminOnly, proveedorOnly } = require("./public/middlewares/auth.js");

// --------------------------- Configs ---------------------------
const PORT = parseInt(process.env.PORT || "3000", 10);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET no está definido.");
  process.exit(1);
}

const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "http://localhost:3000")
  .split(",");

// --------------------------- Helmet ---------------------------
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
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com"
      ],
      "img-src": ["'self'", "data:", "blob:", "https://www.gravatar.com"],
      "connect-src": [
        "'self'",
        "http://localhost:3000",
        "https://www.gstatic.com",
        "https://cdnjs.cloudflare.com",     // ← AGREGADO
        "data:"
      ],
      "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      "frame-src": ["'self'"],
      "object-src": ["'none'"]
    },
  },

  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
};

// --------------------------- App setup ---------------------------
const app = express();

// ✅ CAMBIO 1: necesario para evitar error de X-Forwarded-For / express-rate-limit
app.set("trust proxy", 1);

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// --------------------------- CORS ---------------------------
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    if (FRONTEND_ORIGINS.includes(origin)) {
      return callback(null, true);
    }

    // ✅ CAMBIO 2 aplicado: no lanzar error, solo rechazar sin crash
    return callback(null, false);
  },
  credentials: true,
}));

app.use(helmet(helmetOptions));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// --------------------------- DB ---------------------------
const db = new Pool({
  user: process.env.PGUSER || "postgres",
  password: process.env.PGPASSWORD || "12345",
  database: process.env.PGDATABASE || "railway",
  host: process.env.PGHOST || "localhost",
  port: parseInt(process.env.PGPORT || "5432", 10),
});

function isEncryptedBlock(obj) {
  return (
    obj &&
    typeof obj === "object" &&
    typeof obj.iv === "string" &&
    typeof obj.value === "string" &&
    typeof obj.tag === "string"
  );
}

// --------------------------- UTILS ---------------------------
function sha256(x) {
  return crypto.createHash("sha256").update(x).digest("hex");
}

function canonicalStringify(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalStringify).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return (
    "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}"
  );
}

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

function validatePublicKeyPem(publicKeyPem) {
  if (!publicKeyPem || typeof publicKeyPem !== "string") {
    return { ok: false, error: "Clave pública vacía" };
  }

  // Si es ssh-rsa sin convertir, también la aceptamos.
  if (publicKeyPem.trim().startsWith("ssh-rsa ")) {
    return { ok: true };
  }

  // Verificar PEM básico (sin crear clave)
  if (
    publicKeyPem.includes("-----BEGIN PUBLIC KEY-----") &&
    publicKeyPem.includes("-----END PUBLIC KEY-----")
  ) {
    return { ok: true };
  }

  if (
    publicKeyPem.includes("-----BEGIN RSA PUBLIC KEY-----") &&
    publicKeyPem.includes("-----END RSA PUBLIC KEY-----")
  ) {
    return { ok: true };
  }

  return { ok: false, error: "Formato no reconocido (debe ser ssh-rsa o PEM RSA)" };
}


// --------------------------- PoW ---------------------------
const POW_DIFFICULTY = parseInt(process.env.POW_DIFFICULTY || "4", 10);

function computeBlockHash(prevHash, payloadObj, nonce) {
  const serialized = canonicalStringify(payloadObj);
  return sha256(prevHash + serialized + nonce);
}

function isValidProof(hashHex, difficulty) {
  return hashHex.startsWith("0".repeat(difficulty));
}

// --------------------------- Mining ---------------------------
async function getLastHash() {
  const r = await db.query("SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1");
  return r.rows.length ? r.rows[0].hash_actual : "0".repeat(64);
}

async function minePendingBlock(minerName = null, maxAttempts = 5_000_000, pendingId = null) {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    
    const q = pendingId
      ? `SELECT id, data FROM pending_blocks WHERE id = $1 FOR UPDATE`
      : `SELECT id, data FROM pending_blocks ORDER BY id ASC LIMIT 1 FOR UPDATE SKIP LOCKED`;

    const r = pendingId ? await client.query(q, [pendingId]) : await client.query(q);

    if (!r.rows.length) {
      await client.query("ROLLBACK");
      return { ok: false, error: "No hay bloques pendientes" };
    }

    const pending = r.rows[0];
    const payload = JSON.parse(JSON.stringify(pending.data));

    const prev = await client.query(`SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1`);
    const prevHash = prev.rows.length ? prev.rows[0].hash_actual : "0".repeat(64);

    let nonce = null,
      hash = null;
    const start = Date.now();

    for (let i = 0; i < maxAttempts; i++) {
      nonce = crypto.randomBytes(16).toString("hex");
      hash = computeBlockHash(prevHash, payload, nonce);

      if (isValidProof(hash, POW_DIFFICULTY)) break;
      if ((i & 2047) === 0 && Date.now() - start > 60000) break;
    }

    if (!hash || !isValidProof(hash, POW_DIFFICULTY)) {
      await client.query(
        `UPDATE pending_blocks SET attempted = attempted + 1 WHERE id = $1`,
        [pending.id],
      );
      await client.query("COMMIT");
      return { ok: false, error: "No se encontró un nonce válido" };
    }

    const encryptedData = encryptJSON(payload);
    const now = new Date().toISOString();

    await client.query(
      `INSERT INTO blockchain (nonce, data, hash_actual, hash_anterior, fecha)
       VALUES ($1,$2,$3,$4,$5)`,
      [nonce, encryptedData, hash, prevHash, now],
    );

    await client.query(`DELETE FROM pending_blocks WHERE id=$1`, [pending.id]);
    await client.query("COMMIT");

    return {
      ok: true,
      hash,
      nonce,
      blockData: payload,
      miner: minerName || "unknown",
      blockId: null,
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Error minando:", err);
    return { ok: false, error: err.message };
  } finally {
    client.release();
  }
}
// --------------------------- Registrar Bloques ---------------------------
async function registrarBloqueVenta(ventaId, usuarioId, total, items, meta = {}) {
  const timestamp = new Date().toISOString();

  const payload = {
    operacion: "venta",
    venta_id: ventaId,
    usuario_id: usuarioId,
    total: total,
    productos: items.map((p) => ({
      producto_id: Number(p.producto_id),
      cantidad: Number(p.cantidad),
      precio_unitario: Number(p.precio_unitario),
    })),
    meta,
    timestamp,
  };

  await db.query(`INSERT INTO pending_blocks (data) VALUES ($1)`, [payload]);
}

async function registrarEnPending(operacion, dataObj) {
  const payload = {
    operacion,
    data: dataObj,
    timestamp: new Date().toISOString(),
  };

  await db.query(`INSERT INTO pending_blocks (data) VALUES ($1)`, [payload]);
}

// --------------------------- ENDPOINTS ---------------------------

// raíz
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "login.html")),
);

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const r = await db.query(
      `
      SELECT u.id, u.nombre, u.password, r.nombre AS rol
      FROM usuarios u
      JOIN roles r ON r.id = u.rol_id
      WHERE email=$1
    `,
      [email],
    );

    if (!r.rows.length) return res.status(400).json({ ok: false });

    const user = r.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ ok: false });

    if (user.rol === "proveedor") {
      await db.query(
        `
        INSERT INTO proveedor (usuario_id)
        VALUES ($1)
        ON CONFLICT (usuario_id) DO NOTHING
      `,
        [user.id],
      );
    }

    const token = jwt.sign(
      { id: user.id, nombre: user.nombre, rol: user.rol },
      JWT_SECRET,
      { expiresIn: "2h" },
    );

    res.json({
      ok: true,
      token,
      usuario: { id: user.id, nombre: user.nombre, rol: user.rol },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// PERFIL
app.get("/api/perfil", authRequired, async (req, res) => {
  try {
    const r = await db.query(
      `
      SELECT u.id, u.nombre, u.email, r.nombre AS rol
      FROM usuarios u
      JOIN roles r ON r.id = u.rol_id
      WHERE u.id=$1
    `,
      [req.user.id],
    );

    res.json({ ok: true, usuario: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// CATEGORÍAS
app.get("/api/categorias", authRequired, async (req, res) => {
  try {
    const r = await db.query("SELECT id, nombre FROM categorias ORDER BY id");
    res.json({ ok: true, categorias: r.rows });
  } catch (err) {
    console.error("Error al obtener categorías:", err);
    res.status(500).json({ ok: false, error: "Error al obtener categorías" });
  }
});

// PROVEEDORES (ADMIN)
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
    res.status(500).json({ ok: false, error: "Error al obtener proveedores" });
  }
});

// PRODUCTOS DEL PROVEEDOR
app.get("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id],
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const productos = await db.query(
      `
      SELECT 
        p.id, p.nombre, p.descripcion, p.precio, p.stock,
        p.categoria_id,
        c.nombre AS categoria
      FROM productos p
      JOIN categorias c ON c.id = p.categoria_id
      WHERE p.proveedor_id = $1
      ORDER BY p.id ASC
    `,
      [proveedorId],
    );

    res.json({ ok: true, productos: productos.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// CREAR PRODUCTO PROVEEDOR
app.post("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  const { nombre, descripcion, categoria_id, precio, stock } = req.body || {};

  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id],
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const r = await db.query(
      `
      INSERT INTO productos(nombre, descripcion, categoria_id, proveedor_id, precio, stock)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING *
    `,
      [nombre, descripcion, categoria_id, proveedorId, precio, stock],
    );

    res.json({ ok: true, producto: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// VER PRODUCTO PROVEEDOR
app.get("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;

  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id],
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const r = await db.query(
      "SELECT * FROM productos WHERE id=$1 AND proveedor_id=$2",
      [id, proveedorId],
    );

    if (!r.rows.length)
      return res.status(404).json({ ok: false, error: "Producto no encontrado" });

    res.json({ ok: true, producto: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// ACTUALIZAR PRODUCTO PROVEEDOR
app.put("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, categoria_id, precio, stock } = req.body || {};

  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id],
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const rCheck = await db.query(
      "SELECT * FROM productos WHERE id=$1 AND proveedor_id=$2",
      [id, proveedorId],
    );

    if (!rCheck.rows.length)
      return res.status(403).json({ ok: false, error: "No autorizado" });

    await db.query(
      `
      UPDATE productos
      SET nombre=$1, descripcion=$2, categoria_id=$3, precio=$4, stock=$5
      WHERE id=$6
    `,
      [nombre, descripcion, categoria_id, precio, stock, id],
    );

    res.json({ ok: true, message: "Producto actualizado" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// ELIMINAR PRODUCTO PROVEEDOR
app.delete("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;

  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id],
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const rCheck = await db.query(
      "SELECT * FROM productos WHERE id=$1 AND proveedor_id=$2",
      [id, proveedorId],
    );

    if (!rCheck.rows.length)
      return res.status(403).json({ ok: false, error: "No autorizado" });

    await db.query("DELETE FROM productos WHERE id=$1", [id]);

    res.json({ ok: true, message: "Producto eliminado" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// PRODUCTOS DISPONIBLES
app.get("/api/productos", authRequired, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT id, nombre, descripcion, precio, stock 
      FROM productos 
      WHERE stock > 0 
      ORDER BY id
    `);
    res.json({ ok: true, productos: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error al obtener productos" });
  }
});

// TODOS LOS PRODUCTOS (ADMIN)
app.get("/api/todos-productos", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM productos ORDER BY id DESC");
    res.json({ ok: true, productos: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// Validadores
function isValidInteger(n) {
  return Number.isInteger(Number(n)) && Number(n) > 0;
}

function isValidNonNegativeNumber(x) {
  return !Number.isNaN(Number(x)) && Number(x) >= 0;
}

// ======================================================
// REGISTRO DE USUARIO
// ======================================================
app.post("/api/register", async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password || !rol) {
      return res
        .status(400)
        .json({ ok: false, error: "Todos los campos son obligatorios." });
    }

    const r = await db.query("SELECT id FROM roles WHERE nombre=$1", [rol]);
    if (!r.rows.length) {
      return res.status(400).json({ ok: false, error: "Rol inválido." });
    }

    const rol_id = r.rows[0].id;

    const existe = await db.query("SELECT id FROM usuarios WHERE email=$1", [
      email,
    ]);
    if (existe.rows.length > 0) {
      return res
        .status(400)
        .json({ ok: false, error: "El correo ya está registrado." });
    }

    const hashed = await bcrypt.hash(password, 10);

    const result = await db.query(
      `
        INSERT INTO usuarios (nombre, email, password, rol_id)
        VALUES ($1, $2, $3, $4)
        RETURNING id, nombre, email, rol_id
      `,
      [nombre, email, hashed, rol_id],
    );

    return res.status(201).json({
      ok: true,
      message: "Usuario registrado correctamente ✔",
      user: result.rows[0],
    });
  } catch (err) {
    console.error("❌ Error en /api/register:", err);
    return res
      .status(500)
      .json({ ok: false, error: "Error interno del servidor." });
  }
});

// --------------------------- VENTA CON FIRMA + NONCE + BLOCKCHAIN ---------------------------
app.post("/api/usuario/venta", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { productos, signature, public_key_pem, key_filename, nonce } =
    req.body || {};

  if (!Array.isArray(productos) || productos.length === 0)
    return res
      .status(400)
      .json({ ok: false, error: "Debe enviar productos" });

  for (const p of productos) {
    if (!isValidInteger(p.producto_id))
      return res.status(400).json({ ok: false, error: "producto_id inválido" });
    if (!isValidInteger(p.cantidad))
      return res.status(400).json({ ok: false, error: "cantidad inválida" });
    if (
      p.precio_unitario !== undefined &&
      !isValidNonNegativeNumber(p.precio_unitario)
    )
      return res
        .status(400)
        .json({ ok: false, error: "precio_unitario inválido" });
  }

  // ---------------- MODO FIRMA ----------------
  if (signature || public_key_pem || nonce) {
    if (!signature || !public_key_pem || !nonce) {
      return res.status(400).json({
        ok: false,
        error: "Faltan signature, public_key_pem o nonce",
      });
    }

    const vpub = validatePublicKeyPem(public_key_pem);
    if (!vpub.ok)
      return res
        .status(400)
        .json({ ok: false, error: "public_key_pem inválida: " + vpub.error });

    try {
      const rNonce = await db.query(
        "SELECT id, usuario_id, expires_at, used FROM nonces WHERE nonce=$1",
        [nonce],
      );
      if (!rNonce.rows.length)
        return res.status(400).json({ ok: false, error: "Nonce no encontrado" });

      const row = rNonce.rows[0];

      if (row.usuario_id !== usuarioId)
        return res
          .status(403)
          .json({ ok: false, error: "Nonce no pertenece al usuario" });

      if (row.used)
        return res.status(400).json({ ok: false, error: "Nonce ya usado" });

      if (new Date(row.expires_at) < new Date())
        return res.status(400).json({ ok: false, error: "Nonce expirado" });

      // Construcción de la venta firmada
      const venta = {
        productos: productos.map((p) => ({
          producto_id: Number(p.producto_id),
          cantidad: Number(p.cantidad),
          precio_unitario:
            p.precio_unitario !== undefined
              ? Number(p.precio_unitario)
              : undefined,
        })),
        total: productos.reduce((sum, p) => {
          const u =
            p.precio_unitario !== undefined
              ? Number(p.precio_unitario)
              : 0;
          return sum + Number(p.cantidad) * u;
        }, 0),
      };

      const messageObj = { venta, nonce };
      const message = canonicalStringify(messageObj);

      const okSig = verifySignature(public_key_pem, message, signature);
      if (!okSig)
        return res.status(400).json({ ok: false, error: "Firma inválida" });

      const signatureHash = sha256(signature + message);
      try {
        await db.query(
          "INSERT INTO used_signatures(signature_hash) VALUES($1)",
          [signatureHash],
        );
      } catch (err) {
        return res
          .status(400)
          .json({ ok: false, error: "Firma ya usada (replay)" });
      }

      // Guardar venta + stock
      const client = await db.connect();
      try {
        await client.query("BEGIN");

        const rVenta = await client.query(
          `
          INSERT INTO ventas(usuario_id, total) VALUES ($1,$2)
          RETURNING id, fecha
        `,
          [usuarioId, venta.total],
        );

        const ventaId = rVenta.rows[0].id;

        for (const p of productos) {
          const rStock = await client.query(
            "SELECT stock, precio FROM productos WHERE id=$1 FOR UPDATE",
            [p.producto_id],
          );
          if (!rStock.rows.length)
            throw new Error("Producto no existe: " + p.producto_id);

          const stockActual = rStock.rows[0].stock;
          const precioActual = parseFloat(rStock.rows[0].precio);

          if (stockActual < p.cantidad)
            throw new Error("Stock insuficiente");

          await client.query(
            `
            INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
            VALUES ($1,$2,$3,$4)
          `,
            [
              ventaId,
              p.producto_id,
              p.cantidad,
              p.precio_unitario !== undefined
                ? p.precio_unitario
                : precioActual,
            ],
          );

          await client.query(
            "UPDATE productos SET stock = stock - $1 WHERE id=$2",
            [p.cantidad, p.producto_id],
          );
        }

        await client.query("UPDATE nonces SET used = true WHERE nonce = $1", [
          nonce,
        ]);

        const meta = {
          signature_hash: signatureHash,
          key_filename: key_filename || null,
          fingerprint: sha256(public_key_pem),
          public_key_pem,
        };

        await registrarBloqueVenta(
          ventaId,
          usuarioId,
          venta.total,
          productos,
          meta,
        );

        await client.query("COMMIT");

        res.json({ ok: true, ventaId });
      } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error registrando venta firmada:", err);
        return res.status(500).json({ ok: false, error: err.message });
      } finally {
        client.release();
      }
    } catch (err) {
      console.error("Error validando firma:", err);
      return res
        .status(500)
        .json({ ok: false, error: "Error interno en firma" });
    }
    return;
  }

  // ---------------- MODO LEGACY ----------------
  const client2 = await db.connect();

  try {
    await client2.query("BEGIN");

    const total = productos.reduce((sum, p) => {
      const pu =
        p.precio_unitario !== undefined ? Number(p.precio_unitario) : 0;
      return sum + Number(p.cantidad) * pu;
    }, 0);

    const rVenta = await client2.query(
      `
      INSERT INTO ventas(usuario_id, total)
      VALUES ($1,$2)
      RETURNING id, fecha
    `,
      [usuarioId, total],
    );

    const ventaId = rVenta.rows[0].id;

    for (const p of productos) {
      const rStock = await client2.query(
        "SELECT stock, precio FROM productos WHERE id=$1 FOR UPDATE",
        [p.producto_id],
      );

      if (!rStock.rows.length)
        throw new Error("Producto no existe");

      const stockActual = rStock.rows[0].stock;
      const precioActual = parseFloat(rStock.rows[0].precio);

      if (stockActual < p.cantidad)
        throw new Error("Stock insuficiente");

      await client2.query(
        `
        INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
        VALUES ($1,$2,$3,$4)
      `,
        [
          ventaId,
          p.producto_id,
          p.cantidad,
          p.precio_unitario !== undefined
            ? p.precio_unitario
            : precioActual,
        ],
      );

      await client2.query(
        "UPDATE productos SET stock = stock - $1 WHERE id=$2",
        [p.cantidad, p.producto_id],
      );
    }

    await registrarBloqueVenta(ventaId, usuarioId, total, productos);

    await client2.query("COMMIT");

    res.json({ ok: true, ventaId });
  } catch (err) {
    await client2.query("ROLLBACK");
    console.error("Error registrando venta:", err);
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    client2.release();
  }
});

// --------------------------- LEER BLOCKCHAIN ---------------------------
app.get("/api/blockchain", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT id, nonce, data, hash_actual, hash_anterior, fecha
      FROM blockchain
      ORDER BY id ASC
    `);

    const blocks = [];

    for (const b of r.rows) {
      let payload;

      if (isEncryptedBlock(b.data)) {
        try {
          payload = decryptJSON(b.data);
        } catch (err) {
          console.error("Error decrypting block:", err);
          payload = { error: "Bloque cifrado pero dañado" };
        }
      } else {
        payload = b.data;
      }

      let total_venta = null;

      if (payload && payload.venta_id) {
        try {
          const q = await db.query(
            "SELECT total FROM ventas WHERE id=$1",
            [payload.venta_id],
          );
          if (q.rows.length) total_venta = q.rows[0].total;
        } catch (err) {
          console.error("Error consultando total_venta", err);
        }
      }

      blocks.push({
        ...b,
        data: payload,
        total_venta,
      });
    }

    res.json({ ok: true, cadena: blocks });
  } catch (err) {
    console.error("ERROR /api/blockchain:", err);
    res.status(500).json({ ok: false });
  }
});

// --------------------------- VALIDAR CADENA ---------------------------
app.get("/api/blockchain/validate", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`SELECT * FROM blockchain ORDER BY id ASC`);
    let prevHash = "0".repeat(64);
    const problems = [];

    for (const b of r.rows) {
      let payload;

      try {
        payload = isEncryptedBlock(b.data) ? decryptJSON(b.data) : b.data;
      } catch {
        problems.push({ id: b.id, error: "Bloque cifrado dañado" });
        prevHash = b.hash_actual;
        continue;
      }

      if (b.hash_anterior !== prevHash)
        problems.push({ id: b.id, error: "hash_anterior incorrecto" });

      const recalculated = computeBlockHash(prevHash, payload, b.nonce);
      if (recalculated !== b.hash_actual)
        problems.push({ id: b.id, error: "hash_actual incorrecto" });

      if (!isValidProof(b.hash_actual, POW_DIFFICULTY))
        problems.push({ id: b.id, error: "PoW inválido" });

      prevHash = b.hash_actual;
    }

    res.json({ ok: problems.length === 0, problems });
  } catch (err) {
    console.error("ERROR validate:", err);
    res.status(500).json({ ok: false, error: "Error en validación" });
  }
});

// --------------------------- DETALLE BLOQUE ---------------------------
app.get("/api/blockchain/:id", authRequired, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ ok: false, error: "ID inválido" });
  }

  try {
    const r = await db.query(
      `
      SELECT id, nonce, data, hash_actual, hash_anterior, fecha
      FROM blockchain
      WHERE id=$1
    `,
      [id],
    );

    if (!r.rows.length)
      return res
        .status(404)
        .json({ ok: false, error: "Bloque no encontrado" });

    const b = r.rows[0];

    let payload = isEncryptedBlock(b.data) ? decryptJSON(b.data) : b.data;

    b.data = payload;

    res.json({ ok: true, bloque: b });
  } catch (err) {
    console.error("ERROR /blockchain/:id:", err);
    res.status(500).json({ ok: false });
  }
});

// --------------------------- PENDING BLOCKS ---------------------------
app.get("/api/pending-blocks", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT id, data, created_at, attempted
      FROM pending_blocks
      ORDER BY id ASC
    `);
    res.json({ ok: true, pending: r.rows });
  } catch (err) {
    console.error("Error al obtener pending blocks:", err);
    res.status(500).json({ ok: false });
  }
});

app.get("/api/blockchain/pending", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT id, data, created_at, attempted
      FROM pending_blocks
      ORDER BY id ASC
    `);

    return res.json({
      ok: true,
      count: r.rows.length,
      pending: r.rows
    });

  } catch (err) {
    console.error("ERROR /api/blockchain/pending:", err);
    return res.status(500).json({
      ok: false,
      error: "Error interno servidor"
    });
  }
});




// --------------------------- MINAR BLOQUE ---------------------------
app.post("/api/mine", authRequired, adminOnly, async (req, res) => {
  const { miner_name } = req.body || {};

  try {
    const result = await minePendingBlock(miner_name || "admin");
    if (!result.ok) return res.status(400).json(result);

    res.json({ ok: true, mined: result });
  } catch (err) {
    console.error("ERROR /api/mine:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --------------------------- WALLET REGISTER ---------------------------
// ------------------------------------------
// WALLET REGISTER (usa public_key_pub)
// ------------------------------------------
app.post("/api/wallet/register", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { public_key_pem, pin } = req.body;

  if (!public_key_pem || !pin) {
    return res.status(400).json({ ok: false, error: "Faltan datos" });
  }

  if (pin.length < 4 || pin.length > 10) {
    return res.status(400).json({ ok: false, error: "PIN inválido" });
  }

  // Intentar convertir si es formato ssh-rsa
  let finalPem = sshToPem(public_key_pem) || public_key_pem;

  // Verificar solo claves RSA válidas
  let vpub = validatePublicKeyPem(finalPem);
  if (!vpub.ok) {
    return res.status(400).json({
      ok: false,
      error: "La clave pública debe ser RSA (ssh-rsa o PEM). Otros formatos no se pueden usar."
    });
  }

  const fingerprint = sha256(finalPem);
  const pinHash = await bcrypt.hash(pin, 10);

  try {
    const r = await db.query(`
      INSERT INTO wallets(usuario_id, public_key_pem, pin_hash, fingerprint)
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (usuario_id) DO UPDATE
      SET public_key_pem = EXCLUDED.public_key_pem,
          pin_hash       = EXCLUDED.pin_hash,
          fingerprint    = EXCLUDED.fingerprint,
          updated_at     = NOW()
      RETURNING *
    `, [usuarioId, finalPem, pinHash, fingerprint]);

    return res.json({ ok: true, wallet: r.rows[0] });

  } catch (err) {
    console.error(err);

    if (err.code === "23505") {
      return res.status(400).json({
        ok: false,
        error: "Esta clave ya está registrada por otro usuario"
      });
    }

    return res.status(500).json({ ok: false, error: "Error registrando wallet" });
  }
});




// --------------------------- VENTA CON PIN ---------------------------
app.post("/api/usuario/venta-pin", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { productos, pin } = req.body;

  if (!pin || !Array.isArray(productos))
    return res.status(400).json({ ok: false, error: "Datos incompletos" });

  const w = await db.query("SELECT * FROM wallets WHERE usuario_id=$1", [
    usuarioId,
  ]);
  if (!w.rows.length)
    return res.status(400).json({ ok: false, error: "No tienes wallet registrada" });

  const wallet = w.rows[0];

  const okPin = await bcrypt.compare(pin, wallet.pin_hash);
  if (!okPin)
    return res.status(403).json({ ok: false, error: "PIN incorrecto" });

  try {
    const client = await db.connect();
    await client.query("BEGIN");

    const total = productos.reduce(
      (sum, p) => sum + p.cantidad * p.precio_unitario,
      0,
    );

    const rVenta = await client.query(
      `
      INSERT INTO ventas(usuario_id, total)
      VALUES ($1,$2)
      RETURNING id
    `,
      [usuarioId, total],
    );

    const ventaId = rVenta.rows[0].id;

    for (const p of productos) {
      await client.query(
        `
        INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
        VALUES ($1,$2,$3,$4)
      `,
        [ventaId, p.producto_id, p.cantidad, p.precio_unitario],
      );

      await client.query(
        `
        UPDATE productos SET stock = stock - $1 WHERE id=$2
      `,
        [p.cantidad, p.producto_id],
      );
    }

    await registrarEnPending("venta", {
      venta_id: ventaId,
      usuario: usuarioId,
      productos,
      total,
      meta: {
        fingerprint: wallet.fingerprint,
        wallet_id: wallet.id,
      },
    });

    await client.query("COMMIT");

    return res.json({ ok: true, ventaId });
  } catch (err) {
    console.error(err);
    return res
      .status(500)
      .json({ ok: false, error: "Error registrando venta" });
  }
});




// Helper: crea el paquete cifrado para una venta y lo devuelve como Buffer + filename
async function createEncryptedInvoicePackage(ventaId, usuarioId) {
  // 1) Obten datos de la venta desde la BD
  const rVenta = await db.query(
    `SELECT v.id, v.usuario_id, v.fecha, v.total, u.nombre AS usuario_nombre, u.email
     FROM ventas v
     JOIN usuarios u ON u.id = v.usuario_id
     WHERE v.id = $1`,
    [ventaId]
  );

  if (!rVenta.rows.length) throw new Error("Venta no encontrada");

  const venta = rVenta.rows[0];

  const rDetalle = await db.query(
    `SELECT producto_id, cantidad, precio_unitario FROM venta_detalle WHERE venta_id=$1`,
    [ventaId]
  );

  const detalle = rDetalle.rows;

  // 2) Recuperar la public key del usuario (wallet)
  const rWallet = await db.query("SELECT public_key_pem FROM wallets WHERE usuario_id=$1", [usuarioId]);
  if (!rWallet.rows.length) throw new Error("Usuario no tiene wallet registrada");

  const publicKeyPem = rWallet.rows[0].public_key_pem;

  // 3) Verificar que la clave pública sea RSA (necesario para publicEncrypt)
  let pubKeyObj;
  try {
    pubKeyObj = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new Error("Clave pública no parseable");
  }
  if (pubKeyObj.asymmetricKeyType !== "rsa") {
    throw new Error("Solo se soportan claves RSA para cifrar la factura. Registra una clave RSA (.pub).");
  }

  // 4) Preparar el JSON de factura
  const invoiceObj = {
    venta: {
      id: venta.id,
      fecha: venta.fecha,
      usuario_id: venta.usuario_id,
      usuario_nombre: venta.usuario_nombre,
      email: venta.email,
      total: venta.total,
      items: detalle.map(d => ({
        producto_id: d.producto_id,
        cantidad: d.cantidad,
        precio_unitario: d.precio_unitario
      }))
    },
    generated_at: new Date().toISOString()
  };

  const invoiceJson = JSON.stringify(invoiceObj, null, 2);

  // 5) Comprimir la factura (gzip)
  const compressed = zlib.gzipSync(Buffer.from(invoiceJson, "utf8"));

  // 6) Generar clave simétrica AES-256-GCM
  const aesKey = crypto.randomBytes(32); // 256 bits
  const iv = crypto.randomBytes(12); // 96-bit recommended for GCM

  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // 7) Cifrar la clave AES con la clave pública RSA (OAEP+SHA256)
  const encryptedKey = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    aesKey
  );

  // 8) Construir paquete JSON (base64 campos)
  const packageObj = {
    meta: {
      venta_id: ventaId,
      usuario_id: usuarioId,
      algorithm: "AES-256-GCM",
      key_encryption: "RSA-OAEP-SHA256",
      compressed: "gzip",
      created_at: new Date().toISOString()
    },
    encrypted_key: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
    tag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    filename: `invoice_${ventaId}.json.gz`
  };

  const packageJson = JSON.stringify(packageObj);
  const packageBuffer = Buffer.from(packageJson, "utf8");

  // Optional: puedes devolver packageBuffer directamente o comprimirlo de nuevo.
  // Aquí devolvemos un .invoice (json) que contiene el contenido cifrado en base64.
  const outFilename = `invoice_${ventaId}.invoice`;
  return { buffer: packageBuffer, filename: outFilename };
}

// Generar y descargar paquete cifrado de factura
app.post("/api/usuario/invoice-generate", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  let ventaId = req.body?.ventaId;

  if (!ventaId) {
    return res.status(400).json({ ok: false, error: "ventaId faltante" });
  }

  try {
    // Verificar propiedad de la venta
    const r = await db.query("SELECT usuario_id FROM ventas WHERE id=$1", [ventaId]);

    if (!r.rows.length) {
      return res.status(404).json({ ok: false, error: "Venta no encontrada" });
    }

    if (r.rows[0].usuario_id !== usuarioId) {
      return res.status(403).json({ ok: false, error: "No autorizado" });
    }

    // Crear paquete
    const pkg = await createEncryptedInvoicePackage(ventaId, usuarioId);

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${pkg.filename}"`);
    return res.send(pkg.buffer);

  } catch (err) {
    console.error("Error en invoice-generate:", err);
    return res.status(500).json({ ok: false, error: err.message || "Error generando factura" });
  }
});


// --------------------------- GET WALLET USER ---------------------------
app.get("/api/wallet/me", authRequired, async (req, res) => {
  try {
    const usuarioId = req.user.id;

    const r = await db.query(
      `
      SELECT id, usuario_id, public_key_pem, fingerprint, created_at, updated_at
      FROM wallets
      WHERE usuario_id = $1
    `,
      [usuarioId],
    );

    if (!r.rows.length) {
      return res.json({ ok: false, wallet: null });
    }

    res.json({ ok: true, wallet: r.rows[0] });
  } catch (err) {
    console.error("Error /api/wallet/me:", err);
    res.status(500).json({ ok: false, error: "Error obteniendo wallet" });
  }
});

// --------------------------- LISTAR WALLETS ---------------------------
app.get("/api/wallets", authRequired, adminOnly, async (req, res) => {
  try {
    const walletsMap = new Map();

    const rPending = await db.query(`SELECT id, data, created_at FROM pending_blocks`);
    for (const row of rPending.rows) {
      const meta = row.data?.meta;
      if (meta?.public_key_pem || meta?.fingerprint) {
        const fp = meta.public_key_pem
          ? sha256(meta.public_key_pem)
          : meta.fingerprint;

        if (!walletsMap.has(fp)) {
          walletsMap.set(fp, {
            fingerprint: fp,
            public_key_pem: meta.public_key_pem || null,
            first_seen: row.created_at,
            count: 1,
          });
        } else {
          walletsMap.get(fp).count++;
        }
      }
    }

    const rChain = await db.query(`SELECT id, data, fecha FROM blockchain`);
    for (const row of rChain.rows) {
      let payload;
      try {
        payload = isEncryptedBlock(row.data)
          ? decryptJSON(row.data)
          : row.data;
      } catch {
        continue;
      }

      const meta = payload?.meta;
      if (meta?.public_key_pem || meta?.fingerprint) {
        const fp = meta.public_key_pem
          ? sha256(meta.public_key_pem)
          : meta.fingerprint;

        if (!walletsMap.has(fp)) {
          walletsMap.set(fp, {
            fingerprint: fp,
            public_key_pem: meta.public_key_pem || null,
            first_seen: row.fecha,
            count: 1,
          });
        } else {
          walletsMap.get(fp).count++;
        }
      }
    }

    res.json({ ok: true, wallets: [...walletsMap.values()] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error obteniendo wallets" });
  }
});

// --------------------------- WALLET REGISTERED ---------------------------
app.get("/api/wallets/registered", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(
      `
      SELECT 
        w.id,
        w.usuario_id,
        u.nombre AS usuario,
        u.email,
        w.fingerprint,
        w.created_at,
        w.updated_at
      FROM wallets w
      JOIN usuarios u ON u.id = w.usuario_id
      ORDER BY w.id ASC
    `,
    );

    res.json({ ok: true, wallets: r.rows });
  } catch (err) {
    console.error("Error obteniendo wallets registradas:", err);
    res
      .status(500)
      .json({ ok: false, error: "Error obteniendo wallets registradas" });
  }
});

// --------------------------- VALIDAR UN BLOQUE ---------------------------
app.get("/api/blockchain/validate-one/:id", authRequired, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    const r = await db.query(
      `
      SELECT id, nonce, data, hash_actual, hash_anterior
      FROM blockchain
      WHERE id=$1
    `,
      [id],
    );

    if (!r.rows.length)
      return res.json({ ok: false, error: "Bloque no encontrado" });

    const b = r.rows[0];

    let payload = b.data;
    if (isEncryptedBlock(payload)) {
      try {
        payload = decryptJSON(payload);
      } catch {
        return res.json({ ok: false, error: "Bloque cifrado dañado" });
      }
    }

    const prev = b.hash_anterior || "0".repeat(64);
    const recalculated = computeBlockHash(prev, payload, b.nonce);

    if (recalculated !== b.hash_actual)
      return res.json({ ok: false, error: "Hash incorrecto" });

    if (!isValidProof(b.hash_actual, POW_DIFFICULTY))
      return res.json({ ok: false, error: "PoW inválido" });

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.json({ ok: false, error: "Error interno" });
  }
});

// --------------------------- VERIFICAR FIRMA RSA ---------------------------
app.get("/api/blockchain/verify-signature/:id", authRequired, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    const r = await db.query(
      `SELECT id, data, nonce FROM blockchain WHERE id=$1`,
      [id],
    );
    if (!r.rows.length)
      return res.json({ ok: false, error: "Bloque no encontrado" });

    let payload;
    const row = r.rows[0];

    try {
      payload = isEncryptedBlock(row.data)
        ? decryptJSON(row.data)
        : row.data;
    } catch {
      return res.json({ ok: false, error: "Bloque cifrado/dañado" });
    }

    const meta = payload.meta;
    if (!meta || !meta.public_key_pem || !meta.signature || !meta.nonce) {
      return res.json({ ok: false, error: "El bloque no contiene firma RSA" });
    }

    const messageObj = {
      venta: {
        productos: payload.productos,
        total: payload.total,
      },
      nonce: meta.nonce,
    };

    const message = canonicalStringify(messageObj);
    const valid = verifySignature(meta.public_key_pem, message, meta.signature);

    res.json({
      ok: true,
      valid,
      fingerprint: meta.fingerprint,
      key_filename: meta.key_filename || null,
    });
  } catch (err) {
    console.log(err);
    res.json({ ok: false, error: "Error verificando firma" });
  }
});

// --------------------------- AUDITORÍA COMPLETA ---------------------------
app.get("/api/blockchain/full-audit", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`SELECT * FROM blockchain ORDER BY id ASC`);
    let prevHash = "0".repeat(64);
    const problems = [];

    for (const b of r.rows) {
      let payload;

      try {
        payload = isEncryptedBlock(b.data)
          ? decryptJSON(b.data)
          : b.data;
      } catch {
        problems.push({ id: b.id, error: "Bloque cifrado dañado" });
        prevHash = b.hash_actual;
        continue;
      }

      if (b.hash_anterior !== prevHash)
        problems.push({ id: b.id, error: "hash_anterior inválido" });

      const recalculated = computeBlockHash(prevHash, payload, b.nonce);
      if (recalculated !== b.hash_actual)
        problems.push({ id: b.id, error: "hash_actual incorrecto" });

      if (!isValidProof(b.hash_actual, POW_DIFFICULTY))
        problems.push({ id: b.id, error: "PoW inválido" });

      prevHash = b.hash_actual;
    }

    res.json({ ok: problems.length === 0, problems });
  } catch (err) {
    console.error("ERROR full-audit:", err);
    return res.json({
      ok: false,
      problems: [{ error: "Error auditoría interna" }],
    });
  }
});

// --------------------------- MINAR UN SOLO PENDING ---------------------------
app.post("/api/mine/one", authRequired, adminOnly, async (req, res) => {
  try {
    const { id } = req.body || {};
    if (!id) return res.json({ ok: false, error: "Falta id" });

    const result = await minePendingBlock("admin", 5_000_000, id);
    return res.json(result);
  } catch (err) {
    console.log(err);
    res.json({ ok: false, error: "Error minando pending" });
  }
});

// --------------------------- NONCE PARA FIRMA ---------------------------
app.post("/api/venta/nonce", authRequired, async (req, res) => {
  try {
    const usuarioId = req.user.id;
    const nonce = crypto.randomBytes(24).toString("hex");
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    await db.query(
      `
      INSERT INTO nonces (usuario_id, nonce, expires_at, used)
      VALUES ($1,$2,$3,false)
    `,
      [usuarioId, nonce, expiresAt],
    );

    res.json({ ok: true, nonce, expires_at: expiresAt });
  } catch (err) {
    console.error("Error creando nonce:", err);
    res.status(500).json({ ok: false, error: "No se pudo generar nonce" });
  }
});

// Limpieza automática
setInterval(async () => {
  try {
    await db.query(`
      DELETE FROM nonces
      WHERE expires_at < NOW()
         OR (used = true AND created_at < NOW() - INTERVAL '7 days')
    `);
  } catch (err) {
    console.error("Error limpiando nonces:", err);
  }
}, 60 * 60 * 1000);

// --------------------------- STATIC ROUTES ---------------------------
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
// --------------------------- INIT DB ---------------------------
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

  await db.query(`
    CREATE TABLE IF NOT EXISTS pending_blocks (
      id SERIAL PRIMARY KEY,
      data JSONB NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      attempted INT NOT NULL DEFAULT 0
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS used_signatures (
      id SERIAL PRIMARY KEY,
      signature_hash TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

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

 await db.query(`
  CREATE TABLE IF NOT EXISTS wallets (
    id SERIAL PRIMARY KEY,
    usuario_id INT NOT NULL UNIQUE REFERENCES usuarios(id) ON DELETE CASCADE,
    public_key_pem TEXT NOT NULL,
    pin_hash TEXT NOT NULL,
    fingerprint TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  );
`);

await db.query(`
  DO $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_constraint 
      WHERE conname = 'unique_public_key'
    ) THEN
      ALTER TABLE wallets
      ADD CONSTRAINT unique_public_key UNIQUE (public_key_pem);
    END IF;
  END$$;
`);
;

  const r = await db.query("SELECT COUNT(*) FROM roles");
  if (parseInt(r.rows[0].count) === 0) {
    await db.query(`
      INSERT INTO roles(nombre) VALUES
      ('usuario'), ('admin'), ('proveedor')
    `);
  }
}

// --------------------------- MAIN ---------------------------
async function main() {
  await initDb();

  // *** Solo HTTP ***
  app.listen(PORT, () =>
    console.log(`Servidor HTTP en http://localhost:${PORT}`),
  );
}

main().catch((err) => console.error(err));
