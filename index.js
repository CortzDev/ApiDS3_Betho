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

// Cifrado de bloques
const { encryptJSON, decryptJSON } = require("./encrypt.js");

// Middlewares
const { authRequired, adminOnly, proveedorOnly } = require("./public/middlewares/auth.js");

// BASE HTTP - lo utiliz websocket
const http = require("http");
const WebSocket = require("ws");

// Configs
const PORT = parseInt(process.env.PORT || "3000", 10);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET no está definido.");
  process.exit(1);
}

const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "http://localhost:3000")
  .split(",");

// Helmet 
const helmetOptions = {
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://www.gstatic.com"],
      "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      "img-src": ["'self'", "data:", "blob:", "https://www.gravatar.com"],
      "connect-src": [
        "'self'",
        "http://localhost:3000",
        "ws://localhost:3000",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
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


// App Express 
const app = express();
app.set("trust proxy", 1);

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// CORS 
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (FRONTEND_ORIGINS.includes(origin)) return callback(null, true);
    return callback(null, false);
  },
  credentials: true,
}));

app.use(helmet(helmetOptions));


// DB 
const db = new Pool({
  user: process.env.PGUSER || "postgres",
  password: process.env.PGPASSWORD || "12345",
  database: process.env.PGDATABASE || "railway",
  host: process.env.PGHOST || "localhost",
  port: parseInt(process.env.PGPORT || "5432", 10),
});

// UTILS
function sha256(x) {
  return crypto.createHash("sha256").update(x).digest("hex");
}

function canonicalStringify(obj) {
  if (obj === null) return "null";

  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalStringify).join(",") + "]";
  }

  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    return "{" + keys.map(k =>
      JSON.stringify(k) + ":" + canonicalStringify(obj[k])
    ).join(",") + "}";
  }

  return JSON.stringify(obj);
}


// Verifica firmas RSA
function verifySignature(publicKeyPem, message, signatureBase64) {
  try {
    const verify = crypto.createVerify("SHA256");
    verify.update(message, "utf8");
    verify.end();
    return verify.verify(publicKeyPem, signatureBase64, "base64");
  } catch (err) {
    console.error("Error verifySignature:", err);
    return false;
  }
}

// Valida PEM
function validatePublicKeyPem(publicKeyPem) {
  if (!publicKeyPem || typeof publicKeyPem !== "string") {
    return { ok: false, error: "Clave pública vacía" };
  }
  if (publicKeyPem.trim().startsWith("ssh-rsa ")) return { ok: true };
  if (
    publicKeyPem.includes("-----BEGIN PUBLIC KEY-----") &&
    publicKeyPem.includes("-----END PUBLIC KEY-----")
  ) return { ok: true };

  if (
    publicKeyPem.includes("-----BEGIN RSA PUBLIC KEY-----") &&
    publicKeyPem.includes("-----END RSA PUBLIC KEY-----")
  ) return { ok: true };

  return { ok: false, error: "Formato no reconocido" };
}

// HASH POW - (POW 4)
const POW_DIFFICULTY = parseInt(process.env.POW_DIFFICULTY || "4", 10);

function computeBlockHash(prevHash, payloadObj, nonce) {
  const serialized = canonicalStringify(payloadObj);
  return sha256(prevHash + serialized + nonce);
}
function isValidProof(hashHex, difficulty) {
  return hashHex.startsWith("0".repeat(difficulty));
}


// 🟣 WEBSOCKET SERVER — SISTEMA DE REPLICACIÓN
const server = http.createServer(app); 

const wss = new WebSocket.Server({ 
  server,
  path: "/replicacion"
});

const wsClients = new Set();

function wsBroadcast(type, payload = {}) {
  const msg = JSON.stringify({ type, payload, ts: Date.now() });

  for (const client of wsClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  }
}


// Valida JWT con conexión WebSocket

function authenticateWS(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.rol !== "admin") return null;
    return decoded;
  } catch (err) {
    return null;
  }
}

// WebSocket events
wss.on("connection", (ws, request) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  const token = url.searchParams.get("token");

  const user = authenticateWS(token);
  if (!user) {
    ws.close();
    return;
  }

  ws.user = user;
  wsClients.add(ws);

  // Notificar nuevo admin conectado
  wsBroadcast("admin_connected", { user });

  ws.on("close", () => {
    wsClients.delete(ws);
    wsBroadcast("admin_disconnected", { id: user.id });
  });

  ws.on("error", () => {});
});

console.log("🟣 WebSocket replicación listo en /replicacion");

//Dashboard en tiempo real
// Cuando se agrega pending block
function wsPendingUpdated() {
  wsBroadcast("pending_updated", {});
}
// Cuando se mina un bloque
function wsBlockMined(blockInfo) {
  wsBroadcast("block_mined", blockInfo);
}
// Cuando hay cambios en los usuarios conectados
function wsUserCount(count) {
  wsBroadcast("user_count", { count });
}
// Cambios de wallet
function wsWalletRegistered(wallet) {
  wsBroadcast("wallet_registered", wallet);
}
// Nueva venta
function wsVentaRegistered(data) {
  wsBroadcast("venta_registered", data);
}
// Modificación de stock
function wsStockChange(info) {
  wsBroadcast("stock_changed", info);
}

//Mining helpers 
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

    let nonce = null, hash = null;
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
        [pending.id]
      );
      await client.query("COMMIT");
      return { ok: false, error: "No se encontró un nonce válido" };
    }

    const encryptedData = encryptJSON(payload);
    const now = new Date().toISOString();

    const insertRes = await client.query(
      `INSERT INTO blockchain (nonce, data, hash_actual, hash_anterior, fecha)
       VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [nonce, encryptedData, hash, prevHash, now]
    );

    await client.query(`DELETE FROM pending_blocks WHERE id=$1`, [pending.id]);
    await client.query("COMMIT");

    const blockId = insertRes.rows[0]?.id || null;

    // Emitir evento WS: bloque minado
    try {
      wsBlockMined({ id: blockId, nonce, hash, prevHash, fecha: now, data: payload });
      // Notificar que cambió el estado de pending
      wsPendingUpdated();
    } catch (e) {
      console.error("Error emitiendo evento WS en minePendingBlock:", e);
    }

    return {
      ok: true,
      hash,
      nonce,
      blockData: payload,
      miner: minerName || "unknown",
      blockId,
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Error minando:", err);
    return { ok: false, error: err.message };
  } finally {
    client.release();
  }
}

// Registrar Bloques (ventas -> pending) 
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

  const r = await db.query(`INSERT INTO pending_blocks (data) VALUES ($1) RETURNING id, created_at`, [payload]);

  // Emitir WS: nuevo pending agregado
  try {
    wsPendingUpdated();
    wsVentaRegistered({ ventaId, usuarioId, pendingId: r.rows[0].id });
  } catch (e) {
    console.error("Error emitiendo WS en registrarBloqueVenta:", e);
  }
}

async function registrarEnPending(operacion, dataObj) {
  const payload = {
    operacion,
    data: dataObj,
    timestamp: new Date().toISOString(),
  };

  const r = await db.query(`INSERT INTO pending_blocks (data) VALUES ($1) RETURNING id`, [payload]);

  // Emitir WS
  try {
    wsPendingUpdated();
  } catch (e) {
    console.error("Error emitiendo WS en registrarEnPending:", e);
  }
}

// Helper: contar usuarios conectados (últimos 2 minutos)
async function broadcastUserCountFromDB() {
  try {
    const r = await db.query(`
      SELECT COUNT(*) AS total
      FROM usuarios
      WHERE ultimo_login > NOW() - INTERVAL '2 minutes'
    `);
    const count = parseInt(r.rows[0].total || 0, 10);
    wsUserCount(count);
  } catch (err) {
    console.error("Error broadcastUserCountFromDB:", err);
  }
}

// RUTAS / ENDPOINTS

// raíz
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};

  try {
    const r = await db.query(
      `SELECT u.id, u.nombre, u.password, u.ultimo_login, r.nombre AS rol
       FROM usuarios u
       JOIN roles r ON r.id = u.rol_id
       WHERE email=$1`,
      [email]
    );

    if (!r.rows.length) {
      return res.status(400).json({ ok: false, error: "Usuario no encontrado" });
    }

    const user = r.rows[0];

    // Validar contraseña
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ ok: false, error: "Credenciales incorrectas" });
    }

    // Si es proveedor → registrar si no existe
    if (user.rol === "proveedor") {
      await db.query(
        `INSERT INTO proveedor (usuario_id)
         VALUES ($1)
         ON CONFLICT (usuario_id) DO NOTHING`,
        [user.id]
      );
    }

    // MARCAR ULTIMO LOGIN
    await db.query(
      `UPDATE usuarios SET ultimo_login = NOW() WHERE id = $1`,
      [user.id]
    );

    // Generar JWT
    const token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol }, JWT_SECRET, { expiresIn: "2h" });

    // Broadcast: actualizar conteo de usuarios conectados
    broadcastUserCountFromDB().catch(() => {});

    return res.json({
      ok: true,
      token,
      usuario: { id: user.id, nombre: user.nombre, rol: user.rol }
    });

  } catch (err) {
    console.error("❌ ERROR /api/login:", err);
    return res.status(500).json({ ok: false, error: "Error interno del servidor" });
  }
});

// PERFIL
app.get("/api/perfil", authRequired, async (req, res) => {
  try {
    const r = await db.query(
      `SELECT u.id, u.nombre, u.email, r.nombre AS rol
       FROM usuarios u
       JOIN roles r ON r.id = u.rol_id
       WHERE u.id=$1`,
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
      SELECT p.id, u.nombre, u.email, p.empresa, p.telefono, p.direccion
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
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);
    if (!rProv.rows.length) return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const productos = await db.query(`
      SELECT p.id, p.nombre, p.descripcion, p.precio, p.stock,
             p.categoria_id, c.nombre AS categoria
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

// CREAR PRODUCTO PROVEEDOR
app.post("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  const { nombre, descripcion, categoria_id, precio, stock } = req.body || {};

  try {
    const rProv = await db.query("SELECT id FROM proveedor WHERE usuario_id=$1", [req.user.id]);
    if (!rProv.rows.length) return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const r = await db.query(`
      INSERT INTO productos(nombre, descripcion, categoria_id, proveedor_id, precio, stock)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING *
    `, [nombre, descripcion, categoria_id, proveedorId, precio, stock]);

    // Opcional: emitir evento de stock/creación
    try { wsStockChange({ producto: r.rows[0] }); } catch (e) {}

    res.json({ ok: true, producto: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// PRODUCTOS DISPONIBLES (público interno)
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
    console.error("Error al obtener productos:", err);
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

// REGISTRO DE USUARIO
app.post("/api/register", async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password || !rol) {
      return res.status(400).json({ ok: false, error: "Todos los campos son obligatorios." });
    }

    const r = await db.query("SELECT id FROM roles WHERE nombre=$1", [rol]);
    if (!r.rows.length) {
      return res.status(400).json({ ok: false, error: "Rol inválido." });
    }

    const rol_id = r.rows[0].id;

    const existe = await db.query("SELECT id FROM usuarios WHERE email=$1", [email]);
    if (existe.rows.length > 0) {
      return res.status(400).json({ ok: false, error: "El correo ya está registrado." });
    }

    const hashed = await bcrypt.hash(password, 10);

    const result = await db.query(`
      INSERT INTO usuarios (nombre, email, password, rol_id)
      VALUES ($1, $2, $3, $4)
      RETURNING id, nombre, email, rol_id
    `, [nombre, email, hashed, rol_id]);

    res.status(201).json({ ok: true, message: "Usuario registrado correctamente ✔", user: result.rows[0] });

    // Broadcast: conteo actualizado si es un usuario admin
    broadcastUserCountFromDB();

  } catch (err) {
    console.error("❌ Error en /api/register:", err);
    return res.status(500).json({ ok: false, error: "Error interno del servidor." });
  }
});

//VENTA CON FIRMA RSA
app.post("/api/usuario/venta", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { productos, signature, public_key_pem, key_filename, nonce } =
    req.body || {};

  if (!Array.isArray(productos) || productos.length === 0)
    return res.status(400).json({ ok: false, error: "Debe enviar productos" });

  for (const p of productos) {
    if (!isValidInteger(p.producto_id))
      return res.status(400).json({ ok: false, error: "producto_id inválido" });
    if (!isValidInteger(p.cantidad))
      return res.status(400).json({ ok: false, error: "cantidad inválida" });
    if (p.precio_unitario !== undefined && !isValidNonNegativeNumber(p.precio_unitario))
      return res.status(400).json({ ok: false, error: "precio_unitario inválido" });
  }

  // ========== MODO FIRMA ==========
  if (signature || public_key_pem || nonce) {
    if (!signature || !public_key_pem || !nonce) {
      return res.status(400).json({ ok: false, error: "Faltan signature/public_key/nonce" });
    }

    const vpub = validatePublicKeyPem(public_key_pem);
    if (!vpub.ok)
      return res.status(400).json({ ok: false, error: "public_key_pem inválida: " + vpub.error });

    try {
      const rNonce = await db.query(
        "SELECT id, usuario_id, expires_at, used FROM nonces WHERE nonce=$1",
        [nonce]
      );

      if (!rNonce.rows.length)
        return res.status(400).json({ ok: false, error: "Nonce no encontrado" });

      const row = rNonce.rows[0];

      if (row.usuario_id !== usuarioId)
        return res.status(403).json({ ok: false, error: "Nonce no pertenece al usuario" });

      if (row.used)
        return res.status(400).json({ ok: false, error: "Nonce ya usado" });

      if (new Date(row.expires_at) < new Date())
        return res.status(400).json({ ok: false, error: "Nonce expirado" });

      // Construir venta
      const venta = {
        productos: productos.map((p) => ({
          producto_id: Number(p.producto_id),
          cantidad: Number(p.cantidad),
          precio_unitario:
            p.precio_unitario !== undefined ? Number(p.precio_unitario) : undefined,
        })),
        total: productos.reduce((sum, p) => {
          const u = p.precio_unitario !== undefined ? Number(p.precio_unitario) : 0;
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
        await db.query("INSERT INTO used_signatures(signature_hash) VALUES($1)", [signatureHash]);
      } catch {
        return res.status(400).json({ ok: false, error: "Firma ya usada" });
      }

      // Guardar la venta + modificar stock
      const client = await db.connect();
      try {
        await client.query("BEGIN");

        const rVenta = await client.query(
          `INSERT INTO ventas(usuario_id, total) VALUES ($1,$2) RETURNING id, fecha`,
          [usuarioId, venta.total]
        );

        const ventaId = rVenta.rows[0].id;

        for (const p of productos) {
          const rStock = await client.query(
            "SELECT stock, precio FROM productos WHERE id=$1 FOR UPDATE",
            [p.producto_id]
          );

          if (!rStock.rows.length) throw new Error("Producto no existe");

          const stockActual = rStock.rows[0].stock;
          const precioActual = parseFloat(rStock.rows[0].precio);

          if (stockActual < p.cantidad) throw new Error("Stock insuficiente");

          await client.query(
            `INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
             VALUES ($1,$2,$3,$4)`,
            [
              ventaId,
              p.producto_id,
              p.cantidad,
              p.precio_unitario !== undefined ? p.precio_unitario : precioActual,
            ]
          );

          // Actualizar stock
          await client.query(
            "UPDATE productos SET stock = stock - $1 WHERE id=$2",
            [p.cantidad, p.producto_id]
          );
        }

        await client.query(
          "UPDATE nonces SET used = true WHERE nonce = $1",
          [nonce]
        );

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
          meta
        );

        await client.query("COMMIT");

        // WS: Notificar venta
        try {
          wsVentaRegistered({ ventaId, usuarioId });
          wsStockChange({});
        } catch {}

        res.json({ ok: true, ventaId });

      } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error registrando venta firmada:", err);
        return res.status(500).json({ ok: false, error: err.message });
      } finally {
        client.release();
      }
      return;
    } catch (err) {
      console.error("Error validando firma:", err);
      return res.status(500).json({ ok: false, error: "Error interno en firma" });
    }
  }

  // ========== MODO LEGACY ==========
  const client2 = await db.connect();
  try {
    await client2.query("BEGIN");

    const total = productos.reduce((sum, p) => {
      const pu = p.precio_unitario !== undefined ? Number(p.precio_unitario) : 0;
      return sum + Number(p.cantidad) * pu;
    }, 0);

    const rVenta = await client2.query(
      `INSERT INTO ventas(usuario_id, total)
       VALUES ($1,$2) RETURNING id, fecha`,
      [usuarioId, total]
    );

    const ventaId = rVenta.rows[0].id;

    for (const p of productos) {
      const rStock = await client2.query(
        "SELECT stock, precio FROM productos WHERE id=$1 FOR UPDATE",
        [p.producto_id]
      );

      if (!rStock.rows.length) throw new Error("Producto no existe");

      const stockActual = rStock.rows[0].stock;
      const precioActual = parseFloat(rStock.rows[0].precio);

      if (stockActual < p.cantidad) throw new Error("Stock insuficiente");

      await client2.query(
        `INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
         VALUES ($1,$2,$3,$4)`,
        [
          ventaId,
          p.producto_id,
          p.cantidad,
          p.precio_unitario !== undefined ? p.precio_unitario : precioActual,
        ]
      );

      await client2.query(
        "UPDATE productos SET stock = stock - $1 WHERE id=$2",
        [p.cantidad, p.producto_id]
      );
    }

    await registrarBloqueVenta(ventaId, usuarioId, total, productos);

    await client2.query("COMMIT");

    wsVentaRegistered({ ventaId, usuarioId });
    wsStockChange({});

    res.json({ ok: true, ventaId });

  } catch (err) {
    await client2.query("ROLLBACK");
    console.error("Error registrando venta:", err);
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    client2.release();
  }
});

// WALLET REGISTER
app.post("/api/wallet/register", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { public_key_pem, pin } = req.body;

  if (!public_key_pem || !pin)
    return res.status(400).json({ ok: false, error: "Faltan datos" });

  if (pin.length < 4 || pin.length > 10)
    return res.status(400).json({ ok: false, error: "PIN inválido" });

  let finalPem = sshToPem(public_key_pem) || public_key_pem;

  let vpub = validatePublicKeyPem(finalPem);
  if (!vpub.ok) {
    return res.status(400).json({
      ok: false,
      error: "La clave pública debe ser RSA. Otros formatos no se aceptan."
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

    wsWalletRegistered({ usuarioId, fingerprint });

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

// VENTA CON PIN 
app.post("/api/usuario/venta-pin", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { productos, pin } = req.body;

  if (!pin || !Array.isArray(productos))
    return res.status(400).json({ ok: false, error: "Datos incompletos" });

  const w = await db.query("SELECT * FROM wallets WHERE usuario_id=$1", [usuarioId]);
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
      0
    );

    const rVenta = await client.query(
      `INSERT INTO ventas(usuario_id, total)
       VALUES ($1,$2) RETURNING id`,
      [usuarioId, total]
    );

    const ventaId = rVenta.rows[0].id;

    for (const p of productos) {
      await client.query(
        `INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
         VALUES ($1,$2,$3,$4)`,
        [ventaId, p.producto_id, p.cantidad, p.precio_unitario]
      );

      await client.query(
        `UPDATE productos SET stock = stock - $1 WHERE id=$2`,
        [p.cantidad, p.producto_id]
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

    wsVentaRegistered({ ventaId, usuarioId });
    wsStockChange({});

    return res.json({ ok: true, ventaId });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error registrando venta" });
  }
});

// INVOICE (Paquete cifrado)
async function createEncryptedInvoicePackage(ventaId, usuarioId) {
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

  const rWallet = await db.query("SELECT public_key_pem FROM wallets WHERE usuario_id=$1", [usuarioId]);
  if (!rWallet.rows.length) throw new Error("Usuario no tiene wallet registrada");

  const publicKeyPem = rWallet.rows[0].public_key_pem;

  let pubKeyObj;
  try {
    pubKeyObj = crypto.createPublicKey(publicKeyPem);
  } catch {
    throw new Error("Clave pública no parseable");
  }
  if (pubKeyObj.asymmetricKeyType !== "rsa") {
    throw new Error("Solo se soportan claves RSA para factura");
  }

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

  const compressed = zlib.gzipSync(Buffer.from(invoiceJson, "utf8"));

  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const encryptedKey = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    aesKey
  );

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

  return { buffer: packageBuffer, filename: `invoice_${ventaId}.invoice` };
}

app.post("/api/usuario/invoice-generate", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  let ventaId = req.body?.ventaId;

  if (!ventaId)
    return res.status(400).json({ ok: false, error: "ventaId faltante" });

  try {
    const r = await db.query("SELECT usuario_id FROM ventas WHERE id=$1", [ventaId]);

    if (!r.rows.length)
      return res.status(404).json({ ok: false, error: "Venta no encontrada" });

    if (r.rows[0].usuario_id !== usuarioId)
      return res.status(403).json({ ok: false, error: "No autorizado" });

    const pkg = await createEncryptedInvoicePackage(ventaId, usuarioId);

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${pkg.filename}"`);
    return res.send(pkg.buffer);

  } catch (err) {
    console.error("Error en invoice-generate:", err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// WALLET ME
app.get("/api/wallet/me", authRequired, async (req, res) => {
  try {
    const usuarioId = req.user.id;

    const r = await db.query(`
      SELECT id, usuario_id, public_key_pem, fingerprint, created_at, updated_at
      FROM wallets
      WHERE usuario_id = $1
    `, [usuarioId]);

    if (!r.rows.length) {
      return res.json({ ok: false, wallet: null });
    }

    res.json({ ok: true, wallet: r.rows[0] });
  } catch (err) {
    console.error("Error /api/wallet/me:", err);
    res.status(500).json({ ok: false, error: "Error obteniendo wallet" });
  }
});

// LISTAR WALLETS (Admin)
app.get("/api/wallets/registered", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
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
    `);

    res.json({ ok: true, wallets: r.rows });
  } catch (err) {
    console.error("Error obteniendo wallets registradas:", err);
    res.status(500).json({ ok: false, error: "Error obteniendo wallets registradas" });
  }
});

// PENDING BLOCKS 
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

// USUARIOS CONECTADOS
app.get("/api/usuarios/conectados", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT COUNT(*) AS total
      FROM usuarios
      WHERE ultimo_login > NOW() - INTERVAL '5 minutes'
    `);

    res.json({ ok: true, count: parseInt(r.rows[0].total) });

  } catch (err) {
    console.error("ERROR /api/usuarios/conectados:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// MINAR BLOQUE
app.post("/api/mine", authRequired, adminOnly, async (req, res) => {
  try {
    const { miner_name } = req.body || {};

    // 1) Verificar si hay blocks pendientes
    const rPending = await db.query(
      "SELECT id FROM pending_blocks ORDER BY id ASC LIMIT 1"
    );

    if (!rPending.rows.length) {
      return res.status(400).json({
        ok: false,
        error: "No hay bloques pendientes para minar"
      });
    }

    const pendingId = rPending.rows[0].id;

    // 2) Intentar minar
    console.log("[MINE] Iniciando minado del pending", pendingId);

    const result = await minePendingBlock(miner_name || "admin", 5_000_000, pendingId);

    if (!result.ok) {
      console.warn("[MINE] Falló minado:", result.error);
      return res.status(400).json(result);
    }

    // 3) Respuesta correcta
    return res.json({
      ok: true,
      mined: result
    });

  } catch (err) {
    console.error("❌ ERROR /api/mine:", err);
    return res.status(500).json({
      ok: false,
      error: err.message || "Error interno al minar"
    });
  }
});


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

function isEncryptedBlock(data) {
  if (!data) return false;
  return (
    typeof data === "object" &&
    data !== null &&
    typeof data.iv === "string" &&
    typeof data.tag === "string" &&
    typeof data.ciphertext === "string"
  );
}



// BLOCKCHAIN LECTURA
app.get("/api/blockchain", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT id, nonce, data, hash_actual, hash_anterior, fecha
      FROM blockchain
      ORDER BY id ASC
    `);

    const blocks = [];
    let prevHash = "0".repeat(64);

    for (const b of r.rows) {

      let payload;
        if (isEncryptedBlock(b.data)) {
          try {
            payload = decryptJSON(b.data);
          } catch (err) {
            console.error("❌ Error descifrando bloque:", b.id, err);
            payload = { error: "bloque_encriptado_corrupto" };
          }
        } else {
          payload = b.data; // bloque plano normal
        }

      const serialized = canonicalStringify(payload);
      const recalculated = sha256(prevHash + serialized + b.nonce);
      const powValid = isValidProof(b.hash_actual, POW_DIFFICULTY);

      const valido = recalculated === b.hash_actual && powValid;

      blocks.push({
        id: b.id,
        fecha: b.fecha,
        nonce: b.nonce,
        data: payload,
        hash_anterior: b.hash_anterior,
        hash_actual: b.hash_actual,
        total_venta: payload?.total || null,
        valido
      });

      prevHash = b.hash_actual;
    }

    return res.json({ ok: true, cadena: blocks });

  } catch (err) {
    console.error("ERROR /api/blockchain:", err);
    return res.status(500).json({
      ok: false,
      error: "Error interno obteniendo blockchain"
    });
  }
});



// DETALLE BLOQUE
app.get("/api/blockchain/:id", authRequired, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) return res.json({ ok: false, error: "ID inválido" });

  try {
    const r = await db.query(`
      SELECT id, nonce, data, hash_actual, hash_anterior, fecha
      FROM blockchain
      WHERE id=$1
    `, [id]);

    if (!r.rows.length)
      return res.json({ ok: false, error: "Bloque no encontrado" });

    const b = r.rows[0];

    let payload;
    try {
      payload = isEncryptedBlock(b.data)
        ? decryptJSON(b.data)
        : b.data;
    } catch {
      payload = { error: "Bloque ilegible" };
    }

    return res.json({
      ok: true,
      bloque: {
        ...b,
        data: payload
      }
    });

  } catch (err) {
    console.error("ERROR /blockchain/:id:", err);
    return res.status(500).json({ ok: false });
  }
});


// VALIDAR CADENA COMPLETA 
app.get("/api/blockchain/validate", authRequired, adminOnly, async (req, res) => {
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

      const serialized = canonicalStringify(payload);

      // Validar enlace
      if (b.hash_anterior !== prevHash)
        problems.push({ id: b.id, error: "hash_anterior inválido" });

      // Validar hash
      const recalculated = sha256(prevHash + serialized + b.nonce);
      if (recalculated !== b.hash_actual)
        problems.push({ id: b.id, error: "hash_actual incorrecto" });

      // Validar POW
      if (!isValidProof(b.hash_actual, POW_DIFFICULTY))
        problems.push({ id: b.id, error: "PoW inválido" });

      prevHash = b.hash_actual;
    }

    return res.json({ ok: problems.length === 0, problems });

  } catch (err) {
    console.error("ERROR validate:", err);
    return res.status(500).json({
      ok: false,
      error: "Error validando blockchain"
    });
  }
});


// VALIDAR BLOQUE INDIVIDUAL 
app.get("/api/blockchain/validate-one/:id", authRequired, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    const r = await db.query(`
      SELECT id, nonce, data, hash_actual, hash_anterior
      FROM blockchain
      WHERE id=$1
    `, [id]);

    if (!r.rows.length)
      return res.json({ ok: false, error: "Bloque no encontrado" });

    const b = r.rows[0];

    let payload;
    try {
      payload = isEncryptedBlock(b.data)
        ? decryptJSON(b.data)
        : b.data;
    } catch {
      return res.json({ ok: false, error: "Bloque cifrado dañado" });
    }

    const serialized = canonicalStringify(payload);
    const prev = b.hash_anterior || "0".repeat(64);

    const recalculated = sha256(prev + serialized + b.nonce);

    if (recalculated !== b.hash_actual)
      return res.json({ ok: false, error: "Hash incorrecto" });

    if (!isValidProof(b.hash_actual, POW_DIFFICULTY))
      return res.json({ ok: false, error: "PoW inválido" });

    return res.json({ ok: true });

  } catch (err) {
    console.log(err);
    return res.json({ ok: false, error: "Error interno" });
  }
});


// AUDITORÍA COMPLETA 
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

      const serialized = canonicalStringify(payload);

      if (b.hash_anterior !== prevHash)
        problems.push({ id: b.id, error: "hash_anterior incorrecto" });

      const recalculated = sha256(prevHash + serialized + b.nonce);
      if (recalculated !== b.hash_actual)
        problems.push({ id: b.id, error: "hash_actual incorrecto" });

      if (!isValidProof(b.hash_actual, POW_DIFFICULTY))
        problems.push({ id: b.id, error: "PoW inválido" });

      prevHash = b.hash_actual;
    }

    return res.json({ ok: problems.length === 0, problems });

  } catch (err) {
    console.error("ERROR full-audit:", err);
    return res.json({
      ok: false,
      problems: [{ error: "Error auditoría interna" }]
    });
  }
});


async function initDB() {
  try {
    await db.query("SELECT NOW()");
    console.log("📦 Conexión a PostgreSQL OK");
  } catch (err) {
    console.error("❌ Error conectando a PostgreSQL:", err);
    process.exit(1);
  }
}

initDB();

// ADMIN
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// USUARIO
app.get("/usuario", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "usuario.html"));
});

// PROVEEDOR
app.get("/proveedor", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "proveedor.html"));
});



// SERVIR FRONTEND 
app.use("/", express.static(path.join(__dirname, "public")));
app.use("/css", express.static(path.join(__dirname, "public/css")));
app.use("/js", express.static(path.join(__dirname, "public/js")));
app.use("/assets", express.static(path.join(__dirname, "public/assets")));


// FALLBACK 404 
app.use((req, res) => {
  res.status(404).json({ ok: false, error: "Ruta no encontrada" });
});

// ARRANQUE DEL SERVIDOR 
server.listen(PORT, () => {
  console.log(`🚀 Servidor backend activo en http://localhost:${PORT}`);
  console.log("🌐 WebSocket replicación listo en /replicacion");
});
