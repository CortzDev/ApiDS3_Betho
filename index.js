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
const fs = require("fs");
const https = require("https");

// Encriptación de bloques (tu encrypt.js)
const { encryptJSON, decryptJSON } = require("./encrypt.js");

// Middlewares
const { authRequired, adminOnly, proveedorOnly } = require("./public/middlewares/auth.js");

// --------------------------- Configs / Env checks ---------------------------
const PORT = parseInt(process.env.PORT || "3000", 10);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET no está definido. Define la variable de entorno y vuelve a ejecutar.");
  process.exit(1);
}

const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "http://localhost:3000").split(",");

// -------------------------------- HTTPS options --------------------------------
// Lee server.key / server.cert (debes generarlos y colocarlos en la raíz del proyecto)
const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, "server.key")),
  cert: fs.readFileSync(path.join(__dirname, "server.cert")),
};

// --------------------------- Helmet / Security ---------------------------
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
      "connect-src": ["'self'", "http://localhost:3000", "https://www.gstatic.com", "data:"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      "frame-src": ["'self'"],
      "object-src": ["'none'"]
    }
  },

  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false
};

// --------------------------- App setup ---------------------------
const app = express();

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// CORS: permitimos orígenes listados
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (FRONTEND_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('CORS policy: origin no permitida'), false);
  },
  credentials: true
}));

app.use(helmet(helmetOptions));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// --------------------------- DB ---------------------------
const db = new Pool({
  user: process.env.PGUSER || "postgres",
  password: process.env.PGPASSWORD || "12345",
  database: process.env.PGDATABASE || "railway",
  host: process.env.PGHOST || "localhost",
  port: parseInt(process.env.PGPORT || "5432", 10)
});

// --------------------------- UTIL / CRYPTO HELPERS ---------------------------
function sha256(x) {
  return crypto.createHash("sha256").update(x).digest("hex");
}

// Canonical stringify (mantener compatible con cliente)
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalStringify).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
}

// Verificar firma RSA-SHA256
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

// Validar formato PEM
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

// --------------------------- PoW / MINERÍA ---------------------------
const POW_DIFFICULTY = parseInt(process.env.POW_DIFFICULTY || "4", 10);

// hash = sha256(prevHash + canonical(payload) + nonce)
function computeBlockHash(prevHash, payloadObj, nonce) {
  const serialized = canonicalStringify(payloadObj);
  return sha256(prevHash + serialized + nonce);
}

// Debe empezar con N ceros hexadecimales
function isValidProof(hashHex, difficulty) {
  return hashHex.startsWith("0".repeat(difficulty));
}

// Valida bloque minado (ahora descifra si es necesario)
async function verifyBlockRow(row) {
  try {
    const prevHash = row.hash_anterior || "0".repeat(64);
    const nonce = row.nonce;

    // row.data puede ser:
    //  - objeto cifrado { iv, value, tag }  (JSONB)
    //  - o objeto ya en claro (legacy)
    let payload = row.data;
    try {
      if (payload && payload.iv && payload.value && payload.tag) {
        payload = decryptJSON(payload);
      }
    } catch (err) {
      // si falla el descifrado, considerarlo inválido
      throw new Error("No se pudo descifrar data del bloque");
    }

    const computed = computeBlockHash(prevHash, payload, nonce);
    if (computed !== row.hash_actual) throw new Error("hash_actual no coincide");
    if (!isValidProof(row.hash_actual, POW_DIFFICULTY)) throw new Error("PoW inválido");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// Obtener último hash
async function getLastHash() {
  const r = await db.query("SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1");
  return r.rows.length ? r.rows[0].hash_actual : "0".repeat(64);
}
// --------------------------- MINAR PENDING BLOCK (CIFRADO AGREGADO) ---------------------------
async function minePendingBlock(minerName = null, maxAttempts = 5_000_000) {
  const client = await db.connect();
  try {
    await client.query("BEGIN");

    // Tomar el siguiente pending_block
    const r = await client.query(`
      SELECT id, data 
      FROM pending_blocks 
      ORDER BY id ASC 
      LIMIT 1 
      FOR UPDATE SKIP LOCKED
    `);
    if (!r.rows.length) {
      await client.query("ROLLBACK");
      return { ok: false, error: "No hay bloques pendientes" };
    }

    const pending = r.rows[0];
    const payload = pending.data;

    // hash_prev actual
    const prev = await client.query(`
      SELECT hash_actual FROM blockchain ORDER BY id DESC LIMIT 1
    `);
    const prevHash = prev.rows.length ? prev.rows[0].hash_actual : "0".repeat(64);

    // Intento de minado
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
      return { ok: false, error: "No se encontró un nonce válido en el límite de intentos" };
    }

    // -------------------------------
    // Cifrar bloque antes de guardarlo
    // -------------------------------
    const encryptedData = encryptJSON(payload);

    const now = new Date().toISOString();
    await client.query(
      `INSERT INTO blockchain (nonce, data, hash_actual, hash_anterior, fecha)
       VALUES ($1,$2,$3,$4,$5)`,
      [nonce, encryptedData, hash, prevHash, now]
    );

    // Eliminar de pending_blocks
    await client.query(`DELETE FROM pending_blocks WHERE id=$1`, [pending.id]);

    await client.query("COMMIT");

    return {
      ok: true,
      hash,
      nonce,
      blockData: payload,
      miner: minerName || "unknown"
    };

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error minando:", err);
    return { ok: false, error: err.message };
  } finally {
    client.release();
  }
}

// --------------------------- Registrar Bloques (Ahora en pending) ---------------------------
async function registrarBloqueVenta(ventaId, usuarioId, total, items, meta = {}) {
  const timestamp = new Date().toISOString();

  const data = {
    operacion: "venta",
    venta_id: ventaId,
    usuario_id: usuarioId,
    total,
    productos: items,
    meta,
    timestamp
  };

  await db.query(
    `INSERT INTO pending_blocks (data) VALUES ($1)`,
    [data]
  );
}

async function registrarEnPending(operacion, dataObj) {
  const payload = {
    operacion,
    data: dataObj,
    timestamp: new Date().toISOString()
  };

  await db.query(
    `INSERT INTO pending_blocks (data) VALUES ($1)`,
    [payload]
  );
}

// --------------------------- ENDPOINTS COMUNES ---------------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// --------------------------- LOGIN ---------------------------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const r = await db.query(`
      SELECT u.id, u.nombre, u.password, r.nombre AS rol
      FROM usuarios u
      JOIN roles r ON r.id = u.rol_id
      WHERE email=$1
    `, [email]);

    if (!r.rows.length) return res.status(400).json({ ok: false });

    const user = r.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ ok: false });

    if (user.rol === "proveedor") {
      await db.query(`
        INSERT INTO proveedor (usuario_id)
        VALUES ($1)
        ON CONFLICT (usuario_id) DO NOTHING
      `, [user.id]);
    }

    const token = jwt.sign(
      { id: user.id, nombre: user.nombre, rol: user.rol },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      ok: true,
      token,
      usuario: { id: user.id, nombre: user.nombre, rol: user.rol }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// --------------------------- PERFIL ---------------------------
app.get("/api/perfil", authRequired, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT u.id, u.nombre, u.email, r.nombre AS rol
      FROM usuarios u
      JOIN roles r ON r.id = u.rol_id
      WHERE u.id=$1
    `, [req.user.id]);

    res.json({ ok: true, usuario: r.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// --------------------------- CATEGORÍAS ---------------------------
app.get("/api/categorias", authRequired, async (req, res) => {
  try {
    const r = await db.query("SELECT id, nombre FROM categorias ORDER BY id");
    res.json({ ok: true, categorias: r.rows });
  } catch (err) {
    console.error("Error al obtener categorías:", err);
    res.status(500).json({ ok: false, error: "Error al obtener categorías" });
  }
});

// --------------------------- PROVEEDORES (ADMIN) ---------------------------
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

// --------------------------- PRODUCTOS DEL PROVEEDOR ---------------------------
app.get("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id]
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

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
// --------------------------- CREAR PRODUCTO PROVEEDOR ---------------------------
app.post("/api/proveedor/productos", authRequired, proveedorOnly, async (req, res) => {
  const { nombre, descripcion, categoria_id, precio, stock } = req.body;

  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id]
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const r = await db.query(
      `INSERT INTO productos(nombre, descripcion, categoria_id, proveedor_id, precio, stock)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [nombre, descripcion, categoria_id, proveedorId, precio, stock]
    );

    res.json({ ok: true, producto: r.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// --------------------------- VER PRODUCTO PROVEEDOR ---------------------------
app.get("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;

  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id]
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

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

// --------------------------- ACTUALIZAR PRODUCTO PROVEEDOR ---------------------------
app.put("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, categoria_id, precio, stock } = req.body;

  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id]
    );
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

// --------------------------- ELIMINAR PRODUCTO PROVEEDOR ---------------------------
app.delete("/api/proveedor/productos/:id", authRequired, proveedorOnly, async (req, res) => {
  const { id } = req.params;

  try {
    const rProv = await db.query(
      "SELECT id FROM proveedor WHERE usuario_id=$1",
      [req.user.id]
    );
    if (!rProv.rows.length)
      return res.status(400).json({ ok: false, error: "Proveedor no encontrado" });

    const proveedorId = rProv.rows[0].id;

    const rCheck = await db.query(
      "SELECT * FROM productos WHERE id=$1 AND proveedor_id=$2",
      [id, proveedorId]
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

// --------------------------- PRODUCTOS DISPONIBLES AL USUARIO ---------------------------
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

// --------------------------- TODOS LOS PRODUCTOS (ADMIN) ---------------------------
app.get("/api/todos-productos", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query("SELECT * FROM productos ORDER BY id DESC");
    res.json({ ok: true, productos: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// --------------------------- VALIDADORES ---------------------------
function isValidInteger(n) {
  return Number.isInteger(Number(n)) && Number(n) > 0;
}

function isValidNonNegativeNumber(x) {
  return !Number.isNaN(Number(x)) && Number(x) >= 0;
}

// --------------------------- VENTA CON FIRMA + NONCE + BLOCKCHAIN ---------------------------
app.post("/api/usuario/venta", authRequired, async (req, res) => {
  const usuarioId = req.user.id;
  const { productos, signature, public_key_pem, key_filename, nonce } = req.body;

  if (!Array.isArray(productos) || productos.length === 0)
    return res.status(400).json({ ok: false, error: "Debe enviar productos" });

  // Validaciones
  for (const p of productos) {
    if (!isValidInteger(p.producto_id))
      return res.status(400).json({ ok: false, error: "producto_id inválido" });
    if (!isValidInteger(p.cantidad))
      return res.status(400).json({ ok: false, error: "cantidad inválida" });
    if (p.precio_unitario !== undefined && !isValidNonNegativeNumber(p.precio_unitario))
      return res.status(400).json({ ok: false, error: "precio_unitario inválido" });
  }

  // --------------------------------------
  //     MODO FIRMA (RSA + NONCE)
  // --------------------------------------
  if (signature || public_key_pem || nonce) {
    if (!signature || !public_key_pem || !nonce) {
      return res.status(400).json({ ok: false, error: "Faltan signature, public_key_pem o nonce" });
    }

    // Validar PEM
    const vpub = validatePublicKeyPem(public_key_pem);
    if (!vpub.ok)
      return res.status(400).json({ ok: false, error: "public_key_pem inválida: " + vpub.error });

    try {
      // Revisar nonce en BD
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

      // Construcción de la venta firmada
      const venta = {
        productos: productos.map(p => ({
          producto_id: Number(p.producto_id),
          cantidad: Number(p.cantidad),
          precio_unitario: p.precio_unitario !== undefined
            ? Number(p.precio_unitario)
            : undefined
        })),
        total: productos.reduce((sum, p) => {
          const u = p.precio_unitario !== undefined ? Number(p.precio_unitario) : 0;
          return sum + (Number(p.cantidad) * u);
        }, 0)
      };

      // Mensaje firmado
      const messageObj = { venta, nonce };
      const message = canonicalStringify(messageObj);

      // Verificar firma
      const okSig = verifySignature(public_key_pem, message, signature);
      if (!okSig)
        return res.status(400).json({ ok: false, error: "Firma inválida" });

      // Prevenir reuso de firma
      const signatureHash = sha256(signature + message);
      try {
        await db.query(
          "INSERT INTO used_signatures(signature_hash) VALUES($1)",
          [signatureHash]
        );
      } catch (err) {
        return res.status(400).json({ ok: false, error: "Firma ya usada (replay)" });
      }

      // Guardar venta + descontar stock
      const client = await db.connect();
      try {
        await client.query("BEGIN");

        const rVenta = await client.query(
          `INSERT INTO ventas(usuario_id, total) VALUES ($1,$2) RETURNING id, fecha`,
          [usuarioId, venta.total]
        );

        const ventaId = rVenta.rows[0].id;

        for (const p of productos) {
          // Leer stock
          const rStock = await client.query(
            "SELECT stock, precio FROM productos WHERE id=$1 FOR UPDATE",
            [p.producto_id]
          );
          if (!rStock.rows.length)
            throw new Error("Producto no existe: " + p.producto_id);

          const stockActual = rStock.rows[0].stock;
          const precioActual = parseFloat(rStock.rows[0].precio);

          if (stockActual < p.cantidad)
            throw new Error("Stock insuficiente");

          await client.query(
            `INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
             VALUES ($1,$2,$3,$4)`,
            [
              ventaId,
              p.producto_id,
              p.cantidad,
              p.precio_unitario !== undefined
                ? p.precio_unitario
                : precioActual
            ]
          );

          await client.query(
            "UPDATE productos SET stock = stock - $1 WHERE id=$2",
            [p.cantidad, p.producto_id]
          );
        }

        // Consumir nonce
        await client.query(
          "UPDATE nonces SET used = true WHERE nonce = $1",
          [nonce]
        );

        // Registrar bloque pendiente
        const meta = {
          signature_hash: signatureHash,
          key_filename: key_filename || null,
          fingerprint: sha256(public_key_pem)
        };

        await registrarBloqueVenta(ventaId, usuarioId, venta.total, productos, meta);

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
      return res.status(500).json({ ok: false, error: "Error interno en firma" });
    }
    return;
  }

  // --------------------------------------
  //   MODO SIN FIRMA (LEGACY)
  // --------------------------------------
  const client2 = await db.connect();

  try {
    await client2.query("BEGIN");

    const total = productos.reduce((sum, p) => {
      const pu = p.precio_unitario !== undefined ? Number(p.precio_unitario) : 0;
      return sum + Number(p.cantidad) * pu;
    }, 0);

    const rVenta = await client2.query(
      `INSERT INTO ventas(usuario_id, total)
       VALUES ($1,$2)
       RETURNING id, fecha`,
      [usuarioId, total]
    );

    const ventaId = rVenta.rows[0].id;

    for (const p of productos) {
      const rStock = await client2.query(
        "SELECT stock, precio FROM productos WHERE id=$1 FOR UPDATE",
        [p.producto_id]
      );

      if (!rStock.rows.length)
        throw new Error("Producto no existe");

      const stockActual = rStock.rows[0].stock;
      const precioActual = parseFloat(rStock.rows[0].precio);

      if (stockActual < p.cantidad)
        throw new Error("Stock insuficiente");

      await client2.query(
        `INSERT INTO venta_detalle(venta_id, producto_id, cantidad, precio_unitario)
         VALUES ($1,$2,$3,$4)`,
        [
          ventaId,
          p.producto_id,
          p.cantidad,
          p.precio_unitario !== undefined
            ? p.precio_unitario
            : precioActual
        ]
      );

      await client2.query(
        "UPDATE productos SET stock = stock - $1 WHERE id=$2",
        [p.cantidad, p.producto_id]
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

// --------------------------- LEER BLOCKCHAIN (CIFRADO) ---------------------------
app.get("/api/blockchain", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT 
        b.id,
        b.nonce,
        b.data,
        b.hash_actual,
        b.hash_anterior,
        b.fecha
      FROM blockchain b
      ORDER BY b.id ASC
    `);

    const decrypted = r.rows.map(row => ({
      ...row,
      data: decryptJSON(row.data)
    }));

    res.json({ ok: true, cadena: decrypted });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error al obtener blockchain" });
  }
});

// --------------------------- VALIDAR CADENA (CIFRADA) ---------------------------
app.get("/api/blockchain/validate", authRequired, adminOnly, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT id, nonce, data, hash_actual, hash_anterior, fecha
      FROM blockchain
      ORDER BY id ASC
    `);

    const rows = r.rows;
    let prev = "0".repeat(64);
    const problems = [];

    for (const b of rows) {
      const data = decryptJSON(b.data);
      const recalculated = computeBlockHash(prev, data, b.nonce);

      if (recalculated !== b.hash_actual)
        problems.push({ id: b.id, error: "hash no coincide" });

      prev = b.hash_actual;
    }

    if (problems.length)
      return res.json({ ok: false, problems });

    res.json({ ok: true, message: "Cadena válida", length: rows.length });

  } catch (err) {
    console.error("Error validando cadena:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --------------------------- DETALLE BLOQUE ---------------------------
app.get("/api/blockchain/:id", authRequired, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    const r = await db.query(`
      SELECT *
      FROM blockchain
      WHERE id=$1
    `, [id]);

    if (!r.rows.length)
      return res.status(404).json({ ok: false, error: "Bloque no encontrado" });

    const bloque = r.rows[0];
    const data = decryptJSON(bloque.data);

    res.json({ ok: true, bloque: { ...bloque, data } });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error obteniendo detalle" });
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

// --------------------------- MINAR BLOQUE ---------------------------
app.post("/api/mine", authRequired, adminOnly, async (req, res) => {
  const { miner_name } = req.body || {};

  try {
    const result = await minePendingBlock(miner_name || "admin");

    if (!result.ok)
      return res.status(400).json(result);

    res.json({ ok: true, mined: result });

  } catch (err) {
    console.error("Error en /api/mine:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});
// --------------------------- NONCE PARA FIRMA ---------------------------
app.post("/api/venta/nonce", authRequired, async (req, res) => {
  try {
    const usuarioId = req.user.id;
    const nonce = crypto.randomBytes(24).toString("hex");
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 minutos

    await db.query(`
      INSERT INTO nonces (usuario_id, nonce, expires_at, used)
      VALUES ($1,$2,$3,false)
    `, [usuarioId, nonce, expiresAt]);

    res.json({ ok: true, nonce, expires_at: expiresAt });

  } catch (err) {
    console.error("Error creando nonce:", err);
    res.status(500).json({ ok: false, error: "No se pudo generar nonce" });
  }
});

// Limpieza automática de nonces viejos
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

  // -------------- BLOCKCHAIN --------------
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

  // -------------- PENDING BLOCKS (MEMPOOL) --------------
  await db.query(`
    CREATE TABLE IF NOT EXISTS pending_blocks (
      id SERIAL PRIMARY KEY,
      data JSONB NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      attempted INT NOT NULL DEFAULT 0
    );
  `);

  // previene reuso de firma (replay)
  await db.query(`
    CREATE TABLE IF NOT EXISTS used_signatures (
      id SERIAL PRIMARY KEY,
      signature_hash TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  // NONCES para firma
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

  // Insertar roles básicos si no existen
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

  // Levantar HTTPS server (en lugar de app.listen)
  https.createServer({
    key: fs.readFileSync(path.join(__dirname, "server.key")),
    cert: fs.readFileSync(path.join(__dirname, "server.cert"))
  }, app).listen(PORT, () =>
    console.log(`🔐 Servidor HTTPS + JWT + Blockchain + Mining en https://localhost:${PORT}`)
  );
}

main().catch(err => console.error(err));
