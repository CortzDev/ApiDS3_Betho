const jwt = require("jsonwebtoken");

/**
 * Middleware: Verifica token JWT
 */
function authRequired(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    console.log("❌ No se envió Authorization Header");
    return res.status(401).json({ ok: false, error: "No autorizado" });
  }

  const token = authHeader.split(" ")[1]; // "Bearer TOKEN"

  if (!token) {
    console.log("❌ Token no encontrado en el header");
    return res.status(401).json({ ok: false, error: "No autorizado" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwtsecret");

    console.log("✔ JWT válido:", decoded);

    req.user = decoded;

    next();
  } catch (err) {
    console.log("❌ Token inválido:", err.message);
    return res.status(401).json({ ok: false, error: "Token inválido" });
  }
}

/**
 * Middleware: Solo Admin
 */
function adminOnly(req, res, next) {
  if (!req.user) {
    console.log("❌ adminOnly: No hay usuario en req.user");
    return res.status(401).json({ ok: false, error: "No autorizado" });
  }

  console.log("🔍 ROL RECIBIDO EN TOKEN:", req.user.rol);   // <── AGREGA ESTO

  if (req.user.rol !== "admin") {
    console.log("⛔ Acceso denegado (no es admin):", req.user.rol);
    return res.status(403).json({ ok: false, error: "No autorizado" });
  }

  next();
}


/**
 * Middleware: Solo Proveedor
 */
function proveedorOnly(req, res, next) {
  if (!req.user) {
    console.log("❌ proveedorOnly: No hay usuario en req.user");
    return res.status(401).json({ ok: false, error: "No autorizado" });
  }

  if (req.user.rol !== "proveedor") {
    console.log("⛔ Acceso denegado (no es proveedor):", req.user.rol);
    return res.status(403).json({ ok: false, error: "No autorizado" });
  }

  next();
}

module.exports = {
  authRequired,
  adminOnly,
  proveedorOnly
};
