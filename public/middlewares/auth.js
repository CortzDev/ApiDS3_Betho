const jwt = require("jsonwebtoken");

// Middleware: Verifica si hay token y lo decodifica
function authRequired(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ ok: false, error: "No autorizado" });

  const token = authHeader.split(" ")[1]; // "Bearer TOKEN"
  if (!token) return res.status(401).json({ ok: false, error: "No autorizado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwtsecret");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: "Token inválido" });
  }
}

// Middleware: Solo admin
function adminOnly(req, res, next) {
  if (!req.user || req.user.rol !== "admin") {
    return res.status(403).json({ ok: false, error: "No autorizado" });
  }
  next();
}

// Middleware: Solo proveedor
function proveedorOnly(req, res, next) {
  if (!req.user || req.user.rol !== "proveedor") {
    return res.status(403).json({ ok: false, error: "No autorizado" });
  }
  next();
}

module.exports = { authRequired, adminOnly, proveedorOnly };
