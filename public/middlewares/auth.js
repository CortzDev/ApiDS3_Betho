// auth.js
const jwt = require("jsonwebtoken");

function authRequired(req, res, next) {
  const auth = req.headers.authorization || req.cookies.token;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(403).json({ ok: false, error: "No autorizado" });
  }

  const token = auth.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwtsecret");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ ok: false, error: "Token inválido" });
  }
}

function proveedorOnly(req, res, next) {
  if (req.user && req.user.rol === "proveedor") {
    return next();
  }
  return res.status(403).json({ ok: false, error: "No tienes permisos de proveedor" });
}

function adminOnly(req, res, next) {
  if (req.user && req.user.rol === "admin") {
    return next();
  }
  return res.status(403).json({ ok: false, error: "No tienes permisos de administrador" });
}

module.exports = { authRequired, proveedorOnly, adminOnly };
