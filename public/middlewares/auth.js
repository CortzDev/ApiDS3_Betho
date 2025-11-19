const jwt = require("jsonwebtoken");

function authRequired(req, res, next) {
  const authHeader = req.headers.authorization || req.cookies?.token;
  if (!authHeader) return res.status(403).json({ ok: false, error: "No autorizado" });

  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwtsecret");
    req.user = decoded; // { id, nombre, rol }
    next();
  } catch (e) {
    return res.status(403).json({ ok: false, error: "Token inválido" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user) return res.status(403).json({ ok: false, error: "No autorizado" });
  if (req.user.rol !== "admin") return res.status(403).json({ ok: false, error: "Acceso restringido a admins" });
  next();
}

function proveedorOnly(req, res, next) {
  if (!req.user) return res.status(403).json({ ok: false, error: "No autorizado" });
  if (req.user.rol !== "proveedor") return res.status(403).json({ ok: false, error: "Acceso restringido a proveedores" });
  next();
}

module.exports = { authRequired, adminOnly, proveedorOnly };
