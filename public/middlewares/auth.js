const jwt = require("jsonwebtoken");

function authRequired(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ ok: false, error: "No autorizado" });

  const token = authHeader.split(" ")[1]; // Bearer <token>
  if (!token) return res.status(401).json({ ok: false, error: "No autorizado" });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "jwtsecret");
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: "Token inválido" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.rol !== "admin") return res.status(403).json({ ok: false, error: "No autorizado" });
  next();
}

function proveedorOnly(req, res, next) {
  if (req.user.rol !== "proveedor") return res.status(403).json({ ok: false, error: "No autorizado" });
  next();
}

module.exports = { authRequired, adminOnly, proveedorOnly };
