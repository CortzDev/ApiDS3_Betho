const jwt = require("jsonwebtoken");

// Middleware para verificar token
function authRequired(req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token requerido" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// Middleware solo para administradores
function adminOnly(req, res, next) {
  if (req.user.rol_id !== 1) {
    return res.status(403).json({ error: "Acceso denegado: solo administradores" });
  }
  next();
}

module.exports = { authRequired, adminOnly };
