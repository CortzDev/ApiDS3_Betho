const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());

// Ruta principal
app.get("/", (req, res) => {
  res.json({
    status: "OK",
    service: "APIDS3_B",
    message: "API funcionando correctamente",
    timestamp: new Date().toISOString(),
  });
});

// Ruta de salud (opcional, buena práctica)
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    uptime: process.uptime(),
  });
});

// Ejemplo de endpoint de prueba
app.post("/echo", (req, res) => {
  res.json({
    status: "OK",
    received: req.body,
  });
});

app.listen(PORT, () => {
  console.log(`Servidor APIDS3_B escuchando en el puerto ${PORT}`);
});
