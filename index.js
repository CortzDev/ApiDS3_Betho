const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());

// Página principal con diseño
app.get("/", (req, res) => {
  res.send(`
  <html>
    <head>
      <title>APIDS3_B - API Status</title>
      <style>
        body {
          background-color: #BA776A;
          color: #FFFFFF;
          font-family: Arial, Helvetica, sans-serif;
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          margin: 0;
        }
        .card {
          background-color: #1F2937;
          padding: 40px;
          border-radius: 12px;
          box-shadow: 0 0 18px rgba(0,0,0,0.4);
          text-align: center;
          width: 420px;
        }
        h1 {
          margin: 0 0 15px;
          font-size: 26px;
        }
        p {
          color: #D1D5DB;
          font-size: 16px;
        }
        .footer {
          margin-top: 18px;
          font-size: 14px;
          color: #9CA3AF;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>APIDS3_B - API Status</h1>
        <p>La API está funcionando correctamente.</p>
        <p>Última actualización:<br>${new Date().toISOString()}</p>
        <div class="footer">Node.js / Express Server</div>
      </div>
    </body>
  </html>
  `);
});

// Ruta de salud
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    uptime: process.uptime(),
  });
});

// Ruta POST de prueba
app.post("/echo", (req, res) => {
  res.json({
    status: "OK",
    received: req.body,
  });
});

app.listen(PORT, () => {
  console.log(`Servidor APIDS3_B escuchando en el puerto ${PORT}`);
});

