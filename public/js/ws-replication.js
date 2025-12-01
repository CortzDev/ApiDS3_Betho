/* =============================================================================
   WEBSOCKET DE REPLICACIÓN ENTRE SERVIDORES
   - Auto reconnect
   - Escucha actualizaciones en tiempo real
   - Sincroniza: usuarios online, bloques, wallets, pendientes
============================================================================= */

document.addEventListener("DOMContentLoaded", () => {

  function getToken() {
    return localStorage.getItem("token");
  }

  let ws = null;
  let reconnectDelay = 1000;

  function conectarWS() {
    const token = getToken();
    const proto = location.protocol === "https:" ? "wss" : "ws";

    let url = `${proto}://${location.hostname}:${location.port}/replicacion`;
    if (token) url += `?token=${encodeURIComponent(token)}`;

    ws = new WebSocket(url);

    ws.onopen = () => {
      console.log("[WS] Conectado a replicación");
      reconnectDelay = 1000;
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        procesarMensaje(msg);
      } catch (e) {
        console.error("Mensaje WS inválido", ev.data);
      }
    };

    ws.onerror = (err) => {
      console.error("[WS] Error:", err);
    };

    ws.onclose = () => {
      console.warn("[WS] Desconectado. Reintentando en", reconnectDelay);

      setTimeout(() => {
        reconnectDelay = Math.min(reconnectDelay * 1.8, 20000);
        conectarWS();
      }, reconnectDelay);
    };
  }

  function procesarMensaje(data) {
    if (!data || !data.tipo) return;

    switch (data.tipo) {

      case "usuarios_online":
        document.getElementById("onlineUsers").textContent = data.valor;
        break;

      case "bloques_pendientes":
        actualizarPendientes(data.valor);
        break;

      case "nuevo_bloque":
        mostrarAlerta("Nuevo bloque replicado recibido", "success");
        cargarActividad(); // función ya existente
        break;

      case "actualizar_wallets":
        cargarWallets();
        break;
    }
  }

  function actualizarPendientes(valor) {
    const dot = document.getElementById("pendingDot");
    const count = document.getElementById("pendingCount");

    if (valor > 0) {
      dot.style.display = "inline-block";
      count.style.display = "inline-block";
      count.textContent = valor;
    } else {
      dot.style.display = "none";
      count.style.display = "none";
    }
  }

  conectarWS();
});
