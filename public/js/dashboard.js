/* =============================================================================
   DASHBOARD ADMIN – CORREGIDO Y OPTIMIZADO
   - Verifica token antes de iniciar
   - Evita fetchs sin token
   - Evita error: {ok:false,"error":"Ruta no encontrada"}
   - Compatible con ws-replication.js
============================================================================= */

document.addEventListener("DOMContentLoaded", () => {

  /* ======================================================
     VALIDAR TOKEN AL ENTRAR AL DASHBOARD
  ====================================================== */
  const token = localStorage.getItem("token");
  if (!token) {
    console.warn("❌ No token found → volver a login");
    window.location.href = "/login.html";
    return;
  }

  /* ======================================================
     VALIDACIÓN DEL TOKEN + secureFetch()
  ====================================================== */
  function getValidToken() {
    const token = localStorage.getItem("token");

    if (!token) return null;

    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      const now = Date.now() / 1000;
      if (payload.exp && payload.exp < now) return null;
      return token;
    } catch {
      return null;
    }
  }

  async function secureFetch(url, options = {}) {
    const token = getValidToken();

    if (!token) {
      localStorage.clear();
      window.location.href = "/login.html";
      throw new Error("Token inválido o expirado");
    }

    options.headers = {
      ...(options.headers || {}),
      "Authorization": "Bearer " + token
    };

    if ((options.method || "GET").toUpperCase() === "GET") {
      delete options.body;
    }

    const response = await fetch(url, options);

    if (response.status === 401 || response.status === 403) {
      localStorage.clear();
      window.location.href = "/login.html";
      throw new Error("No autorizado");
    }

    return response;
  }

  /* ======================================================
     ALERTAS
  ====================================================== */
  function mostrarAlerta(mensaje, tipo = "info") {
    const cont = document.getElementById("alertContainer");
    const id = "alert-" + Date.now();

    cont.insertAdjacentHTML("beforeend", `
      <div id="${id}" class="alert alert-${tipo} alert-dismissible fade show" role="alert">
        ${mensaje}
        <button class="btn-close" data-bs-dismiss="alert"></button>
      </div>
    `);

    setTimeout(() => {
      const a = document.getElementById(id);
      if (a) bootstrap.Alert.getOrCreateInstance(a).close();
    }, 5000);
  }

  /* ======================================================
     VALIDAR LLAVE PÚBLICA
  ====================================================== */
  function pemValida(pem) {
    if (!pem) return false;
    return pem.includes("-----BEGIN PUBLIC KEY-----")
        || pem.includes("-----BEGIN RSA PUBLIC KEY-----");
  }

  function checkPublicKey() {
    const pem = localStorage.getItem("admin_public_key_pem");
    if (!pemValida(pem)) {
      mostrarAlerta("Debes cargar tu llave pública para usar el panel.", "warning");
      bootstrap.Modal.getOrCreateInstance(document.getElementById("modalKey")).show();
      return false;
    }
    return true;
  }

  /* ======================================================
     STRINGIFY CANÓNICO
  ====================================================== */
  function canonicalStringify(obj) {
    if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
    if (Array.isArray(obj)) return "[" + obj.map(canonicalStringify).join(",") + "]";
    const keys = Object.keys(obj).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
  }

  /* ======================================================
     DOM ELEMENTOS
  ====================================================== */
  const proveedoresSection = document.getElementById("proveedoresSection");
  const actividadSection = document.getElementById("actividadSection");
  const walletSection = document.getElementById("walletSection");

  const tablaProveedores = document.getElementById("tablaProveedores");
  const tablaBlockchain = document.getElementById("tablaBlockchain");
  const tablaWallets = document.getElementById("tablaWallets");

  const pendingDot = document.getElementById("pendingDot");
  const pendingCount = document.getElementById("pendingCount");

  /* ======================================================
     LOGOUT
  ====================================================== */
  document.getElementById("logoutBtn").addEventListener("click", () => {
    localStorage.clear();
    window.location.href = "/login.html";
  });

  /* ======================================================
     OCULTAR SECCIONES
  ====================================================== */
  function ocultarTodo() {
    proveedoresSection.style.display = "none";
    actividadSection.style.display = "none";
    walletSection.style.display = "none";
  }

  /* ======================================================
     PENDING BLOCKS
  ====================================================== */
  let alertaPendientesMostrada = false;

  async function revisarPendientes() {
    try {
      const res = await secureFetch("/api/pending-blocks");
      const data = await res.json();

      if (!data.ok) return;

      const count = data.pending.length;

      if (count > 0) {
        pendingDot.style.display = "inline-flex";
        pendingCount.textContent = count;

        if (!alertaPendientesMostrada) {
          mostrarAlerta(`Hay ${count} bloque(s) pendiente(s) de minar.`, "warning");
          alertaPendientesMostrada = true;
        }
      } else {
        pendingDot.style.display = "none";
        pendingCount.textContent = "";
        alertaPendientesMostrada = false;
      }
    } catch {}
  }

  setInterval(revisarPendientes, 6000);

  /* ======================================================
     PROVEEDORES
  ====================================================== */
  async function cargarProveedores() {
    if (!checkPublicKey()) return;

    ocultarTodo();
    proveedoresSection.style.display = "block";
    tablaProveedores.innerHTML = "";

    const res = await secureFetch("/api/proveedores");
    const data = await res.json();

    if (!data.ok) return mostrarAlerta("Error cargando proveedores", "danger");

    data.proveedores.forEach(p => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${p.id}</td>
        <td>${p.nombre}</td>
        <td>${p.email}</td>
        <td>${p.empresa || ""}</td>
        <td>${p.telefono || ""}</td>
        <td>${p.direccion || ""}</td>
      `;
      tablaProveedores.appendChild(tr);
    });
  }

  document.getElementById("btnProveedor").addEventListener("click", cargarProveedores);

  /* ======================================================
     BLOCKCHAIN — LISTA
  ====================================================== */
  async function cargarActividad() {
    if (!checkPublicKey()) return;

    ocultarTodo();
    actividadSection.style.display = "block";
    tablaBlockchain.innerHTML = "";

    const res = await secureFetch("/api/blockchain");
    const data = await res.json();

    if (!data.ok) {
      mostrarAlerta("Error cargando blockchain", "danger");
      return;
    }

    data.cadena.forEach(b => {
      const prev = b.hash_anterior || "0".repeat(64);

      const recalculado = CryptoJS.SHA256(
        prev + canonicalStringify(b.data) + b.nonce
      ).toString();

      const valido = recalculado === b.hash_actual;

      const totalVenta =
        b.total_venta ?? b.data?.total ?? b.data?.data?.total ?? "N/A";

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${b.id}</td>
        <td>${new Date(b.fecha).toLocaleString()}</td>
        <td>${b.nonce}</td>
        <td class="text-break small">${prev}</td>
        <td class="text-break small">${b.hash_actual}</td>
        <td>${totalVenta}</td>
        <td><span class="badge ${valido ? "bg-success" : "bg-danger"}">
          ${valido ? "Válido" : "Corrupto"}
        </span></td>
      `;

      tr.addEventListener("click", () => cargarDetalleBloque(b.id));

      tablaBlockchain.appendChild(tr);
    });
  }

  document.getElementById("btnActividad").addEventListener("click", cargarActividad);

  /* ======================================================
     DETALLE DE BLOQUE
  ====================================================== */
  async function cargarDetalleBloque(id) {
    const res = await secureFetch(`/api/blockchain/${id}`);
    const data = await res.json();

    if (!data.ok) return mostrarAlerta("Error cargando bloque", "danger");

    const b = data.bloque;

    document.getElementById("detOperacion").textContent = b.data?.operacion || "Venta";
    document.getElementById("detFecha").textContent = new Date(b.fecha).toLocaleString();
    document.getElementById("detNonce").textContent = b.nonce;
    document.getElementById("detHashPrev").textContent = b.hash_anterior || "GENESIS";
    document.getElementById("detHashActual").textContent = b.hash_actual;

    const totalVenta =
      b.total_venta ??
      b.data?.total ??
      b.data?.data?.total ??
      "N/A";

    document.getElementById("detTotalVenta").textContent = totalVenta;

    const tbody = document.getElementById("detProductos");
    tbody.innerHTML = "";

    const productos =
      b.data?.productos ||
      b.data?.data?.productos ||
      [];

    productos.forEach(p => {
      const subtotal = p.cantidad * p.precio_unitario;

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${p.nombre || p.producto_id}</td>
        <td>${p.cantidad}</td>
        <td>$${p.precio_unitario}</td>
        <td>$${subtotal}</td>
      `;
      tbody.appendChild(tr);
    });

    bootstrap.Modal.getOrCreateInstance(
      document.getElementById("modalBloque")
    ).show();
  }

  /* ======================================================
     MINAR BLOQUE
  ====================================================== */
  document.getElementById("btnMine").addEventListener("click", async () => {
    if (!checkPublicKey()) return;

    const res = await secureFetch("/api/mine", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    });

    const data = await res.json();

    if (!data.ok) {
      return mostrarAlerta("No se pudo minar: " + (data.error || ""), "danger");
    }

    mostrarAlerta("Bloque minado con éxito", "success");
    cargarActividad();
    revisarPendientes();
  });

  /* ======================================================
     USUARIOS CONECTADOS
  ====================================================== */
  async function revisarUsuariosConectados() {
    try {
      const res = await secureFetch("/api/usuarios/conectados");
      const data = await res.json();

      if (data.ok) {
        const span = document.getElementById("onlineUsers");
        span.textContent = data.count;

        if (data.count > 0) {
          span.classList.remove("bg-secondary");
          span.classList.add("bg-success");
        } else {
          span.classList.remove("bg-success");
          span.classList.add("bg-secondary");
        }
      }
    } catch {}
  }

  setInterval(revisarUsuariosConectados, 5000);

  /* ======================================================
     WALLETS
  ====================================================== */
  async function cargarWallets() {
    if (!checkPublicKey()) return;

    ocultarTodo();
    walletSection.style.display = "block";
    tablaWallets.innerHTML = `<tr><td colspan="4" class="text-center">Cargando...</td></tr>`;

    const res = await secureFetch("/api/wallets/registered");
    const data = await res.json();

    if (!data.ok) {
      tablaWallets.innerHTML = `<tr><td colspan="4" class="text-danger text-center">Error</td></tr>`;
      return;
    }

    tablaWallets.innerHTML = "";

    if (data.wallets.length === 0) {
      tablaWallets.innerHTML = `<tr><td colspan="4" class="text-center">No hay wallets</td></tr>`;
      return;
    }

    data.wallets.forEach(w => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${w.fingerprint}</td>
        <td>${w.usuario}<br><small>${w.email}</small></td>
        <td>${new Date(w.created_at).toLocaleString()}</td>
        <td><button class="btn btn-primary btn-sm">Detalle</button></td>
      `;
      tablaWallets.appendChild(tr);
    });
  }

  document.getElementById("btnWallets").addEventListener("click", cargarWallets);

  /* ======================================================
     ARRANQUE
  ====================================================== */
  cargarActividad();
  revisarPendientes();
  revisarUsuariosConectados();

});
