document.addEventListener("DOMContentLoaded", () => {

  const token = localStorage.getItem("token");
  const publicKeyPem = localStorage.getItem("admin_public_key_pem");

  if (!token) {
    window.location.href = "/login.html";
    return;
  }

  /* ====================================================
     ALERTAS BOOTSTRAP
  ==================================================== */
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

  /* ====================================================
     VALIDAR PEM
  ==================================================== */
  function pemValida(pem) {
    if (!pem) return false;
    return pem.includes("-----BEGIN PUBLIC KEY-----") ||
           pem.includes("-----BEGIN RSA PUBLIC KEY-----");
  }

  if (!pemValida(publicKeyPem)) {
    mostrarAlerta("Debes cargar tu llave pública antes de usar el panel.", "warning");
    bootstrap.Modal.getOrCreateInstance(document.getElementById("modalKey")).show();
  }

  /* ====================================================
     STRINGIFY CANÓNICO
  ==================================================== */
  function canonicalStringify(obj) {
    if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
    if (Array.isArray(obj)) {
      return "[" + obj.map(canonicalStringify).join(",") + "]";
    }
    const keys = Object.keys(obj).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
  }

  /* ====================================================
     REFERENCIAS DOM
  ==================================================== */
  const proveedoresSection = document.getElementById("proveedoresSection");
  const actividadSection = document.getElementById("actividadSection");
  const walletSection = document.getElementById("walletSection");

  const tablaProveedores = document.getElementById("tablaProveedores");
  const tablaBlockchain = document.getElementById("tablaBlockchain");
  const tablaWallets = document.getElementById("tablaWallets");

  /* ====================================================
     LOGOUT
  ==================================================== */
  document.getElementById("logoutBtn").addEventListener("click", () => {
    localStorage.clear();
    window.location.href = "/login.html";
  });

  /* ====================================================
     OCULTAR TODAS LAS SECCIONES
  ==================================================== */
  function ocultarTodo() {
    proveedoresSection.style.display = "none";
    actividadSection.style.display = "none";
    walletSection.style.display = "none";
  }

  /* ====================================================
     CHECK LLAVE PÚBLICA
  ==================================================== */
  function checkPublicKey() {
    const pem = localStorage.getItem("admin_public_key_pem");
    if (!pemValida(pem)) {
      mostrarAlerta("Debes cargar tu llave pública para usar el panel.", "warning");
      bootstrap.Modal.getOrCreateInstance(document.getElementById("modalKey")).show();
      return false;
    }
    return true;
  }

  /* ====================================================
     REVISAR BLOQUES PENDIENTES (NOTIFICACIÓN)
  ==================================================== */
  async function revisarPendientes() {
  try {
    const res = await fetch("/api/blockchain/pending", {
      headers: { "Authorization": "Bearer " + token }
    });

    const data = await res.json();

    const dot = document.getElementById("pendingDot");
    const countSpan = document.getElementById("pendingCount");

    if (data.ok && data.count > 0) {
      countSpan.textContent = data.count;   // ← muestra número real
      dot.style.display = "inline-flex";    // aparece
    } else {
      dot.style.display = "none";           // se oculta si no hay nada
    }

  } catch (err) {
    console.error("Error revisando pendientes:", err);
  }
}

// Revisar pendientes cada 10s
setInterval(revisarPendientes, 10000);


  /* ====================================================
     CARGAR PROVEEDORES
  ==================================================== */
  async function cargarProveedores() {
    if (!checkPublicKey()) return;

    ocultarTodo();
    proveedoresSection.style.display = "block";
    tablaProveedores.innerHTML = "";

    try {
      const res = await fetch("/api/proveedores", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok) {
        mostrarAlerta("Error cargando proveedores", "danger");
        return;
      }

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

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error inesperado al cargar proveedores", "danger");
    }
  }

  document.getElementById("btnProveedor").addEventListener("click", cargarProveedores);

  /* ====================================================
     CARGAR ACTIVIDAD (BLOCKCHAIN)
  ==================================================== */
  async function cargarActividad() {
    if (!checkPublicKey()) return;

    ocultarTodo();
    actividadSection.style.display = "block";
    tablaBlockchain.innerHTML = "";

    try {
      const res = await fetch("/api/blockchain", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok || !Array.isArray(data.cadena)) {
        mostrarAlerta("Error al cargar blockchain", "danger");
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
          <td>
            <span class="badge ${valido ? "bg-success" : "bg-danger"}">
              ${valido ? "Válido" : "Corrupto"}
            </span>
          </td>
        `;

        tr.addEventListener("click", () => cargarDetalleBloque(b.id));
        tablaBlockchain.appendChild(tr);
      });

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error cargando actividad", "danger");
    }
  }

  document.getElementById("btnActividad").addEventListener("click", cargarActividad);

  /* ====================================================
     DETALLE DEL BLOQUE
  ==================================================== */
  async function cargarDetalleBloque(id) {
    if (!checkPublicKey()) return;

    try {
      const res = await fetch(`/api/blockchain/${id}`, {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok) {
        mostrarAlerta("No se pudo cargar el detalle del bloque.", "danger");
        return;
      }

      const b = data.bloque;

      document.getElementById("detOperacion").textContent =
        b.data?.operacion || "Venta";

      document.getElementById("detFecha").textContent =
        new Date(b.fecha).toLocaleString();

      document.getElementById("detNonce").textContent = b.nonce;
      document.getElementById("detHashPrev").textContent =
        b.hash_anterior || "GENESIS";

      document.getElementById("detHashActual").textContent = b.hash_actual;
      document.getElementById("detHashActual").dataset.blockid = b.id;

      const totalVenta =
        b.total_venta ?? b.data?.total ?? b.data?.data?.total ?? "N/A";

      document.getElementById("detTotalVenta").textContent = totalVenta;

      const prev = b.hash_anterior || "0".repeat(64);
      const recalculado = CryptoJS.SHA256(
        prev + canonicalStringify(b.data) + b.nonce
      ).toString();

      const valido = recalculado === b.hash_actual;

      document.getElementById("detEstado").innerHTML = `
        <span class="badge ${valido ? "bg-success" : "bg-danger"}">
          ${valido ? "Bloque Válido" : "Bloque Corrupto"}
        </span>
      `;

      const tbody = document.getElementById("detProductos");
      tbody.innerHTML = "";

      const productos =
        data.productos || b.data?.productos || b.data?.data?.productos || [];

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

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error cargando detalle del bloque.", "danger");
    }
  }

  /* ====================================================
     MINAR BLOQUE
  ==================================================== */
  document.getElementById("btnMine").addEventListener("click", async () => {
    if (!checkPublicKey()) return;

    try {
      const res = await fetch("/api/mine", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + token,
          "Content-Type": "application/json"
        },
        body: "{}"
      });

      const data = await res.json();

      if (!data.ok) {
        mostrarAlerta("No se pudo minar: " + (data.error || "Error"), "danger");
        return;
      }

      mostrarAlerta("Bloque minado con éxito.", "success");
      cargarActividad();

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error al minar el bloque.", "danger");
    }
  });

  /* ====================================================
     VALIDAR CADENA
  ==================================================== */
  document.getElementById("btnValidate")?.addEventListener("click", async () => {
    if (!checkPublicKey()) return;

    try {
      const res = await fetch("/api/blockchain/full-audit", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (data.ok) {
        mostrarAlerta("Cadena válida ✔", "success");
      } else {
        mostrarAlerta("Problemas detectados ❌", "danger");
        console.warn("PROBLEMAS DETECTADOS:", data.problems || data.error);
      }

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error validando cadena.", "danger");
    }
  });

  /* ====================================================
     ====  CARGAR WALLETS REGISTRADAS  =====
  ==================================================== */
  async function cargarWallets() {
    if (!checkPublicKey()) return;

    ocultarTodo();
    walletSection.style.display = "block";
    tablaWallets.innerHTML = `
      <tr><td colspan="4" class="text-center">Cargando...</td></tr>
    `;

    try {
      const res = await fetch("/api/wallets/registered", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok) {
        tablaWallets.innerHTML = `
          <tr><td colspan="4" class="text-danger text-center">
            Error al cargar wallets registradas
          </td></tr>
        `;
        return;
      }

      const wallets = data.wallets;
      tablaWallets.innerHTML = "";

      if (wallets.length === 0) {
        tablaWallets.innerHTML = `
          <tr><td colspan="4" class="text-center">
            No hay wallets registradas
          </td></tr>
        `;
        return;
      }

      wallets.forEach(w => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${w.fingerprint}</td>
          <td>${w.usuario} <br> <small>${w.email}</small></td>
          <td>${new Date(w.created_at).toLocaleString()}</td>
          <td>
            <button class="btn btn-primary btn-sm verWalletBtn" data-fp="${w.fingerprint}">
              Ver Detalle
            </button>
          </td>
        `;
        tablaWallets.appendChild(tr);
      });

    } catch (err) {
      console.error(err);
      tablaWallets.innerHTML = `
        <tr><td colspan="4" class="text-danger text-center">Error de conexión</td></tr>
      `;
    }
  }

  document.getElementById("btnWallets").addEventListener("click", cargarWallets);

  document.addEventListener("click", (e) => {
    if (e.target.classList.contains("verWalletBtn")) {
      const fp = e.target.dataset.fp;
      verWallet(fp);
    }
  });

  /* ====================================================
     DETALLE DE WALLET
  ==================================================== */
  function verWallet(fp) {
    alert("Fingerprint: " + fp + "\n(Aquí puedes ampliar info si deseas)");
  }

  /* ====================================================
     VERIFICAR FIRMA RSA (doble click)
  ==================================================== */
  document.getElementById("detHashActual")
    ?.addEventListener("dblclick", () => {
      const id = document.getElementById("detHashActual").dataset.blockid;
      if (id) verificarFirma(id);
    });

  async function verificarFirma(id) {
    if (!checkPublicKey()) return;

    try {
      const res = await fetch(`/api/blockchain/verify-signature/${id}`, {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok) {
        mostrarAlerta("No se pudo verificar la firma.", "danger");
        return;
      }

      mostrarAlerta(
        data.valid
          ? `✔ Firma válida — Wallet: ${data.fingerprint}`
          : "❌ Firma inválida",
        data.valid ? "success" : "danger"
      );

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error verificando firma RSA.", "danger");
    }
  }

  /* ====================================================
     INICIO AUTOMÁTICO → Blockchain
  ==================================================== */
  cargarActividad();
  revisarPendientes();

});
