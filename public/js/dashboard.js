document.addEventListener("DOMContentLoaded", () => {

  const token = localStorage.getItem("token");
  const publicKeyPem = localStorage.getItem("admin_public_key_pem");

  if (!token) {
    window.location.href = "/login.html";
    return;
  }

  /* ====================================================
     ALERTAS BOOTSTRAP (Autoclose: 5 segundos)
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

  /* ==================================================== */
  /* VALIDACIÓN PEM                                       */
  /* ==================================================== */
  function pemValida(pem) {
    if (!pem) return false;
    return pem.includes("-----BEGIN PUBLIC KEY-----") ||
           pem.includes("-----BEGIN RSA PUBLIC KEY-----");
  }

  if (!pemValida(publicKeyPem)) {
    mostrarAlerta("Debes cargar tu llave pública antes de usar el panel.", "warning");
    const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById("modalKey"));
    modal.show();
  }

  /* =========== STRINGIFY CANÓNICO =========== */
  function canonicalStringify(obj) {
    if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
    if (Array.isArray(obj))
      return "[" + obj.map(canonicalStringify).join(",") + "]";
    const keys = Object.keys(obj).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
  }

  /* =========== ELEMENTOS =========== */
  const proveedoresSection = document.getElementById("proveedoresSection");
  const actividadSection = document.getElementById("actividadSection");
  const tablaProveedores = document.getElementById("tablaProveedores");
  const tablaBlockchain = document.getElementById("tablaBlockchain");

  /* ==================================================== */
  /* LOGOUT                                               */
  /* ==================================================== */
  document.getElementById("logoutBtn").addEventListener("click", () => {
    localStorage.clear();
    mostrarAlerta("Sesión cerrada correctamente.", "info");
    window.location.href = "/login.html";
  });

  function checkPublicKey() {
    const pem = localStorage.getItem("admin_public_key_pem");
    if (!pemValida(pem)) {
      mostrarAlerta("Debes cargar tu llave pública para usar el panel.", "warning");
      const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById("modalKey"));
      modal.show();
      return false;
    }
    return true;
  }

  /* ==================================================== */
  /* CARGAR PROVEEDORES                                   */
  /* ==================================================== */
  async function cargarProveedores() {
    if (!checkPublicKey()) return;

    proveedoresSection.style.display = "block";
    actividadSection.style.display = "none";
    tablaProveedores.innerHTML = "";

    try {
      const res = await fetch("/api/proveedores", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();
      if (!data.ok) {
        mostrarAlerta("Error al cargar proveedores.", "danger");
        return;
      }

      data.proveedores.forEach(p => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${p.id}</td>
          <td>${p.nombre}</td>
          <td>${p.email}</td>
          <td>${p.empresa ?? ""}</td>
          <td>${p.telefono ?? ""}</td>
          <td>${p.direccion ?? ""}</td>
        `;
        tablaProveedores.appendChild(tr);
      });

      mostrarAlerta("Proveedores cargados correctamente.", "success");

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error inesperado al cargar proveedores.", "danger");
    }
  }

  document.getElementById("btnProveedor").addEventListener("click", cargarProveedores);

  /* ==================================================== */
  /* CARGAR ACTIVIDAD                                     */
  /* ==================================================== */
  async function cargarActividad() {
    if (!checkPublicKey()) return;

    proveedoresSection.style.display = "none";
    actividadSection.style.display = "block";
    tablaBlockchain.innerHTML = "";

    try {
      const res = await fetch("/api/blockchain", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok) {
        mostrarAlerta("Error cargando blockchain.", "danger");
        return;
      }

      data.cadena.forEach(b => {
        const prev = b.hash_anterior || "0".repeat(64);
        const recalculado = CryptoJS.SHA256(
          prev + canonicalStringify(b.data) + b.nonce
        ).toString();

        const valido = recalculado === b.hash_actual;

        const totalVenta =
          b.total_venta ??
          b.data?.total ??
          b.data?.data?.total ??
          "N/A";

        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${b.id}</td>
          <td>${new Date(b.fecha).toLocaleString()}</td>
          <td>${b.nonce}</td>
          <td class="small text-break">${prev}</td>
          <td class="small text-break">${b.hash_actual}</td>
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

      mostrarAlerta("Actividad cargada correctamente.", "success");

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error cargando actividad.", "danger");
    }
  }

  document.getElementById("btnActividad").addEventListener("click", cargarActividad);

  /* ==================================================== */
  /* DETALLE DE BLOQUE                                    */
  /* ==================================================== */
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

      document.getElementById("detOperacion").textContent = b.data.operacion || "Operación";
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
        data.productos ||
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

      bootstrap.Modal.getOrCreateInstance(document.getElementById("modalBloque")).show();

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error cargando detalle del bloque.", "danger");
    }
  }

  /* ==================================================== */
  /* MINAR BLOQUE                                          */
  /* ==================================================== */
  document.getElementById("btnMine")?.addEventListener("click", async () => {
    if (!checkPublicKey()) return;

    try {
      const res = await fetch("/api/mine", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + token,
          "Content-Type": "application/json"
        }
      });

      const data = await res.json();

      if (!data.ok) {
        mostrarAlerta("No se pudo minar el bloque: " + (data.error || ""), "danger");
        return;
      }

      mostrarAlerta("Bloque minado con éxito.", "success");
      cargarActividad();

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error al minar el bloque.", "danger");
    }
  });

  /* ==================================================== */
  /* VALIDAR CADENA                                        */
  /* ==================================================== */
  document.getElementById("btnValidate")?.addEventListener("click", async () => {
    if (!checkPublicKey()) return;

    try {
      /* 1) Consultar bloques pendientes */
      const pending = await fetch("/api/pending-blocks", {
        headers: { "Authorization": "Bearer " + token }
      });

      const pendData = await pending.json();

      if (!pendData.ok || pendData.pending.length === 0) {
        mostrarAlerta("No hay bloques pendientes para validar.", "warning");
        return;
      }

      /* 2) Ejecutar validación */
      const res = await fetch("/api/blockchain/validate", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (data.ok) {
        mostrarAlerta(`Cadena válida. Bloques verificados: ${data.length}`, "success");
      } else {
        mostrarAlerta("Se detectaron problemas en la cadena.", "danger");
      }

    } catch (err) {
      console.error(err);
      mostrarAlerta("Error validando cadena.", "danger");
    }
  });

});
