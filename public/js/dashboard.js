document.addEventListener("DOMContentLoaded", () => {

  const token = localStorage.getItem("token");

  if (!token) {
    window.location.href = "/login.html";
    return;
  }

  const proveedoresSection = document.getElementById("proveedoresSection");
  const actividadSection = document.getElementById("actividadSection");
  const tablaProveedores = document.getElementById("tablaProveedores");
  const tablaBlockchain = document.getElementById("tablaBlockchain");

  // =========================
  // LOGOUT
  // =========================
  document.getElementById("logoutBtn").addEventListener("click", () => {
    localStorage.clear();
    window.location.href = "/login.html";
  });

  // =========================
  // CARGAR PROVEEDORES
  // =========================
  async function cargarProveedores() {
    proveedoresSection.style.display = "block";
    actividadSection.style.display = "none";
    tablaProveedores.innerHTML = "";

    try {
      const res = await fetch("/api/proveedores", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok) {
        alert("Error al cargar proveedores");
        return;
      }

      data.proveedores.forEach(p => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${p.id}</td>
          <td>${p.nombre}</td>
          <td>${p.email}</td>
          <td>${p.empresa}</td>
          <td>${p.telefono}</td>
          <td>${p.direccion}</td>
        `;
        tablaProveedores.appendChild(tr);
      });

    } catch (err) {
      console.error("Error proveedores:", err);
      alert("Error cargando proveedores");
    }
  }

  // BOTÓN PROVEEDORES
  document.getElementById("btnProveedor")
    .addEventListener("click", cargarProveedores);

  // =========================
  // CARGAR ACTIVIDAD (BLOCKCHAIN)
  // =========================
  async function cargarActividad() {
    proveedoresSection.style.display = "none";
    actividadSection.style.display = "block";
    tablaBlockchain.innerHTML = "";

    try {
      const res = await fetch("/api/blockchain", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok) {
        alert("Error cargando actividad");
        return;
      }

      data.cadena.forEach(b => {

        const payloadString = JSON.stringify(b.data);
        const previo = b.hash_anterior || "0".repeat(64);

        const recalculado = CryptoJS.SHA256(
          previo + payloadString + b.nonce
        ).toString();

        const valido = recalculado === b.hash_actual;

        const totalVenta = b.total_venta
          ? `$${b.total_venta}`
          : (b.data?.data?.total ? `$${b.data.data.total}` : "N/A");

        const tr = document.createElement("tr");

        tr.innerHTML = `
          <td>${b.id}</td>
          <td>${new Date(b.fecha).toLocaleString()}</td>
          <td>${b.nonce}</td>
          <td class="small text-break">${b.hash_anterior || "GENESIS"}</td>
          <td class="small text-break">${b.hash_actual}</td>
          <td>${totalVenta}</td>
          <td>
            <span class="badge ${valido ? 'bg-danger' : 'bg-success'}">
              ${valido ? 'Corrupto' : 'Válido'}
            </span>
          </td>
        `;

        tr.addEventListener("click", () => cargarDetalleBloque(b.id));

        tablaBlockchain.appendChild(tr);
      });

    } catch (err) {
      console.error("Error actividad:", err);
      alert("Error cargando actividad");
    }
  }

  document.getElementById("btnActividad")
    .addEventListener("click", cargarActividad);

  // =========================
  // DETALLE DE BLOQUE
  // =========================
  async function cargarDetalleBloque(id) {
    try {
      const res = await fetch(`/api/blockchain/${id}`, {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();

      if (!data.ok) {
        alert("No se pudo cargar detalle");
        return;
      }

      const b = data.bloque;

      document.getElementById("detOperacion").textContent = b.data.operacion;
      document.getElementById("detFecha").textContent = new Date(b.fecha).toLocaleString();
      document.getElementById("detNonce").textContent = b.nonce;
      document.getElementById("detHashPrev").textContent = b.hash_anterior || "GENESIS";
      document.getElementById("detHashActual").textContent = b.hash_actual;

      document.getElementById("detTotalVenta").textContent =
        b.total_venta ? `$${b.total_venta}` : "N/A";

      const recalculado = CryptoJS.SHA256(
        (b.hash_anterior || "0".repeat(64)) + JSON.stringify(b.data) + b.nonce
      ).toString();

      const valido = recalculado === b.hash_actual;

      document.getElementById("detEstado").innerHTML =
        `<span class="badge ${valido ? "bg-success" : "bg-danger"}">
           ${valido ? "Bloque Válido" : "Bloque Corrupto"}
         </span>`;

      const tbody = document.getElementById("detProductos");
      tbody.innerHTML = "";

      (data.productos || []).forEach(p => {
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

      new bootstrap.Modal(document.getElementById("modalBloque")).show();

    } catch (err) {
      console.error("Detalle error:", err);
      alert("Error cargando detalle");
    }
  }

});
