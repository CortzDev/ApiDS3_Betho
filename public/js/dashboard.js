document.addEventListener("DOMContentLoaded", () => {

  const token = localStorage.getItem("token");

  // Protección
  if (!token) {
    window.location.href = "/login.html";
  }

  const tablaRoles = document.getElementById("tablaRoles");
  const rolesSection = document.getElementById("rolesSection");
  const actividadSection = document.getElementById("actividadSection");
  const tablaBlockchain = document.getElementById("tablaBlockchain");

  // =========================
  // LOGOUT
  // =========================
  document.getElementById("logoutBtn").addEventListener("click", () => {
    localStorage.clear();
    window.location.href = "/login.html";
  });

  // =========================
  // CARGAR ACTIVIDAD (BLOCKCHAIN)
  // =========================
  async function cargarActividad() {
    rolesSection.style.display = "none";
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

        // =========================
        // Verificar integridad del hash
        // =========================
        const calculado = CryptoJS.SHA256(
          JSON.stringify(b.data) + b.nonce + (b.hash_anterior || "")
        ).toString();

        const valido = calculado === b.hash_actual;

        // =========================
        // Obtener TOTAL DE VENTA desde el backend
        // =========================
        let totalVenta = "N/A";
        if (b.total_venta) {
          totalVenta = `$${b.total_venta}`;
        } else if (b.data && b.data.total) {
          // por compatibilidad si el total también viene en el JSON
          totalVenta = `$${b.data.total}`;
        }

        // =========================
        // Dibujar fila
        // =========================
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${b.id}</td>
          <td>${new Date(b.fecha).toLocaleString()}</td>
          <td>${b.nonce}</td>
          <td class="small text-break">${b.hash_anterior || "GENESIS"}</td>
          <td class="small text-break">${b.hash_actual}</td>
          <td>${totalVenta}</td>
          <td>
            <span class="badge ${valido ? 'bg-success' : 'bg-danger'}">
              ${valido ? 'Sí' : 'No'}
            </span>
          </td>
        `;

        tablaBlockchain.appendChild(tr);
      });

    } catch (err) {
      console.error(err);
      alert("Error al cargar actividad");
    }
  }

  // =========================
  // BOTÓN ACTIVIDAD
  // =========================
  const btnActividad = document.getElementById("btnActividad");
  if (btnActividad) {
    btnActividad.addEventListener("click", cargarActividad);
  }

  // =========================
  // CARGAR ROLES
  // =========================
  document.getElementById("linkRoles").addEventListener("click", async () => {
    actividadSection.style.display = "none";
    rolesSection.style.display = "block";
    tablaRoles.innerHTML = "";

    const res = await fetch("/api/roles", {
      headers: { "Authorization": "Bearer " + token }
    });

    const data = await res.json();

    data.roles.forEach(r => {
      const tr = document.createElement("tr");

      tr.innerHTML = `
        <td>${r.id}</td>
        <td>${r.nombre}</td>
        <td>
          <button class="btn btn-danger btn-sm">Eliminar</button>
        </td>
      `;

      tablaRoles.appendChild(tr);
    });
  });

});
