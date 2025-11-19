const token = localStorage.getItem("token");
if (!token) {
  alert("No has iniciado sesión");
  window.location.href = "/login.html";
}

// Referencias
const tabla = document.getElementById("tablaRoles");
const form = document.getElementById("formRol");
const nombreInput = document.getElementById("nombreRol");
const msg = document.getElementById("msg");
const btnDashboard = document.getElementById("btnDashboard");

// -------------------- Funciones --------------------

// Cargar roles
async function cargarRoles() {
  const res = await fetch("/roles", {
    headers: { "Authorization": "Bearer " + token }
  });
  const data = await res.json();
  tabla.innerHTML = "";
  if (data.ok) {
    data.roles.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${r.id}</td>
        <td>${r.nombre}</td>
        <td>
          <button class="btn btn-sm btn-warning" onclick="editar(${r.id}, '${r.nombre}')">Editar</button>
          <button class="btn btn-sm btn-danger" onclick="eliminar(${r.id})">Eliminar</button>
        </td>`;
      tabla.appendChild(tr);
    });
  }
}

// Crear rol
form.addEventListener("submit", async e => {
  e.preventDefault();
  const nombre = nombreInput.value.trim();
  if (!nombre) return;

  const res = await fetch("/roles", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ nombre })
  });
  const data = await res.json();
  msg.innerText = data.ok ? "Rol creado correctamente" : "Error: " + data.error;
  msg.className = data.ok ? "text-success" : "text-danger";
  form.reset();
  cargarRoles();
});

// Editar rol
window.editar = async (id, nombre) => {
  const nuevoNombre = prompt("Nuevo nombre del rol:", nombre);
  if (!nuevoNombre) return;
  const res = await fetch(`/roles/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ nombre: nuevoNombre })
  });
  const data = await res.json();
  msg.innerText = data.ok ? "Rol actualizado" : "Error: " + data.error;
  msg.className = data.ok ? "text-success" : "text-danger";
  cargarRoles();
};

// Eliminar rol
window.eliminar = async (id) => {
  if (!confirm("¿Seguro que deseas eliminar este rol?")) return;
  const res = await fetch(`/roles/${id}`, {
    method: "DELETE",
    headers: { "Authorization": "Bearer " + token }
  });
  const data = await res.json();
  msg.innerText = data.ok ? "Rol eliminado" : "Error: " + data.error;
  msg.className = data.ok ? "text-success" : "text-danger";
  cargarRoles();
};

// -------------------- Redirigir al dashboard admin --------------------
btnDashboard.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/perfil", {
      headers: { "Authorization": "Bearer " + token }
    });
    const data = await res.json();
    if (data.ok && data.usuario.rol === "admin") {
      window.location.href = "/admin/dashboard";
    } else {
      alert("No tienes permisos de administrador");
    }
  } catch (err) {
    console.error(err);
    alert("Error al validar sesión");
  }
});

// Inicializar
cargarRoles();
