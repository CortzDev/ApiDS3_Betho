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

btnDashboard.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/perfil", {
      headers: { "Authorization": "Bearer " + token }
    });
    const data = await res.json();
    if (!data.ok) throw new Error("Error al obtener perfil");

    const rol = data.usuario.rol;
    if (rol === "admin") {
      window.location.href = "/admin/dashboard";
    } else if (rol === "proveedor") {
      window.location.href = "/proveedor/dashboard";
    } else {
      alert("No tienes permisos para acceder al dashboard");
    }
  } catch (err) {
    console.error(err);
    alert("Error al validar sesión");
    window.location.href = "/login.html";
  }
});

// Inicializar tabla
cargarRoles();
