const API = "http://localhost:3000"; // ajusta si usas otro puerto
const token = localStorage.getItem("token");

// Si no hay token, enviar al login
if (!token) {
  window.location.href = "login.html";
}

// Mostrar roles al hacer clic en el menú
document.getElementById("linkRoles").addEventListener("click", () => {
  document.getElementById("rolesSection").style.display = "block";
  cargarRoles();
});

// Cerrar sesión
document.getElementById("logoutBtn").addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "login.html";
});

// ------------------------------------------------------
// Cargar contadores
// ------------------------------------------------------
async function cargarContadores() {
  try {
    const res = await fetch(`${API}/admin/dashboard`, {
      headers: { "Authorization": "Bearer " + token }
    });

    const data = await res.json();

    document.getElementById("countUsuarios").innerText = data.usuarios;
    document.getElementById("countRoles").innerText = data.roles;
    document.getElementById("countActividad").innerText = data.actividad;

  } catch (err) {
    console.error(err);
  }
}
cargarContadores();

// ------------------------------------------------------
// CRUD ROLES (USANDO JWT)
// ------------------------------------------------------
async function cargarRoles() {
  try {
    const res = await fetch(`${API}/roles`, {
      headers: { "Authorization": "Bearer " + token }
    });

    const roles = await res.json();
    const tbody = document.getElementById("tablaRoles");

    tbody.innerHTML = "";

    roles.forEach(r => {
      tbody.innerHTML += `
        <tr>
          <td>${r.id}</td>
          <td>${r.nombre}</td>
          <td>
            <button class="btn btn-warning btn-sm" onclick="editarRol(${r.id}, '${r.nombre}')">Editar</button>
            <button class="btn btn-danger btn-sm" onclick="eliminarRol(${r.id})">Eliminar</button>
          </td>
        </tr>
      `;
    });

  } catch (err) {
    console.error(err);
  }
}

window.editarRol = function(id, nombre) {
  document.getElementById("rolId").value = id;
  document.getElementById("rolNombre").value = nombre;
  document.getElementById("msgRol").innerText = "";
  new bootstrap.Modal(document.getElementById("modalRol")).show();
};

window.eliminarRol = async function(id) {
  if (!confirm("¿Eliminar este rol?")) return;

  try {
    await fetch(`${API}/roles/${id}`, {
      method: "DELETE",
      headers: { "Authorization": "Bearer " + token }
    });

    cargarRoles();
  } catch (err) {
    console.error(err);
  }
};

document.getElementById("logoutBtn").addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "login.html";
});


document.getElementById("guardarRolBtn").addEventListener("click", async () => {
  const id = document.getElementById("rolId").value;
  const nombre = document.getElementById("rolNombre").value;

  if (nombre.trim() === "") {
    document.getElementById("msgRol").innerText = "El nombre es obligatorio.";
    return;
  }

  const metodo = id ? "PUT" : "POST";
  const url = id ? `${API}/roles/${id}` : `${API}/roles`;

  try {
    await fetch(url, {
      method: metodo,
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify({ nombre })
    });

    document.getElementById("msgRol").innerText = "Guardado correctamente.";
    cargarRoles();

  } catch (err) {
    console.error(err);
  }
});
