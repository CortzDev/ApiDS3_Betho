const token = localStorage.getItem("token");
if (!token) window.location.href = "login.html";

async function cargarRoles() {
    const res = await fetch("/roles", {
        headers: { "Authorization": "Bearer " + token }
    });
    const json = await res.json();

    if (!json.ok) {
        alert("Acceso denegado");
        return;
    }

    tablaRoles.innerHTML = json.roles
        .map(r => `
            <tr>
                <td>${r.id}</td>
                <td>
                    <input class="form-control" value="${r.nombre}" id="rol_${r.id}">
                </td>
                <td>
                    <button class="btn btn-warning btn-sm" onclick="editar(${r.id})">Editar</button>
                    <button class="btn btn-danger btn-sm" onclick="eliminar(${r.id})">Eliminar</button>
                </td>
            </tr>
        `)
        .join("");
}

formRol.addEventListener("submit", async (e) => {
    e.preventDefault();

    const res = await fetch("/roles", {
        method: "POST",
        headers: {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ nombre: nombreRol.value })
    });

    const json = await res.json();
    msg.textContent = json.message;
    cargarRoles();
});

async function editar(id) {
    const nombre = document.getElementById("rol_" + id).value;

    await fetch("/roles/" + id, {
        method: "PUT",
        headers: {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ nombre })
    });

    cargarRoles();
}

async function eliminar(id) {
    await fetch("/roles/" + id, {
        method: "DELETE",
        headers: { "Authorization": "Bearer " + token }
    });

    cargarRoles();
}

cargarRoles();
