const token = localStorage.getItem("token");

if (!token) {
  alert("No has iniciado sesión");
  window.location.href = "/login.html";
}

// Mostrar info del usuario
fetch("/api/perfil", {
  headers: { "Authorization": "Bearer " + token }
})
  .then(res => res.json())
  .then(data => {
    if (data.ok) document.getElementById("usuarioInfo").innerText = `Bienvenido: ${data.usuario.nombre}`;
  });

// Cargar categorías
async function cargarCategorias() {
  const res = await fetch("/api/categorias", {
    headers: { "Authorization": "Bearer " + token }
  });
  const data = await res.json();
  const select = document.getElementById("categoria_id");
  select.innerHTML = "";
  if (data.ok) {
    data.categorias.forEach(c => {
      const option = document.createElement("option");
      option.value = c.id;
      option.innerText = c.nombre;
      select.appendChild(option);
    });
  }
}

// Llamar al inicio
cargarCategorias();



// Cargar productos del proveedor
async function cargarProductos() {
  const res = await fetch("/api/proveedor/productos", {
    headers: { "Authorization": "Bearer " + token }
  });
  const data = await res.json();
  const tbody = document.querySelector("#tablaProductos tbody");
  tbody.innerHTML = "";
  if (data.ok) {
    data.productos.forEach(p => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${p.id}</td><td>${p.nombre}</td><td>${p.descripcion}</td><td>${p.categoria_id}</td><td>${p.precio}</td>`;
      tbody.appendChild(tr);
    });
  }
}
cargarProductos();

// Guardar producto
document.getElementById("formProducto").addEventListener("submit", async e => {
  e.preventDefault();
  const nombre = document.getElementById("nombre").value;
  const descripcion = document.getElementById("descripcion").value;
  const categoria_id = document.getElementById("categoria_id").value;
  const precio = document.getElementById("precio").value;

  const res = await fetch("/api/proveedor/productos", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify({ nombre, descripcion, categoria_id, precio })
  });

  const data = await res.json();
  const msg = document.getElementById("msg");

  if (data.ok) {
    msg.innerText = "Producto guardado correctamente!";
    msg.className = "text-success";
    document.getElementById("formProducto").reset();
    cargarProductos();
  } else {
    msg.innerText = "Error: " + data.error;
    msg.className = "text-danger";
  }
});
