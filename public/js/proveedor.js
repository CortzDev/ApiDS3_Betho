const token = localStorage.getItem("token");
if (!token) {
  alert("No has iniciado sesión");
  window.location.href = "/login.html";
}

// Referencias
const formProducto = document.getElementById("formProducto");
const tablaProductos = document.getElementById("tablaProductos");
const msg = document.getElementById("msg");
const categoriaSelect = document.getElementById("categoria");
const btnLogout = document.getElementById("btnLogout");

// Cargar categorías
async function cargarCategorias() {
  const res = await fetch("/api/categorias", {
    headers: { "Authorization": "Bearer " + token }
  });
  const data = await res.json();
  categoriaSelect.innerHTML = "";
  if (data.ok) {
    data.categorias.forEach(c => {
      const opt = document.createElement("option");
      opt.value = c.id;
      opt.textContent = c.nombre;
      categoriaSelect.appendChild(opt);
    });
  }
}

// Cargar productos del proveedor
async function cargarProductos() {
  const res = await fetch("/api/proveedor/productos", {
    headers: { "Authorization": "Bearer " + token }
  });
  const data = await res.json();
  tablaProductos.innerHTML = "";
  if (data.ok) {
    data.productos.forEach(p => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${p.id}</td>
        <td>${p.nombre}</td>
        <td>${p.descripcion}</td>
        <td>${p.categoria_id}</td>
        <td>${p.precio}</td>
      `;
      tablaProductos.appendChild(tr);
    });
  }
}

// Guardar producto
formProducto.addEventListener("submit", async (e) => {
  e.preventDefault();
  const nombre = document.getElementById("nombre").value.trim();
  const descripcion = document.getElementById("descripcion").value.trim();
  const categoria_id = categoriaSelect.value;
  const precio = parseFloat(document.getElementById("precio").value);

  if (!nombre || !precio) return;

  const res = await fetch("/api/proveedor/productos", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ nombre, descripcion, categoria_id, precio })
  });

  const data = await res.json();
  msg.innerText = data.ok ? "Producto guardado correctamente" : "Error: " + data.error;
  msg.className = data.ok ? "text-success" : "text-danger";
  formProducto.reset();
  cargarProductos();
});

// Logout
btnLogout.addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "/login.html";
});

// Inicializar
cargarCategorias();
cargarProductos();
