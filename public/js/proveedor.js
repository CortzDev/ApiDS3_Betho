// Token y rol
const token = localStorage.getItem("token");
const rol = localStorage.getItem("rol");
if (!token || rol !== "proveedor") {
  alert("No autorizado");
  window.location.href = "/login.html";
}

// Referencias
const tabla = document.getElementById("tablaProductos");
const form = document.getElementById("formProducto");
const nombre = document.getElementById("nombre");
const descripcion = document.getElementById("descripcion");
const categoria = document.getElementById("categoria");
const precio = document.getElementById("precio");
const msg = document.getElementById("msg");
const btnLogout = document.getElementById("btnLogout");

// Cerrar sesión
btnLogout.addEventListener("click", () => {
  localStorage.removeItem("token");
  localStorage.removeItem("rol");
  window.location.href = "/login.html";
});

// Cargar categorías
async function cargarCategorias() {
  const res = await fetch("/api/categorias", { headers: { "Authorization": "Bearer " + token } });
  const data = await res.json();
  categoria.innerHTML = "";
  if (data.ok) {
    data.categorias.forEach(c => {
      const option = document.createElement("option");
      option.value = c.id;
      option.textContent = c.nombre;
      categoria.appendChild(option);
    });
  }
}

// Cargar productos
async function cargarProductos() {
  const res = await fetch("/api/proveedor/productos", { headers: { "Authorization": "Bearer " + token } });
  const data = await res.json();
  tabla.innerHTML = "";
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
      tabla.appendChild(tr);
    });
  }
}

// Agregar producto
form.addEventListener("submit", async e => {
  e.preventDefault();
  const res = await fetch("/api/proveedor/productos", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({
      nombre: nombre.value.trim(),
      descripcion: descripcion.value.trim(),
      categoria_id: parseInt(categoria.value),
      precio: parseFloat(precio.value)
    })
  });
  const data = await res.json();
  msg.innerText = data.ok ? "Producto agregado correctamente" : "Error: " + data.error;
  msg.className = data.ok ? "text-success" : "text-danger";
  form.reset();
  cargarProductos();
});

// Inicializar
cargarCategorias();
cargarProductos();
