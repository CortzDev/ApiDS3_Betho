// Token y rol
const token = localStorage.getItem("token");
const rol = localStorage.getItem("rol");

if (!token || rol !== "proveedor") {
  alert("No autorizado");
  window.location.href = "/login.html";
}

// Elementos del DOM
const tabla = document.getElementById("tablaProductos");
const form = document.getElementById("formProducto");
const nombre = document.getElementById("nombre");
const descripcion = document.getElementById("descripcion");
const categoria = document.getElementById("categoria");
const precio = document.getElementById("precio");
const msg = document.getElementById("msg");
const btnLogout = document.getElementById("btnLogout");

// Modal (para editar)
const modalNombre = document.getElementById("modalNombre");
const modalDescripcion = document.getElementById("modalDescripcion");
const modalCategoria = document.getElementById("modalCategoria");
const modalPrecio = document.getElementById("modalPrecio");
const modalGuardar = document.getElementById("modalGuardar");
let productoEditandoID = null;

// Cerrar sesión
btnLogout.addEventListener("click", () => {
  localStorage.removeItem("token");
  localStorage.removeItem("rol");
  window.location.href = "/login.html";
});

// Cargar categorías
async function cargarCategorias() {
  const res = await fetch("/api/categorias", {
    headers: { "Authorization": "Bearer " + token }
  });
  const data = await res.json();
  categoria.innerHTML = "";
  modalCategoria.innerHTML = "";

  if (data.ok) {
    data.categorias.forEach(c => {
      const opt1 = document.createElement("option");
      opt1.value = c.id;
      opt1.textContent = c.nombre;
      categoria.appendChild(opt1);

      const opt2 = opt1.cloneNode(true);
      modalCategoria.appendChild(opt2);
    });
  }
}

// Cargar productos
async function cargarProductos() {
  const res = await fetch("/api/proveedor/productos", {
    headers: { "Authorization": "Bearer " + token }
  });

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
        <td>$${p.precio}</td>
        <td>
          <button class="btn btn-warning btn-sm" onclick="editarProducto(${p.id})">Editar</button>
          <button class="btn btn-danger btn-sm" onclick="eliminarProducto(${p.id})">Eliminar</button>
        </td>
      `;
      tabla.appendChild(tr);
    });
  }
}

// Crear producto
form.addEventListener("submit", async e => {
  e.preventDefault();

  const res = await fetch("/api/proveedor/productos", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token 
    },
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

  if (data.ok) {
    form.reset();
    cargarProductos();
  }
});

// ➤ ABRIR MODAL DE EDICIÓN
window.editarProducto = async function(id) {
  productoEditandoID = id;

  const res = await fetch("/api/proveedor/productos", {
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();
  const prod = data.productos.find(x => x.id === id);

  if (!prod) return alert("Producto no encontrado");

  modalNombre.value = prod.nombre;
  modalDescripcion.value = prod.descripcion;
  modalCategoria.value = prod.categoria_id;
  modalPrecio.value = prod.precio;

  const modal = new bootstrap.Modal(document.getElementById("modalEditar"));
  modal.show();
};

// ➤ GUARDAR CAMBIOS
modalGuardar.addEventListener("click", async () => {
  if (!productoEditandoID) return;

  const res = await fetch(`/api/proveedor/productos/${productoEditandoID}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify({
      nombre: modalNombre.value.trim(),
      descripcion: modalDescripcion.value.trim(),
      categoria_id: parseInt(modalCategoria.value),
      precio: parseFloat(modalPrecio.value)
    })
  });

  const data = await res.json();
  if (!data.ok) return alert("Error: " + data.error);

  const modal = bootstrap.Modal.getInstance(document.getElementById("modalEditar"));
  modal.hide();

  cargarProductos();
});

// ➤ ELIMINAR PRODUCTO
window.eliminarProducto = async function(id) {
  if (!confirm("¿Eliminar producto?")) return;

  const res = await fetch(`/api/proveedor/productos/${id}`, {
    method: "DELETE",
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();

  if (data.ok) {
    cargarProductos();
  } else {
    alert("Error: " + data.error);
  }
};

// Inicializar
cargarCategorias();
cargarProductos();
