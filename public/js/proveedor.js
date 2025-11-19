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
const stock = document.getElementById("stock");
const msg = document.getElementById("msg");
const btnLogout = document.getElementById("btnLogout");

// Logout
btnLogout.addEventListener("click", () => {
  localStorage.clear();
  window.location.href = "/login.html";
});

// Cargar categorías
// Cargar categorías desde la API
async function cargarCategorias() {
  const res = await fetch("/api/categorias", {
    headers: { "Authorization": "Bearer " + token }
  });

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
        <td>${p.precio}</td>
        <td>${p.stock}</td>
        <td>
          <button class="btn btn-warning btn-sm" onclick="editarProducto(${p.id})">Editar</button>
        </td>
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
    headers: { 
      "Content-Type": "application/json", 
      "Authorization": "Bearer " + token 
    },
    body: JSON.stringify({
      nombre: nombre.value.trim(),
      descripcion: descripcion.value.trim(),
      categoria_id: parseInt(categoria.value),
      precio: parseFloat(precio.value),
      stock: parseInt(stock.value)
    })
  });

  const data = await res.json();

  msg.innerText = data.ok ? "Producto agregado correctamente" : "Error: " + data.error;
  msg.className = data.ok ? "text-success" : "text-danger";

  form.reset();
  cargarProductos();
});

// =============== EDITAR PRODUCTO ===============

window.editarProducto = async function(id) {

  const res = await fetch("/api/proveedor/productos/" + id, {
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();
  const p = data.producto;

  document.getElementById("edit_id").value = p.id;
  document.getElementById("edit_nombre").value = p.nombre;
  document.getElementById("edit_descripcion").value = p.descripcion;
  document.getElementById("edit_precio").value = p.precio;
  document.getElementById("edit_stock").value = p.stock;

  // categorías
  const select = document.getElementById("edit_categoria");
  select.innerHTML = "";

  const resCat = await fetch("/api/categorias", {
    headers: { "Authorization": "Bearer " + token }
  });

  const cats = await resCat.json();

  cats.categorias.forEach(c => {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = c.nombre;
    if (c.id === p.categoria_id) opt.selected = true;
    select.appendChild(opt);
  });

  const modal = new bootstrap.Modal(document.getElementById("modalEditar"));
  modal.show();
};

document.getElementById("btnGuardarCambios").addEventListener("click", async () => {

  const id = document.getElementById("edit_id").value;

  const body = {
    nombre: document.getElementById("edit_nombre").value,
    descripcion: document.getElementById("edit_descripcion").value,
    categoria_id: parseInt(document.getElementById("edit_categoria").value),
    precio: parseFloat(document.getElementById("edit_precio").value),
    stock: parseInt(document.getElementById("edit_stock").value)
  };

  const res = await fetch("/api/proveedor/productos/" + id, {
    method: "PUT",
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  const data = await res.json();

  if (data.ok) {
    alert("Producto actualizado correctamente");
    const modal = bootstrap.Modal.getInstance(document.getElementById("modalEditar"));
    modal.hide();
    cargarProductos();
  } else {
    alert("Error: " + data.error);
  }
});

// Inicializar
cargarCategorias();
cargarProductos();
