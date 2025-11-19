// =========================
//   proveedor.js
// =========================

// Token y rol
const token = localStorage.getItem("token");
const rol = localStorage.getItem("rol");

if (!token || rol !== "proveedor") {
  alert("No autorizado.");
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

let editando = false;
let idEditando = null;

// =========================
// Cerrar sesión
// =========================
btnLogout.addEventListener("click", () => {
  localStorage.removeItem("token");
  localStorage.removeItem("rol");
  window.location.href = "/login.html";
});

// =========================
// CARGAR CATEGORÍAS
// =========================
async function cargarCategorias() {
  try {
    const res = await fetch("/api/categorias", {
      headers: { "Authorization": "Bearer " + token }
    });

    const data = await res.json();

    categoria.innerHTML = "";

    if (data.ok) {
      data.categorias.forEach(cat => {
        const opt = document.createElement("option");
        opt.value = cat.id;
        opt.textContent = cat.nombre;
        categoria.appendChild(opt);
      });
    }

  } catch (err) {
    console.error("Error cargando categorías:", err);
  }
}

// =========================
// EDITAR PRODUCTO (abre formulario)
// =========================
function activarModoEdicion(producto) {
  editando = true;
  idEditando = producto.id;

  nombre.value = producto.nombre;
  descripcion.value = producto.descripcion;
  precio.value = producto.precio;
  stock.value = producto.stock;

  categoria.value = producto.categoria_id;

  msg.innerHTML = `<b>Editando producto ID ${producto.id}</b>`;
  msg.className = "text-primary";
}

// =========================
// ELIMINAR PRODUCTO
// =========================
async function eliminarProducto(id) {
  if (!confirm("¿Seguro de eliminar este producto?")) return;

  try {
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
  } catch (err) {
    console.error("Error eliminando producto:", err);
  }
}

// =========================
// LISTAR PRODUCTOS
// =========================
async function cargarProductos() {
  try {
    const res = await fetch("/api/proveedor/productos", {
      headers: { "Authorization": "Bearer " + token }
    });

    const data = await res.json();
    tabla.innerHTML = "";

    if (data.ok && data.productos.length > 0) {
      data.productos.forEach(p => {
        const tr = document.createElement("tr");

        tr.innerHTML = `
          <td>${p.id}</td>
          <td>${p.nombre}</td>
          <td>${p.descripcion}</td>
          <td>${p.categoria_id}</td>
          <td>$${p.precio}</td>
          <td>${p.stock}</td>
          <td><button class="btn btn-warning btn-sm btn-edit">Editar</button></td>
          <td><button class="btn btn-danger btn-sm btn-delete">Eliminar</button></td>
        `;

        // --- EVENTOS SIN INLINE (CSP-friendly) ---

        tr.querySelector(".btn-edit").addEventListener("click", () => {
          activarModoEdicion(p);
        });

        tr.querySelector(".btn-delete").addEventListener("click", () => {
          eliminarProducto(p.id);
        });

        tabla.appendChild(tr);
      });

    } else {
      tabla.innerHTML = `
        <tr>
          <td colspan="8" class="text-center text-muted">No hay productos</td>
        </tr>`;
    }

  } catch (err) {
    console.error("Error cargando productos:", err);
  }
}

// =========================
// AGREGAR / EDITAR PRODUCTO
// =========================
form.addEventListener("submit", async e => {
  e.preventDefault();

  const datos = {
    nombre: nombre.value.trim(),
    descripcion: descripcion.value.trim(),
    categoria_id: parseInt(categoria.value),
    precio: parseFloat(precio.value),
    stock: parseInt(stock.value)
  };

  let url = "/api/proveedor/productos";
  let method = "POST";

  if (editando) {
    url = `/api/proveedor/productos/${idEditando}`;
    method = "PUT";
  }

  try {
    const res = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify(datos)
    });

    const data = await res.json();

    if (data.ok) {
      msg.innerText = editando
        ? "Producto actualizado correctamente"
        : "Producto agregado correctamente";

      msg.className = "text-success";

      editando = false;
      idEditando = null;
      form.reset();
      cargarProductos();

    } else {
      msg.innerText = "Error: " + data.error;
      msg.className = "text-danger";
    }

  } catch (err) {
    console.error("Error guardando producto:", err);
  }
});

// =========================
// INICIALIZAR
// =========================
cargarCategorias();
cargarProductos();
