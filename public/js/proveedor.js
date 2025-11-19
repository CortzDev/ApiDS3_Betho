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
let productoEditandoId = null;

// Cerrar sesión
btnLogout.addEventListener("click", () => {
  localStorage.removeItem("token");
  localStorage.removeItem("rol");
  window.location.href = "/login.html";
});


// =========================
// Cargar categorías
// =========================
async function cargarCategorias() {
  try {
    const res = await fetch("/api/categorias", {
      headers: { "Authorization": "Bearer " + token }
    });

    const data = await res.json();

    if (!data.ok) {
      console.error("Error al obtener categorías:", data.error);
      return;
    }

    categoria.innerHTML = "";

    data.categorias.forEach(cat => {
      const opt = document.createElement("option");
      opt.value = cat.id;
      opt.textContent = cat.nombre;
      categoria.appendChild(opt);
    });

  } catch (err) {
    console.error("Error cargando categorías:", err);
  }
}


function editarProducto(id, nombreP, descripcionP, categoriaP, precioP, stockP) {
  editando = true;
  idEditando = id;

  nombre.value = nombreP;
  descripcion.value = descripcionP;
  precio.value = precioP;
  stock.value = stockP;

  [...categoria.options].forEach(opt => {
    if (opt.textContent === categoriaP) opt.selected = true;
  });

  msg.innerHTML = `<b>Editando producto ID ${id}</b>`;
  msg.className = "text-primary";
}


async function eliminarProducto(id) {
  if (!confirm("¿Seguro de eliminar este producto?")) return;

  try {
    const res = await fetch(`/api/proveedor/productos/${id}`, {
      method: "DELETE",
      headers: {
        "Authorization": "Bearer " + token
      }
    });

    const data = await res.json();

    if (data.ok) {
      alert("Producto eliminado");
      cargarProductos();
    } else {
      alert("Error: " + data.error);
    }

  } catch (err) {
    console.error(err);
  }
}



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
          <td>${p.categoria}</td>
          <td>$${p.precio}</td>
          <td>${p.stock}</td>

          <td>
            <button class="btn btn-warning btn-sm"
              onclick="editarProducto(${p.id}, '${p.nombre}', '${p.descripcion}', '${p.categoria}', ${p.precio}, ${p.stock})">
              Editar
            </button>
          </td>

          <td>
            <button class="btn btn-danger btn-sm" onclick="eliminarProducto(${p.id})">
              Eliminar
            </button>
          </td>
        `;

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
// Agregar producto
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
      msg.innerText = editando ? "Producto editado correctamente" : "Producto agregado";
      msg.className = "text-success";

      form.reset();
      editando = false;
      idEditando = null;
      cargarProductos();
    } else {
      msg.innerText = "Error: " + data.error;
      msg.className = "text-danger";
    }

  } catch (err) {
    console.error(err);
  }
});


// Inicializar vista
cargarCategorias();
cargarProductos();
