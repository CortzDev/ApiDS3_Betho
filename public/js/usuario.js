const token = localStorage.getItem("token");
const rol = localStorage.getItem("rol");

if (!token || rol !== "usuario") {
  alert("No autorizado");
  window.location.href = "/login.html";
}

const tablaProductos = document.getElementById("tablaProductos");
const tablaCarrito = document.getElementById("tablaCarrito");
const totalSpan = document.getElementById("total");
const msg = document.getElementById("msg");
const btnLogout = document.getElementById("btnLogout");
const btnComprar = document.getElementById("btnComprar");

let carrito = [];

// ================= LOGOUT =================
btnLogout.addEventListener("click", () => {
  localStorage.clear();
  window.location.href = "/login.html";
});

// ================= CARGAR PRODUCTOS =================
async function cargarProductos() {
  const res = await fetch("/api/productos", {
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();
  tablaProductos.innerHTML = "";

  if (data.ok) {
    data.productos.forEach(p => {
      const tr = document.createElement("tr");

      tr.innerHTML = `
        <td>${p.nombre}</td>
        <td>${p.descripcion}</td>
        <td>$${p.precio}</td>
        <td>${p.stock}</td>
        <td>
          <button class="btn btn-primary btn-sm btn-agregar"
                  data-id="${p.id}"
                  data-nombre="${p.nombre}"
                  data-precio="${p.precio}"
                  data-stock="${p.stock}">
            Agregar
          </button>
        </td>
      `;

      tablaProductos.appendChild(tr);
    });
  }
}

// ================= AGREGAR AL CARRITO =================
// Reemplaza onclick con addEventListener para CSP
document.addEventListener("click", e => {
  if (e.target.classList.contains("btn-agregar")) {
    const id = parseInt(e.target.dataset.id);
    const nombre = e.target.dataset.nombre;
    const precio = parseFloat(e.target.dataset.precio);
    const stock = parseInt(e.target.dataset.stock);

    agregarCarrito(id, nombre, precio, stock);
  }
});

function agregarCarrito(id, nombre, precio, stock) {
  const item = carrito.find(i => i.id === id);

  if (item) {
    if (item.cantidad + 1 > stock) {
      alert("Stock insuficiente");
      return;
    }
    item.cantidad++;
  } else {
    carrito.push({ id, nombre, precio, cantidad: 1 });
  }

  actualizarCarrito();
}

// ================= ACTUALIZAR CARRITO =================
function actualizarCarrito() {
  tablaCarrito.innerHTML = "";
  let total = 0;

  carrito.forEach(item => {
    const subtotal = item.precio * item.cantidad;
    total += subtotal;

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${item.nombre}</td>
      <td>${item.cantidad}</td>
      <td>$${subtotal.toFixed(2)}</td>
    `;

    tablaCarrito.appendChild(tr);
  });

  totalSpan.textContent = total.toFixed(2);
}

// ================= REGISTRAR VENTA =================
btnComprar.addEventListener("click", async () => {
  if (carrito.length === 0) {
    msg.textContent = "El carrito está vacío";
    msg.className = "text-danger";
    return;
  }

  const payload = {
    productos: carrito.map(item => ({
      producto_id: item.id,
      cantidad: item.cantidad,
      precio_unitario: item.precio
    }))
  };

  try {
    const res = await fetch("/api/usuario/venta", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (data.ok) {
      msg.textContent = "Venta registrada correctamente";
      msg.className = "text-success";

      carrito = [];
      actualizarCarrito();
      cargarProductos();
    } else {
      msg.textContent = "Error: " + data.error;
      msg.className = "text-danger";
    }

  } catch (err) {
    console.error("Error en compra:", err);
    msg.textContent = "Error de conexión";
    msg.className = "text-danger";
  }
});


// ================= INICIALIZAR =================
cargarProductos();
