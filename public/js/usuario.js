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

// Logout
btnLogout.addEventListener("click", () => {
  localStorage.clear();
  window.location.href = "/login.html";
});

// Cargar productos disponibles
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
          <button class="btn btn-primary btn-sm" onclick="agregarCarrito(${p.id}, '${p.nombre}', ${p.precio}, ${p.stock})">
            Agregar
          </button>
        </td>
      `;

      tablaProductos.appendChild(tr);
    });
  }
}

window.agregarCarrito = function (id, nombre, precio, stock) {
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
};

// Actualizar tabla carrito
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

// Registrar venta
btnComprar.addEventListener("click", async () => {
  if (carrito.length === 0) {
    msg.textContent = "El carrito está vacío";
    msg.className = "text-danger";
    return;
  }

  const res = await fetch("/api/ventas", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ items: carrito })
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
});

// Inicializar
cargarProductos();
