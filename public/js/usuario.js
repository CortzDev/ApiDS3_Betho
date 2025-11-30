// =========================================
// usuario.js — Compra con PIN + Wallet del servidor
// =========================================

// Validación de sesión
const token = localStorage.getItem("token");
const rol   = localStorage.getItem("rol");

if (!token || rol !== "usuario") {
  window.location.href = "/login.html";
}

// Referencias DOM
const tablaProductos = document.getElementById("tablaProductos");
const tablaCarrito   = document.getElementById("tablaCarrito");
const totalSpan      = document.getElementById("total");
const btnLogout      = document.getElementById("btnLogout");
const btnComprar     = document.getElementById("btnComprar");
const btnRegistrarWallet = document.getElementById("btnRegistrarWallet");

let carrito = [];

// Toast helpers
function alertaSuccess(m){ toastSuccess(m); }
function alertaError(m)  { toastError(m); }
function alertaWarn(m)   { toastInfo(m); }

// =========================================
// LOGOUT
// =========================================
btnLogout.onclick = () => {
  localStorage.clear();
  window.location.href = "/login.html";
};

// =========================================
// CARGAR PRODUCTOS
// =========================================
async function cargarProductos() {
  const res = await fetch("/api/productos", {
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();
  tablaProductos.innerHTML = "";

  if (!data.ok) {
    alertaError("Error cargando productos");
    return;
  }

  data.productos.forEach(p => {
    tablaProductos.insertAdjacentHTML("beforeend", `
      <tr>
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
      </tr>
    `);
  });
}

// =========================================
// AGREGAR AL CARRITO
// =========================================
document.addEventListener("click", e => {
  if (e.target.classList.contains("btn-agregar")) {
    const id     = parseInt(e.target.dataset.id);
    const nombre = e.target.dataset.nombre;
    const precio = parseFloat(e.target.dataset.precio);
    const stock  = parseInt(e.target.dataset.stock);

    agregarCarrito(id, nombre, precio, stock);
  }
});

function agregarCarrito(id, nombre, precio, stock) {
  const item = carrito.find(i => i.id === id);

  if (item) {
    if (item.cantidad + 1 > stock) {
      return alertaError("Stock insuficiente.");
    }
    item.cantidad++;
  } else {
    carrito.push({ id, nombre, precio, cantidad: 1 });
  }

  actualizarCarrito();
}

// =========================================
// ACTUALIZAR CARRITO
// =========================================
function actualizarCarrito() {
  tablaCarrito.innerHTML = "";
  let total = 0;

  carrito.forEach(p => {
    const subtotal = p.precio * p.cantidad;
    total += subtotal;

    tablaCarrito.insertAdjacentHTML("beforeend", `
      <tr>
        <td>${p.nombre}</td>
        <td>${p.cantidad}</td>
        <td>$${subtotal.toFixed(2)}</td>
      </tr>
    `);
  });

  totalSpan.textContent = total.toFixed(2);
}

// =========================================
// VERIFICAR WALLET EN SERVIDOR
// =========================================
async function verificarWallet() {
  const res = await fetch("/api/wallet/me", {
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();

  if (!data.ok || !data.wallet) {
    document.getElementById("modalCrearWallet").style.display = "flex";
  }
}

// =========================================
// REGISTRAR WALLET MANUALMENTE (BOTÓN)
// =========================================
btnRegistrarWallet.onclick = () => {
  document.getElementById("modalCrearWallet").style.display = "flex";
};

// =========================================
// GUARDAR WALLET EN SERVIDOR
// =========================================
// =========================================
// GUARDAR WALLET EN SERVIDOR (.pub)
// =========================================
document.getElementById("btnSaveWallet").onclick = async () => {
  const file = document.getElementById("walletPubKey").files[0];
  const pin  = document.getElementById("walletPin").value;

  if (!file) return alertaError("Selecciona una clave pública (.pub)");
  if (!file.name.endsWith(".pub")) {
    return alertaError("El archivo debe terminar en .pub");
  }

  if (!/^\d{4,8}$/.test(pin)) {
    return alertaError("El PIN debe tener entre 4 y 8 dígitos");
  }

  // sigue siendo formato PEM internamente!
  const publicKeyPub = await file.text();

  const res = await fetch("/api/wallet/register", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ public_key_pem: publicKeyPub, pin })
  });

  const data = await res.json();
  if (!data.ok) return alertaError(data.error);

  alertaSuccess("Wallet registrada correctamente");
  document.getElementById("modalCrearWallet").style.display = "none";
};


// =========================================
// PEDIR PIN ANTES DE COMPRAR
// =========================================
function pedirPIN() {
  const modal = document.getElementById("modalPin");
  const input = document.getElementById("pinInput");

  modal.style.display = "flex";
  input.value = "";
  input.focus();

  return new Promise(resolve => {

    document.getElementById("btnPinCancel").onclick = () => {
      modal.style.display = "none";
      resolve(null);
    };

    document.getElementById("btnPinContinue").onclick = () => {
      const pin = input.value.trim();

      if (!/^\d{4,8}$/.test(pin)) {
        alertaWarn("PIN inválido");
        return;
      }

      modal.style.display = "none";
      resolve(pin);
    };
  });
}

// =========================================
// REGISTRAR VENTA (usa wallet + PIN del servidor)
// =========================================
btnComprar.onclick = async () => {

  if (carrito.length === 0) {
    return alertaWarn("El carrito está vacío.");
  }

  const pin = await pedirPIN();
  if (!pin) return;

  const productosPayload = carrito.map(p => ({
    producto_id: p.id,
    cantidad: p.cantidad,
    precio_unitario: p.precio
  }));

  const payload = {
    productos: productosPayload,
    pin
  };

  const res = await fetch("/api/usuario/venta-pin", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const data = await res.json();

  if (!data.ok) {
    return alertaError(data.error || "Error procesando la venta");
  }

  alertaSuccess("Venta procesada correctamente ✔");
  carrito = [];
  actualizarCarrito();
  cargarProductos();
};

// =========================================
// INICIO
// =========================================
cargarProductos();
verificarWallet();
