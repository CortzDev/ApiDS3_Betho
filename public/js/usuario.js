// ===============================
// usuario.js SOLO SOLICITA LLAVE PRIVADA CON MODAL
// ===============================

// Validación básica de sesión
const token = localStorage.getItem("token");
const rol = localStorage.getItem("rol");

if (!token || rol !== "usuario") {
  window.location.href = "/login.html";
}

const tablaProductos = document.getElementById("tablaProductos");
const tablaCarrito   = document.getElementById("tablaCarrito");
const totalSpan      = document.getElementById("total");
const btnLogout      = document.getElementById("btnLogout");
const btnComprar     = document.getElementById("btnComprar");

let carrito = [];

/* ---------------------------------------------------
   WRAPPERS
------------------------------------------------------*/
function alertaSuccess(msg) { window.notifyVentaSuccess(msg); }
function alertaError(msg)   { window.notifyVentaError(msg); }
function alertaWarn(msg)    { window.notifyVentaWarning(msg); }

/* ---------------------------------------------------
   LOGOUT
------------------------------------------------------*/
btnLogout.addEventListener("click", () => {
  localStorage.clear();
  window.location.href = "/login.html";
});

/* ---------------------------------------------------
   CARGAR PRODUCTOS
------------------------------------------------------*/
async function cargarProductos() {
  try {
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
  } catch {
    alertaError("Error cargando productos.");
  }
}

/* ---------------------------------------------------
   AGREGAR AL CARRITO
------------------------------------------------------*/
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
      alertaError("Stock insuficiente.");
      return;
    }
    item.cantidad++;
  } else {
    carrito.push({ id, nombre, precio, cantidad: 1 });
  }
  actualizarCarrito();
}

/* ---------------------------------------------------
   ACTUALIZAR CARRITO
------------------------------------------------------*/
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

/* ---------------------------------------------------
   UTIL: leer archivo
------------------------------------------------------*/
function leerArchivoComoTexto(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Error leyendo archivo"));
    reader.onload  = () => resolve(reader.result);
    reader.readAsText(file);
  });
}

/* ---------------------------------------------------
   canonicalStringify
------------------------------------------------------*/
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalStringify).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
}

/* ---------------------------------------------------
   PEDIR NONCE
------------------------------------------------------*/
async function pedirNonce() {
  const res = await fetch("/api/venta/nonce", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({})
  });

  const data = await res.json();
  if (!data.ok) throw new Error(data.error);
  return data.nonce;
}

/* ---------------------------------------------------
   MODAL: pedir llave privada
------------------------------------------------------*/
function modalPedirLlavePrivada() {
  return new Promise(resolve => {
    const modal = document.getElementById("modalKeyPrivada");
    const btnCancel = document.getElementById("btnPrivKeyCancel");
    const btnContinue = document.getElementById("btnPrivKeyContinue");
    const input = document.getElementById("privateKeyFile");

    input.value = "";
    modal.style.display = "flex";

    btnCancel.onclick = () => {
      modal.style.display = "none";
      resolve(null);
    };

    btnContinue.onclick = async () => {
      if (!input.files.length) {
        alertaWarn("Debes seleccionar una llave privada (.pem)");
        return;
      }

      const file = input.files[0];
      const pem = await file.text();

      modal.style.display = "none";
      resolve({ pem, filename: file.name });
    };
  });
}

/* ---------------------------------------------------
   REGISTRAR VENTA — CON MODAL
------------------------------------------------------*/
btnComprar.addEventListener("click", async () => {

  if (carrito.length === 0) {
    alertaWarn("El carrito está vacío.");
    return;
  }

  let nonce;
  try {
    nonce = await pedirNonce();
  } catch {
    return alertaError("No se pudo obtener el nonce.");
  }

  // Mostrar modal
  const result = await modalPedirLlavePrivada();
  if (!result) {
    return alertaWarn("Operación cancelada.");
  }

  const privatePem = result.pem;
  const filename   = result.filename;

  // ===================== FIRMA =====================
  try {
    // OBJETO VENTA
    const productosPayload = carrito.map(item => ({
      producto_id: item.id,
      cantidad: item.cantidad,
      precio_unitario: item.precio
    }));

    const venta = {
      productos: productosPayload,
      total: parseFloat(totalSpan.textContent) || 0
    };

    const messageObj = { venta, nonce };
    const message = canonicalStringify(messageObj);

    if (!window.forge) return alertaError("Forge no está cargado.");

    let privateKey;
    try {
      privateKey = forge.pki.privateKeyFromPem(privatePem);
    } catch {
      return alertaError("La llave privada no es válida.");
    }

    const md = forge.md.sha256.create();
    md.update(message, "utf8");

    const signatureBytes  = privateKey.sign(md);
    const signatureBase64 = forge.util.encode64(signatureBytes);

    // Generar llave pública
    const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
    const publicPem = forge.pki.publicKeyToPem(publicKey);

    // Payload final
    const payload = {
      productos: productosPayload,
      signature: signatureBase64,
      public_key_pem: publicPem,
      key_filename: filename,
      nonce
    };

    // Enviar al backend
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
      alertaSuccess("Venta registrada correctamente ✔");
      carrito = [];
      actualizarCarrito();
      cargarProductos();
    } else {
      alertaError(data.error || "Error desconocido");
    }

  } catch (err) {
    alertaError("Error procesando la llave privada.");
  }
});

/* ---------------------------------------------------
   INICIO
------------------------------------------------------*/
cargarProductos();
