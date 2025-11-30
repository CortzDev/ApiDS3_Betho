// =========================================
// usuario.js — Usuario + Wallet + PDF Invoice
// =========================================

// VALIDACIÓN SESIÓN
const token = localStorage.getItem("token");
const rol   = localStorage.getItem("rol");

if (!token || rol !== "usuario") {
  window.location.href = "/login.html";
}

// DOM
const tablaProductos = document.getElementById("tablaProductos");
const tablaCarrito   = document.getElementById("tablaCarrito");
const totalSpan      = document.getElementById("total");
const btnLogout      = document.getElementById("btnLogout");
const btnComprar     = document.getElementById("btnComprar");
const btnRegistrarWallet = document.getElementById("btnRegistrarWallet");

let carrito = [];
let lastDecryptedJSON = null;

// ---------------- TOASTS -----------------
function toast(msg, type="info"){
  const id = "t" + Date.now();
  const bg = type==="success" ? "bg-success text-white"
           : type==="danger" ? "bg-danger text-white"
           : type==="warning"? "bg-warning text-dark"
           : "bg-info text-dark";

  const html = `
  <div id="${id}" class="toast ${bg} border-0" data-bs-delay="4000">
    <div class="d-flex">
      <div class="toast-body">${msg}</div>
      <button class="btn-close me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  </div>`;

  document.getElementById("toastContainer").insertAdjacentHTML("beforeend", html);
  const t = new bootstrap.Toast(document.getElementById(id));
  t.show();
}
function alertaSuccess(m){ toast(m,"success"); }
function alertaError(m){ toast(m,"danger"); }
function alertaWarn(m){ toast(m,"warning"); }


// ---------------- LOGOUT -----------------
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

  if (!data.ok) return alertaError("Error cargando productos");

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

    const item = carrito.find(p => p.id === id);

    if (item) {
      if (item.cantidad + 1 > stock)
        return alertaError("Stock insuficiente");
      item.cantidad++;
    } else {
      carrito.push({ id, nombre, precio, cantidad: 1 });
    }

    actualizarCarrito();
  }
});


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
// VERIFICAR SI EL USUARIO TIENE WALLET
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

btnRegistrarWallet.onclick = () => {
  document.getElementById("modalCrearWallet").style.display = "flex";
};


// =========================================
// GUARDAR WALLET (.pub)
// =========================================
document.getElementById("btnSaveWallet").onclick = async () => {
  const file = document.getElementById("walletPubKey").files[0];
  const pin  = document.getElementById("walletPin").value;

  if (!file) return alertaError("Selecciona una clave pública (.pub)");
  if (!/\.pub$/.test(file.name)) return alertaError("Debe ser archivo .pub");
  if (!/^\d{4,8}$/.test(pin)) return alertaError("PIN inválido");

  const pub = await file.text();

  const res = await fetch("/api/wallet/register", {
    method:"POST",
    headers:{
      "Authorization": "Bearer " + token,
      "Content-Type":"application/json"
    },
    body: JSON.stringify({ public_key_pem: pub, pin })
  });

  const data = await res.json();
  if (!data.ok) return alertaError(data.error);

  alertaSuccess("Wallet registrada ✔");
  document.getElementById("modalCrearWallet").style.display = "none";
};


// =========================================
// PEDIR PIN (PROMESA)
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
// REGISTRAR COMPRA (venta-pin)
// =========================================
btnComprar.onclick = async () => {

  if (carrito.length === 0) return alertaWarn("Tu carrito está vacío");

  const pin = await pedirPIN();
  if (!pin) return;

  const productosPayload = carrito.map(p => ({
    producto_id: p.id,
    cantidad: p.cantidad,
    precio_unitario: p.precio
  }));

  const res = await fetch("/api/usuario/venta-pin", {
    method:"POST",
    headers:{
      "Authorization": "Bearer " + token,
      "Content-Type":"application/json"
    },
    body: JSON.stringify({ productos: productosPayload, pin })
  });

  const data = await res.json();
  if (!data.ok) return alertaError(data.error);

  alertaSuccess("Venta completada ✔");

  carrito = [];
  actualizarCarrito();
  cargarProductos();

  // DESCARGAR FACTURA .invoice
  try {
    const dl = await fetch("/api/usuario/invoice-generate", {
      method:"POST",
      headers:{
        "Authorization":"Bearer "+token,
        "Content-Type":"application/json"
      },
      body: JSON.stringify({ ventaId: data.ventaId })
    });

    if (!dl.ok) {
      return alertaWarn("Factura generada, pero no descargada");
    }

    const blob = await dl.blob();
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `invoice_${data.ventaId}.invoice`;
    a.click();

    URL.revokeObjectURL(url);

    alertaSuccess("Factura cifrada descargada ✔");

  } catch (err) {
    console.error(err);
    alertaWarn("Error descargando factura");
  }
};


// =============================================================
//      DESENCRIPTAR FACTURA (.invoice + .pem)
// =============================================================

// Abrir modal
document.getElementById("btnDecryptModal").onclick = () => {
  document.getElementById("modalDecrypt").style.display = "flex";
};

// Cerrar modal
document.getElementById("closeDecryptModal").onclick = () => {
  document.getElementById("modalDecrypt").style.display = "none";
};


// DESENCRIPTAR FACTURA
document.getElementById("btnDecryptStart").onclick = async () => {

  const fileInvoice = document.getElementById("decryptInvoiceFile").files[0];
  const fileKey     = document.getElementById("decryptPrivateKey").files[0];
  const output      = document.getElementById("decryptOutput");
  const pdfBtn      = document.getElementById("btnDownloadPDF");

  if (!fileInvoice) return alertaError("Selecciona archivo .invoice");
  if (!fileKey)     return alertaError("Selecciona tu clave privada .pem");

  try {
    const invoiceText = await fileInvoice.text();
    const pkg = JSON.parse(invoiceText);

    const privatePem = await fileKey.text();

    // 1) Desencriptar clave AES con RSA-OAEP
    const aesKey = crypto.privateDecrypt(
      {
        key: privatePem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(pkg.encrypted_key, "base64")
    );

    // 2) Desencriptar GCM
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      aesKey,
      Buffer.from(pkg.iv, "base64")
    );
    decipher.setAuthTag(Buffer.from(pkg.tag, "base64"));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(pkg.ciphertext, "base64")),
      decipher.final()
    ]);

    // 3) Descomprimir GZIP
    const decompressed = pako.ungzip(decrypted, { to: "string" });

    // Mostrar JSON
    output.style.display = "block";
    output.textContent = decompressed;

    lastDecryptedJSON = JSON.parse(decompressed);
    pdfBtn.style.display = "block";

    alertaSuccess("Factura desencriptada ✔");

  } catch (err) {
    console.error(err);
    alertaError("Error al desencriptar factura");
  }
};


// =============================================================
//           GENERAR PDF DESDE FACTURA DESENCRIPTADA
// =============================================================
document.getElementById("btnDownloadPDF").onclick = () => {

  if (!lastDecryptedJSON)
    return alertaError("No hay factura desencriptada");

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  const v = lastDecryptedJSON.venta;
  let y = 10;

  doc.setFontSize(18);
  doc.text("FACTURA DE COMPRA", 10, y); y += 10;

  doc.setFontSize(12);
  doc.text(`Factura ID: ${v.id}`, 10, y); y += 6;
  doc.text(`Fecha: ${v.fecha}`, 10, y); y += 6;
  doc.text(`Usuario: ${v.usuario_nombre}`, 10, y); y += 6;
  doc.text(`Correo: ${v.email}`, 10, y); y += 10;

  doc.setFontSize(14);
  doc.text("PRODUCTOS:", 10, y); y += 8;

  doc.setFontSize(12);
  v.items.forEach(item => {
    doc.text(
      `Producto ${item.producto_id}  | Cant: ${item.cantidad}  | $${item.precio_unitario}`,
      10, y
    );
    y += 6;
    if (y > 270) { doc.addPage(); y = 10; }
  });

  y += 10;
  doc.setFontSize(14);
  doc.text(`TOTAL: $${v.total}`, 10, y);

  doc.save(`factura_${v.id}.pdf`);
};



// =========================================
// INICIO
// =========================================
cargarProductos();
verificarWallet();
