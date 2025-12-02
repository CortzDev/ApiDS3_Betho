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

// Alertas
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


//LOGOUT 
btnLogout.onclick = () => {
  localStorage.clear();
  window.location.href = "/login.html";
};


// CARGAR PRODUCTOS
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

// AGREGAR AL CARRITO
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

// ACTUALIZAR CARRITO
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

// Validacion que verifica si el usuario tiene wallet
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

// GUARDAR WALLET (.pem)
document.getElementById("btnSaveWallet").onclick = async () => {
  const file = document.getElementById("walletPubKey").files[0];
  const pin  = document.getElementById("walletPin").value;

  if (!file) return alertaError("Selecciona una clave pública (.pem)");
  if (!/\.pem$/i.test(file.name)) return alertaError("Debe ser archivo .pem");
  if (!/^\d{4,8}$/.test(pin)) return alertaError("PIN inválido");

  const pub = await file.text();

  if (!pub.includes("BEGIN PUBLIC KEY")) {
    return alertaError("El archivo no contiene una clave pública válida");
  }

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

// PEDIR PIN 
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

// REGISTRAR COMPRA (venta-pin)
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

//      DESENCRIPTAR FACTURA (.invoice + .pem) 
// Helpers
function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function concatUint8Arrays(a, b) {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

function pemToArrayBuffer(pem) {
  
  const lines = pem.trim().split(/\r?\n/);

  const base64Lines = lines.filter(line => !line.includes('BEGIN') && !line.includes('END'));
  const base64 = base64Lines.join('');
  return base64ToUint8Array(base64).buffer;
}

async function importPrivateKeyFromPem(pem) {
  // detect header
  if (pem.includes("-----BEGIN PRIVATE KEY-----")) {
    const ab = pemToArrayBuffer(pem);
    return await window.crypto.subtle.importKey(
      "pkcs8",
      ab,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  } else if (pem.includes("-----BEGIN RSA PRIVATE KEY-----")) {
    throw new Error(
      "Clave en formato PKCS#1 detectada. Convierte a PKCS#8 con:\n\n" +
      "openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in user1priv.pem -out user1priv_pk8.pem\n\n" +
      "Luego usa el archivo resultante (user1priv_pk8.pem) en la UI."
    );
  } else {
    throw new Error("Formato PEM no reconocido. Debe contener 'BEGIN PRIVATE KEY' o 'BEGIN RSA PRIVATE KEY'.");
  }
}

// Abrir modal
document.getElementById("btnDecryptModal").onclick = () => {
  document.getElementById("modalDecrypt").style.display = "flex";
};

// Cerrar modal
document.getElementById("closeDecryptModal").onclick = () => {
  document.getElementById("modalDecrypt").style.display = "none";
};

// DESENCRIPTAR FACTURA usando WebCrypto
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

    // Importar clave privada (webcrypto)
    let privateKey;
    try {
      privateKey = await importPrivateKeyFromPem(privatePem);
    } catch (err) {
      console.error(err);
      alertaError(
        "Error importando la clave privada: " + err.message +
        "\nSi tu clave es del tipo 'RSA PRIVATE KEY', conviértela a PKCS#8 con OpenSSL:\n" +
        "openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in user1priv.pem -out user1priv_pk8.pem"
      );
      return;
    }

    //Desencriptar la clave AES con RSA-OAEP (la encrypted_key viene en base64)
    const encryptedKeyBytes = base64ToUint8Array(pkg.encrypted_key).buffer;
    const aesKeyRaw = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedKeyBytes
    ); // ArrayBuffer (raw AES key bytes)

    // Importar clave AES para AES-GCM
    const aesKey = await window.crypto.subtle.importKey(
      "raw",
      aesKeyRaw,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // Preparar ciphertext + tag (pkg.ciphertext y pkg.tag están en base64 por separado)
    const ciphertextBytes = base64ToUint8Array(pkg.ciphertext);
    const tagBytes = base64ToUint8Array(pkg.tag);
    const combined = concatUint8Arrays(ciphertextBytes, tagBytes);

    const ivBytes = base64ToUint8Array(pkg.iv);

    // Desencriptar AES-GCM
    const decryptedArrayBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBytes,
        tagLength: 128
      },
      aesKey,
      combined.buffer
    );

    // Descomprimir GZIP
    const decryptedUint8 = new Uint8Array(decryptedArrayBuffer);
    const decompressed = pako.ungzip(decryptedUint8, { to: "string" });

    // Mostrar JSON
    output.style.display = "block";
    output.textContent = decompressed;

    lastDecryptedJSON = JSON.parse(decompressed);
    pdfBtn.style.display = "block";

    alertaSuccess("Factura desencriptada ✔");

  } catch (err) {
    console.error(err);
    alertaError("Error al desencriptar factura: " + (err.message || err));
  }
};

//    PDF FACTURA (jsPDF)
document.getElementById("btnDownloadPDF").onclick = async () => {

  if (!lastDecryptedJSON)
    return alertaError("No hay factura desencriptada");

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: "mm", format: "letter" });

  const v = lastDecryptedJSON.venta;

  let y = 10;
  doc.setFillColor(240, 240, 240);
  doc.rect(0, 0, 216, 279, "F");
  // TÍTULO
  doc.setFontSize(26);
  doc.setTextColor(40, 62, 81);
  doc.text("FACTURA ELECTRÓNICA", 125, 25, { align: "center" });

  // Línea decorativa
  doc.setDrawColor(40, 62, 81);
  doc.setLineWidth(1.2);
  doc.line(10, 55, 206, 55);

  y = 65;


  // INFORMACIÓN DEL CLIENTE
  doc.setFontSize(14);
  doc.text("Datos del Cliente", 12, y);
  doc.setLineWidth(0.4);
  doc.line(12, y + 2, 205, y + 2);
  y += 10;

  doc.setFontSize(11);
  doc.text(`Cliente: ${v.usuario_nombre}`, 12, y); y += 6;
  doc.text(`Correo: ${v.email}`, 12, y); y += 6;

  y += 4;
  doc.setDrawColor(200);
  doc.line(10, y, 206, y);
  y += 8;
  // DATOS DE FACTURA 

  doc.setFontSize(14);
  doc.setTextColor(40, 62, 81);
  doc.text("Datos de la Factura", 12, y);
  doc.setLineWidth(0.4);
  doc.line(12, y + 2, 205, y + 2);
  y += 10;

  doc.setFontSize(11);
  doc.setTextColor(0, 0, 0);
  doc.text(`Factura ID: ${v.id}`, 12, y); y += 6;
  doc.text(`Fecha: ${v.fecha}`, 12, y); y += 6;

  y += 4;
  doc.line(10, y, 206, y);
  y += 10;

  //TABLA DE PRODUCTOS
  doc.setFontSize(14);
  doc.text("Productos", 12, y);
  y += 6;

  // ENCABEZADO
  doc.setFillColor(230, 230, 230);
  doc.rect(10, y, 196, 10, "F");

  doc.setFontSize(11);
  doc.setFont(undefined, "bold");
  doc.text("Producto", 15, y + 7);
  doc.text("Cantidad", 110, y + 7);
  doc.text("Precio", 160, y + 7);

  y += 14;

  doc.setFont(undefined, "normal");

  v.items.forEach((item, idx) => {

    if (idx % 2 === 0) {
      doc.setFillColor(247, 247, 247);
      doc.rect(10, y - 6, 196, 10, "F");
    }

    doc.text(`Producto ${item.producto_id}`, 15, y);
    doc.text(String(item.cantidad), 115, y);
    doc.text(`$${item.precio_unitario}`, 160, y);

    y += 10;

    if (y > 250) {
      doc.addPage();
      y = 20;
    }
  });

  y += 4;
  doc.line(10, y, 206, y);
  y += 10;


  doc.setFontSize(18);
  doc.setFont(undefined, "bold");
  doc.setTextColor(40, 62, 81);
  doc.text(`TOTAL: $${v.total}`, 12, y);
  doc.setTextColor(0, 0, 0);
  doc.setFont(undefined, "normal");

  doc.setFontSize(9);
  doc.setTextColor(120);
  doc.text("Documento generado automáticamente por el sistema de facturación.", 105, 270, { align: "center" });

  // Guardar
  doc.save(`factura_${v.id}.pdf`);
};

//inicializar
cargarProductos();
verificarWallet();

