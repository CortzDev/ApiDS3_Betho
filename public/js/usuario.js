// usuario.js (reemplaza tu script de cliente con este)

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
const keyFileInput = document.getElementById("keyFile"); // <input type="file" id="keyFile">

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

// ================= UTIL: leer archivo como texto =================
function leerArchivoComoTexto(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Error leyendo el archivo de llave"));
    reader.onload = () => resolve(reader.result);
    reader.readAsText(file);
  });
}

// ================= UTIL: canonicalStringify (debe coincidir con servidor) =================
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalStringify).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

// ================= PETICIÓN DE NONCE (challenge) =================
async function pedirNonce() {
  const res = await fetch("/api/venta/nonce", {
    method: "POST",
    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || "Error al pedir nonce");
  return data.nonce;
}

// ================= REGISTRAR VENTA (firmada con PEM local) =================
btnComprar.addEventListener("click", async () => {
  if (carrito.length === 0) {
    msg.textContent = "El carrito está vacío";
    msg.className = "text-danger";
    return;
  }

  // Construir array de productos para enviar / firmar
  const productosPayload = carrito.map(item => ({
    producto_id: item.id,
    cantidad: item.cantidad,
    precio_unitario: item.precio
  }));

  // Intentamos el flujo seguro con nonce + firma
  try {
    const nonce = await pedirNonce();

    // Abrir selector de archivos para que el usuario elija su llave PEM
    keyFileInput.value = ""; // reset
    keyFileInput.click();

    // Manejo cuando el usuario selecciona la llave
    keyFileInput.onchange = async (ev) => {
      const files = ev.target.files;
      if (!files || files.length === 0) {
        msg.textContent = "No se seleccionó ninguna llave";
        msg.className = "text-danger";
        return;
      }

      const file = files[0];
      try {
        const pem = await leerArchivoComoTexto(file);

        // Confirmación breve al usuario
        const confirmMsg = `Has seleccionado: ${file.name}\nTamaño: ${file.size} bytes\n\n` +
                           `Se usará esta llave localmente para firmar la venta. La llave privada NO será enviada al servidor.\n\n¿Continuar?`;

        if (!confirm(confirmMsg)) {
          msg.textContent = "Operación cancelada por el usuario";
          msg.className = "text-warning";
          return;
        }

        // Construir objeto venta exactamente como el servidor espera
        const venta = {
          productos: productosPayload,
          total: parseFloat(totalSpan.textContent) || 0
        };

        const messageObj = { venta, nonce };
        const message = canonicalStringify(messageObj);

        // Requiere forge cargado en la página
        if (typeof forge === "undefined") {
          msg.textContent = "La librería forge no está disponible. Añade el script de forge en tu HTML.";
          msg.className = "text-danger";
          return;
        }

        // Importar la clave privada (PEM RSA PKCS#1 sin passphrase)
        let privateKey;
        try {
          privateKey = forge.pki.privateKeyFromPem(pem);
        } catch (err) {
          console.error("Error importando la clave privada:", err);
          msg.textContent = "No se pudo importar la llave privada (¿formato PEM y sin passphrase?).";
          msg.className = "text-danger";
          return;
        }

        // Firmar con RSA-SHA256
        const md = forge.md.sha256.create();
        md.update(message, "utf8");
        const signatureBytes = privateKey.sign(md);
        const signatureBase64 = forge.util.encode64(signatureBytes);

        // Obtener public key PEM para enviar al servidor
        const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
        const publicPem = forge.pki.publicKeyToPem(publicKey);

        // Payload final a enviar
        const payload = {
          productos: productosPayload,
          signature: signatureBase64,
          public_key_pem: publicPem,
          key_filename: file.name,
          nonce
        };

        // Enviar al servidor
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
            msg.textContent = "Venta registrada correctamente (firma verificada).";
            msg.className = "text-success";
            carrito = [];
            actualizarCarrito();
            cargarProductos();
          } else {
            // Mostrar mensaje de error del servidor
            msg.textContent = "Error: " + (data.error || "Error desconocido");
            msg.className = "text-danger";
          }
        } catch (err) {
          console.error("Error enviando la venta:", err);
          msg.textContent = "Error de conexión al enviar la venta";
          msg.className = "text-danger";
        }

      } catch (err) {
        console.error("Error leyendo la llave:", err);
        msg.textContent = "No se pudo leer la llave privada";
        msg.className = "text-danger";
      }
    };

  } catch (err) {
    // Si no se pudo obtener nonce, opcionalmente intentar la ruta sin firma
    console.error("Error pidiendo nonce:", err);

    // opción: intentar enviar sin firma (legacy)
    // Nota: es más seguro usar la ruta firmada; si quieres forzar solo firma, elimina este fallback.
    const payloadFallback = { productos: productosPayload };
    try {
      const res = await fetch("/api/usuario/venta", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payloadFallback)
      });
      const data = await res.json();
      if (data.ok) {
        msg.textContent = "Venta registrada correctamente (ruta sin firma).";
        msg.className = "text-success";
        carrito = [];
        actualizarCarrito();
        cargarProductos();
      } else {
        msg.textContent = "Error: " + (data.error || "Error desconocido");
        msg.className = "text-danger";
      }
    } catch (err2) {
      console.error("Error en fallback sin firma:", err2);
      msg.textContent = "No se pudo completar la compra (nonce o conexión).";
      msg.className = "text-danger";
    }
  }
});

// ================= INICIALIZAR =================
cargarProductos();
