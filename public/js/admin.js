// ============================
// EVENTOS
// ============================

document.addEventListener("DOMContentLoaded", () => {

  cargarProductos();
  cargarCategorias();
  cargarBlockchain();

  document.getElementById("btnLogout").addEventListener("click", logout);

  document.getElementById("btnGuardarProducto").addEventListener("click", crearProducto);
  document.getElementById("btnGuardarCategoria").addEventListener("click", crearCategoria);

  document.getElementById("btnRecargarBlockchain").addEventListener("click", cargarBlockchain);

});


// ============================
// FUNCIONES PRINCIPALES
// ============================

async function logout() {
  await fetch('/logout', { method: 'POST' });
  location.href = '/login.html';
}

async function cargarProductos() {
  const r = await fetch('/productos');
  const data = await r.json();

  let html = "";
  data.productos.forEach(p => {
    html += `
      <tr>
        <td>${p.id}</td>
        <td>${p.nombre}</td>
        <td>$${p.precio}</td>
        <td>${p.stock}</td>
      </tr>`;
  });

  document.getElementById("listaProductos").innerHTML = html;
}

async function cargarCategorias() {
  const r = await fetch('/categorias');
  const data = await r.json();

  let html = "";
  let opciones = "";

  data.categorias.forEach(c => {
    html += `
      <tr>
        <td>${c.id}</td>
        <td>${c.nombre}</td>
        <td>${c.descripcion}</td>
      </tr>`;

    opciones += `<option value="${c.id}">${c.nombre}</option>`;
  });

  document.getElementById("listaCategorias").innerHTML = html;
  document.getElementById("p_categoria").innerHTML = opciones;
}

async function crearProducto() {
  await fetch('/productos', {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      nombre: p_nombre.value,
      descripcion: p_desc.value,
      precio: p_precio.value,
      stock: p_stock.value,
      categoria_id: p_categoria.value
    })
  });

  location.reload();
}

async function crearCategoria() {
  await fetch('/categorias', {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      nombre: c_nombre.value,
      descripcion: c_desc.value
    })
  });

  location.reload();
}

async function cargarBlockchain() {
  const r = await fetch('/blockchain');
  const data = await r.json();

  document.getElementById("blockchain").innerText =
    JSON.stringify(data.blockchain, null, 2);
}
