function authHeaders() {
  const t = localStorage.getItem('token');
  return {
    'Authorization': 'Bearer ' + t,
    'Content-Type': 'application/json'
  };
}

// Cargar cadena
async function cargar() {
  const res = await fetch('/cadena', { headers: authHeaders() });

  if (res.status === 403) {
    alert('Sesión inválida o expirada');
    localStorage.clear();
    location.href = '/';
    return;
  }

  const data = await res.json();
  const tbody = document.getElementById('tabla');
  tbody.innerHTML = '';

  data.forEach(b => {
    const row = document.createElement('tr');
    row.className = 'border-b hover:bg-gray-50 cursor-pointer';

    row.addEventListener('click', () => mostrarModal(b));

    row.innerHTML = `
      <td class="p-2">${b.block_id}</td>
      <td class="p-2">${b.nonce}</td>
      <td class="p-2">${b.hash}</td>
      <td class="p-2">${b.previous_hash}</td>
      <td class="p-2">
        ${b.valido
          ? '<span class="text-green-600 font-semibold">Válido</span>'
          : '<span class="text-red-600 font-semibold">Alterado</span>'}
      </td>
    `;

    tbody.appendChild(row);
  });
}

// Validar cadena
async function validar() {
  const res = await fetch('/validar', { headers: authHeaders() });
  const j = await res.json();
  alert(j.ok ? j.message : `Problema: ${j.error}`);
}

// Modal
function mostrarModal(b) {
  document.getElementById('modalContent').innerText =
    JSON.stringify(b, null, 2);
  document.getElementById('blockModal').classList.remove('hidden');
}

function cerrarModal() {
  document.getElementById('blockModal').classList.add('hidden');
}

// Descargar JSON
function generarJSON() {
  fetch('/reporte-json', { headers: authHeaders() })
    .then(res => res.blob())
    .then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = "blockchain.json";
      a.click();
    });
}

// Descargar PDF
function generarPDF() {
  fetch('/reporte-pdf', { headers: authHeaders() })
    .then(res => res.blob())
    .then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = "blockchain.pdf";
      a.click();
    });
}

// Cerrar sesión
function cerrarSesionReal() {
  localStorage.clear();
  location.href = '/';
}

// Eventos seguros
document.addEventListener("DOMContentLoaded", () => {
  protegerPagina();
  cargar();

  document.getElementById("btnJSON").addEventListener("click", generarJSON);
  document.getElementById("btnPDF").addEventListener("click", generarPDF);
  document.getElementById("btnValidar").addEventListener("click", validar);
  document.getElementById("btnCerrarSesion").addEventListener("click", cerrarSesionReal);
  document.getElementById("btnCerrarModal").addEventListener("click", cerrarModal);
});
