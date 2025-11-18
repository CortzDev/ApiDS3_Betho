// Auto-generated safe dashboard.js
document.addEventListener("DOMContentLoaded", () => {
  try { if (typeof protegerPagina === 'function') protegerPagina(); } catch(e){ console.warn('protegerPagina missing', e); }
  cargar();

  const mappings = {
    'btn-json': generarJSON,
    'btn-pdf': generarPDF,
    'btn-validar': validar,
    'btn-logout': cerrarSesionReal,
    'closeModalBtn': cerrarModal
  };

  Object.keys(mappings).forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', mappings[id]);
  });
});

function authHeaders() {
  const t = localStorage.getItem('token');
  return { 'Authorization': 'Bearer ' + t, 'Content-Type': 'application/json' };
}

async function cargar(){
  try {
    const res = await fetch('/cadena', { headers: authHeaders() });
    if (res.status === 403) { alert('Sesión inválida o no verificada'); localStorage.clear(); location.href='/'; return; }
    const data = await res.json();
    const tbody = document.getElementById('tabla'); if(!tbody) return;
    tbody.innerHTML = '';
    data.forEach(b=>{
      const row = document.createElement('tr');
      row.className = 'border-b hover:bg-gray-50 cursor-pointer';
      row.addEventListener('click', ()=> mostrarModal(b));
      row.innerHTML = `
        <td class="p-2">${b.block_id}</td>
        <td class="p-2">${b.nonce}</td>
        <td class="p-2">${b.hash}</td>
        <td class="p-2">${b.previous_hash}</td>
        <td class="p-2">${b.valido?'<span class="text-green-600 font-semibold">Válido</span>':'<span class="text-red-600 font-semibold">Alterado</span>'}</td>
      `;
      tbody.appendChild(row);
    });
  } catch(e){ console.error('Error cargando cadena', e); }
}

async function validar(){
  try {
    const res = await fetch('/validar', { headers: authHeaders() });
    const j = await res.json();
    alert(j.ok ? j.message : 'Problema: ' + j.error);
  } catch(e){ console.error(e); alert('Error validando'); }
}

function mostrarModal(b){
  const modal = document.getElementById('blockModal');
  if(!modal) return;
  document.getElementById('modalContent').innerText = JSON.stringify(b,null,2);
  modal.classList.remove('hidden');
}
function cerrarModal(){ const modal = document.getElementById('blockModal'); if(modal) modal.classList.add('hidden'); }

function generarJSON(){
  fetch('/reporte-json', { headers: authHeaders() }).then(r=>r.blob()).then(blob=>{
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download='blockchain.json'; a.click();
  }).catch(e=>console.error(e));
}

function generarPDF(){
  fetch('/reporte-pdf', { headers: authHeaders() }).then(r=>r.blob()).then(blob=>{
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download='blockchain.pdf'; a.click();
  }).catch(e=>console.error(e));
}

function cerrarSesionReal(){
  localStorage.clear();
  location.href = '/';
}
