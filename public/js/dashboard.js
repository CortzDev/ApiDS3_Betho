document.addEventListener('DOMContentLoaded', ()=>{
  const tabla = document.getElementById('tabla');
  const blockModal = document.getElementById('blockModal');
  const modalContent = document.getElementById('modalContent');
  const cerrarModalBtn = document.getElementById('cerrarModalBtn');
  const jsonBtn = document.getElementById('jsonBtn');
  const pdfBtn = document.getElementById('pdfBtn');
  const validarBtn = document.getElementById('validarBtn');
  const cerrarBtn = document.getElementById('cerrarBtn');

  function authHeaders(){ return {'Authorization':'Bearer '+localStorage.getItem('token'),'Content-Type':'application/json'}; }

  async function cargar(){
    const res = await fetch('/cadena',{ headers: authHeaders() });
    if(res.status===401){ alert('Sesión inválida'); localStorage.clear(); location.href='/'; return; }
    const data = await res.json();
    tabla.innerHTML='';
    data.forEach(b=>{
      const row=document.createElement('tr');
      row.className='border-b hover:bg-gray-50 cursor-pointer';
      row.addEventListener('click',()=> mostrarModal(b));
      row.innerHTML=`
        <td class="p-2">${b.block_id}</td>
        <td class="p-2">${b.nonce}</td>
        <td class="p-2">${b.hash}</td>
        <td class="p-2">${b.previous_hash}</td>
        <td class="p-2">${b.valido?'<span class="text-green-600 font-semibold">Válido</span>':'<span class="text-red-600 font-semibold">Alterado</span>'}</td>
      `;
      tabla.appendChild(row);
    });
  }

  function mostrarModal(b){ modalContent.innerText=JSON.stringify(b,null,2); blockModal.classList.remove('hidden'); }
  cerrarModalBtn.addEventListener('click', ()=> blockModal.classList.add('hidden'));

  jsonBtn.addEventListener('click',()=>{
    fetch('/reporte-json',{ headers:authHeaders() })
      .then(r=>r.blob())
      .then(b=>{
        const url = URL.createObjectURL(b);
        const a = document.createElement('a');
        a.href=url; a.download="blockchain.json"; a.click();
      });
  });

  pdfBtn.addEventListener('click',()=>{
    fetch('/reporte-pdf',{ headers:authHeaders() })
      .then(r=>r.blob())
      .then(b=>{
        const url = URL.createObjectURL(b);
        const a = document.createElement('a');
        a.href=url; a.download="blockchain.pdf"; a.click();
      });
  });

  validarBtn.addEventListener('click', async ()=>{
    const res = await fetch('/validar',{ headers:authHeaders() });
    const j = await res.json();
    alert(j.message || j.error);
  });

  cerrarBtn.addEventListener('click', async ()=>{
    await fetch('/logout',{ method:'POST', headers:authHeaders() });
    localStorage.clear(); location.href='/';
  });

  cargar();
});
