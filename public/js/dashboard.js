document.addEventListener('DOMContentLoaded', () => {
  const tabla = document.getElementById('tabla');
  const jsonBtn = document.getElementById('jsonBtn');
  const pdfBtn = document.getElementById('pdfBtn');
  const validateBtn = document.getElementById('validateBtn');
  const logoutBtn = document.getElementById('logoutBtn');

  const authHeaders = ()=>({ 'Authorization':'Bearer '+localStorage.getItem('token'),'Content-Type':'application/json' });

  const cargar = async ()=>{
    const res = await fetch('/cadena',{ headers: authHeaders() });
    if(res.status===401){ alert('Sesión inválida'); localStorage.clear(); location.href='/'; return; }
    const data = await res.json();
    tabla.innerHTML='';
    data.forEach(b=>{
      const row = document.createElement('tr');
      row.innerHTML=`
        <td>${b.block_id}</td>
        <td>${b.nonce}</td>
        <td>${b.hash}</td>
        <td>${b.previous_hash}</td>
        <td>${b.valido?'<span class="text-success">Válido</span>':'<span class="text-danger">Alterado</span>'}</td>
      `;
      tabla.appendChild(row);
    });
  };
  cargar();

  jsonBtn.addEventListener('click', async ()=>{
    const res = await fetch('/reporte-json',{ headers: authHeaders() });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download='blockchain.json'; a.click();
  });

  pdfBtn.addEventListener('click', async ()=>{
    const res = await fetch('/reporte-pdf',{ headers: authHeaders() });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download='blockchain.pdf'; a.click();
  });

  validateBtn.addEventListener('click', async ()=>{
    const res = await fetch('/validar',{ headers: authHeaders() });
    const j = await res.json();
    alert(j.ok? j.message : j.error);
  });

  logoutBtn.addEventListener('click', async ()=>{
    await fetch('/logout',{ method:'POST', headers: authHeaders() });
    localStorage.clear();
    location.href='/';
  });
});
