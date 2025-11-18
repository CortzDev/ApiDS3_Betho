document.addEventListener('DOMContentLoaded',()=>{
  const validarBtn=document.getElementById('validarBtn');
  const logoutBtn=document.getElementById('logoutBtn');
  const msgEl=document.getElementById('msg');
  const tablaBody=document.querySelector('#tablaCadena tbody');

  async function cargarCadena(){
    try{
      const res=await fetch('/cadena',{credentials:'include'});
      const data=await res.json();
      tablaBody.innerHTML='';
      data.forEach(b=>{
        const tr=document.createElement('tr');
        tr.innerHTML=`<td>${b.block_id}</td><td>${b.nonce}</td><td>${b.previous_hash}</td><td>${b.hash}</td><td>${b.valido}</td>`;
        tablaBody.appendChild(tr);
      });
    }catch(err){ msgEl.className='text-danger'; msgEl.innerText='Error al cargar cadena'; }
  }

  validarBtn.addEventListener('click',async()=>{
    const nonce=Math.floor(Math.random()*1000000);
    try{
      const res=await fetch('/crearBloque',{method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body:JSON.stringify({nonce})});
      const data=await res.json();
      if(!data.ok){ msgEl.className='text-danger'; msgEl.innerText=data.error; return; }
      msgEl.className='text-success'; msgEl.innerText=`Bloque creado con ID: ${data.bloque.block_id}`;
      cargarCadena();
    }catch(err){ msgEl.className='text-danger'; msgEl.innerText='Error al crear bloque'; }
  });

  logoutBtn.addEventListener('click',async()=>{
    await fetch('/logout',{method:'POST', credentials:'include'});
    location.href='login.html';
  });

  cargarCadena();
});
