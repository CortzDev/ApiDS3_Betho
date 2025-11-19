document.addEventListener('DOMContentLoaded',()=>{
  const validarBtn=document.getElementById('validarBtn');
  const logoutBtn=document.getElementById('logoutBtn');
  const msgEl=document.getElementById('msg');
  const tablaBody=document.querySelector('#tablaCadena tbody');

  // Elementos del modal
  const modal = new bootstrap.Modal(document.getElementById('modalBloque'));
  const detalleId = document.getElementById('detalleId');
  const detalleNonce = document.getElementById('detalleNonce');
  const detallePrevHash = document.getElementById('detallePrevHash');
  const detalleHash = document.getElementById('detalleHash');
  const detalleValido = document.getElementById('detalleValido');


  const token = localStorage.getItem("token");
const payload = JSON.parse(atob(token.split(".")[1]));




if (payload.rol !== "admin") {
  alert("No tienes permiso");
  window.location.href = "login.html";
}



// Referencias
const nombreUsuario = document.getElementById("nombreUsuario");
const btnRoles = document.getElementById("btnRoles");
const btnLogout = document.getElementById("btnLogout");

// Validar token y rol
async function validarAdmin() {
  try {
    const res = await fetch("/api/perfil", {
      headers: { "Authorization": "Bearer " + token }
    });
    const data = await res.json();
    if (!data.ok || data.usuario.rol !== "admin") {
      alert("No tienes permisos de administrador");
      localStorage.removeItem("token");
      window.location.href = "/login.html";
      return;
    }
    nombreUsuario.textContent = data.usuario.nombre;
  } catch (err) {
    console.error(err);
    alert("Error al validar sesión");
    window.location.href = "/login.html";
  }
}

// Botón roles
btnRoles.addEventListener("click", () => {
  window.location.href = "./public/roles.html";
});

// Botón logout
btnLogout.addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "/login.html";
});

validarAdmin();





  async function cargarCadena(){
    try{
      const res=await fetch('/bloques',{credentials:'include'});
      const data=await res.json();
      tablaBody.innerHTML='';
      if(data.ok){
        data.bloques.forEach(b=>{
          const tr=document.createElement('tr');
          tr.innerHTML=`<td>${b.block_id}</td><td>${b.nonce}</td><td>${b.previous_hash}</td><td>${b.hash}</td><td>${b.valido}</td>`;
          tr.addEventListener('click',()=> mostrarModal(b)); // clic abre modal
          tablaBody.appendChild(tr);
        });
      }
    }catch(err){ msgEl.className='text-danger'; msgEl.innerText='Error al cargar bloques'; }
  }

  function mostrarModal(bloque){
    detalleId.textContent = bloque.block_id;
    detalleNonce.textContent = bloque.nonce;
    detallePrevHash.textContent = bloque.previous_hash;
    detalleHash.textContent = bloque.hash;
    detalleValido.textContent = bloque.valido;
    modal.show();
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
