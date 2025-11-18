document.addEventListener('DOMContentLoaded', () => {
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const msgEl = document.getElementById('msg');
  const registerBtn = document.getElementById('registerBtn');
  const loginBtn = document.getElementById('loginBtn');

  registerBtn.addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;
    try{
      const res = await fetch('/register',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ email,password })
      });
      const j = await res.json();
      if(!j.ok){ msgEl.className='text-danger'; msgEl.innerText=j.error; return; }
      msgEl.className='text-success';
      msgEl.innerText='Registro exitoso. Verifica tu correo';
      setTimeout(()=>{ location.href='verify.html'; }, 1000);
    }catch(err){
      msgEl.className='text-danger';
      msgEl.innerText='Error en registro';
      console.error(err);
    }
  });

  loginBtn.addEventListener('click',()=>{ location.href='login.html'; });
});


