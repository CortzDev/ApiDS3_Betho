document.addEventListener('DOMContentLoaded', () => {
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const msgEl = document.getElementById('msg');
  const loginBtn = document.getElementById('loginBtn');
  const registerBtn = document.getElementById('registerBtn');

  loginBtn.addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;

    try {
      const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type':'application/json' },
        body: JSON.stringify({ email, password })
      });
      const j = await res.json();
      if(!j.ok){ 
        msgEl.className='text-danger'; 
        msgEl.innerText=j.error; 
        return; 
      }

      localStorage.setItem('token', j.token);
      msgEl.className='text-success';
      msgEl.innerText='Inicio de sesión exitoso';
      setTimeout(()=>{ location.href='dashboard.html'; }, 1000);
    } catch(err){
      msgEl.className='text-danger';
      msgEl.innerText='Error al iniciar sesión';
      console.error(err);
    }
  });

  registerBtn.addEventListener('click', () => {
    location.href='index.html';
  });
});
