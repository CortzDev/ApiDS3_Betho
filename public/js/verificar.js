document.addEventListener('DOMContentLoaded', () => {
  const emailInput = document.getElementById('email');
  const codigoInput = document.getElementById('codigo');
  const msgEl = document.getElementById('msg');
  const verificarBtn = document.getElementById('verificarBtn');
  const reenviarBtn = document.getElementById('reenviarBtn');

  verificarBtn.addEventListener('click', async () => {
    const email = emailInput.value;
    const codigo = codigoInput.value;
    try {
      const res = await fetch('/verify',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ email, codigo })
      });
      const j = await res.json();
      if(!j.ok){ msgEl.className='text-danger'; msgEl.innerText=j.error; return; }
      msgEl.className='text-success';
      msgEl.innerText=j.message;
      setTimeout(()=>{ location.href='login.html'; }, 1000);
    } catch(err){
      msgEl.className='text-danger';
      msgEl.innerText='Error al verificar';
      console.error(err);
    }
  });

  reenviarBtn.addEventListener('click', async () => {
    const email = emailInput.value;
    try {
      const res = await fetch('/reenviar',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ email })
      });
      const j = await res.json();
      if(!j.ok){ msgEl.className='text-danger'; msgEl.innerText=j.error; return; }
      msgEl.className='text-success';
      msgEl.innerText=j.otp ? 'OTP (prueba): '+j.otp : j.message;
    } catch(err){
      msgEl.className='text-danger';
      msgEl.innerText='Error al reenviar OTP';
    }
  });
});
