document.addEventListener('DOMContentLoaded', () => {
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const msgEl = document.getElementById('msg');
  const registerBtn = document.getElementById('registerBtn');
  const backBtn = document.getElementById('backBtn');

  registerBtn.addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;
    try {
      const res = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type':'application/json' },
        body: JSON.stringify({ email, password })
      });
      const j = await res.json();
      if(!j.ok){ msgEl.className='text-danger'; msgEl.innerText=j.error; return; }
      msgEl.className='text-success'; 
      msgEl.innerText = 'Registro exitoso. '+(j.otp? 'OTP: '+j.otp : 'Revisa tu correo.');
      setTimeout(()=>{ location.href='/verify.html'; },1500);
    } catch(err){ msgEl.className='text-danger'; msgEl.innerText='Error al registrar'; }
  });

  backBtn.addEventListener('click', () => { location.href='/'; });
});


