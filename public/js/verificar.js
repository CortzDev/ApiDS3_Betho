document.addEventListener('DOMContentLoaded', () => {
  const emailInput = document.getElementById('email');
  const codigoInput = document.getElementById('codigo');
  const msgEl = document.getElementById('msg');
  const verifyBtn = document.getElementById('verifyBtn');
  const resendBtn = document.getElementById('resendBtn');

  verifyBtn.addEventListener('click', async () => {
    const email = emailInput.value;
    const otp = codigoInput.value;
    try {
      const res = await fetch('/verify', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ email, otp })
      });
      const j = await res.json();
      msgEl.className = j.ok?'text-success':'text-danger';
      msgEl.innerText = j.ok? j.message : j.error;
      if(j.ok) setTimeout(()=>{ location.href='/'; },1500);
    } catch(err){ msgEl.className='text-danger'; msgEl.innerText='Error al verificar'; }
  });

  resendBtn.addEventListener('click', async () => {
    const email = emailInput.value;
    try{
      const res = await fetch('/reenviar', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ email })
      });
      const j = await res.json();
      msgEl.className = j.ok?'text-success':'text-danger';
      msgEl.innerText = j.otp? 'OTP: '+j.otp : j.message;
    }catch(err){ msgEl.className='text-danger'; msgEl.innerText='Error al reenviar OTP'; }
  });
});
