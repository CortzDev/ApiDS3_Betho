document.addEventListener('DOMContentLoaded',()=>{
  const emailInput = document.getElementById('email');
  const passInput = document.getElementById('pass');
  const msgEl = document.getElementById('msg');
  const registerBtn = document.getElementById('registerBtn');
  const backBtn = document.getElementById('backBtn');

  backBtn.addEventListener('click',()=>{ location.href='/'; });

  registerBtn.addEventListener('click', async ()=>{
    const email = emailInput.value;
    const password = passInput.value;

    try{
      const res = await fetch('/register',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ email,password })
      });
      const j = await res.json();

      if(!j.ok){
        msgEl.className='text-red-600';
        msgEl.innerText=j.error;
        return;
      }

      msgEl.className='text-green-600';
      msgEl.innerText=j.otp? `Registro creado. OTP (prueba): ${j.otp}` : 'Registro creado. Revisa tu correo.';

      setTimeout(()=>{ location.href='/verify.html'; },1500);

    }catch(err){
      msgEl.className='text-red-600';
      msgEl.innerText='Error al registrar';
      console.error(err);
    }
  });
});

