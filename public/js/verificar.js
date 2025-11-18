document.addEventListener('DOMContentLoaded',()=>{
  const emailInput = document.getElementById('email');
  const codigoInput = document.getElementById('codigo');
  const msgEl = document.getElementById('msg');
  const verificarBtn = document.getElementById('verificarBtn');
  const reenviarBtn = document.getElementById('reenviarBtn');

  verificarBtn.addEventListener('click', async ()=>{
    const email = emailInput.value;
    const otp = codigoInput.value;

    try{
      const res = await fetch('/verify',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ email, otp })
      });
      const j = await res.json();

      if(!j.ok){
        msgEl.className='text-red-600';
        msgEl.innerText=j.error;
        return;
      }

      msgEl.className='text-green-600';
      msgEl.innerText=j.message;
      setTimeout(()=>{ location.href='/'; },1500);

    }catch(err){
      msgEl.className='text-red-600';
      msgEl.innerText='Error al verificar';
      console.error(err);
    }
  });

  reenviarBtn.addEventListener('click', async ()=>{
    const email = emailInput.value;

    try{
      const res = await fetch('/register',{ // Para pruebas: reenviar OTP se puede mapear a /register temporal
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ email, password:'test1234' })
      });
      const j = await res.json();

      if(!j.ok){
        msgEl.className='text-red-600';
        msgEl.innerText=j.error;
        return;
      }

      if(j.otp){
        msgEl.className='text-yellow-600';
        msgEl.innerText='OTP (prueba): '+j.otp;
      }else{
        msgEl.className='text-green-600';
        msgEl.innerText=j.message;
      }
    }catch(err){
      msgEl.className='text-red-600';
      msgEl.innerText='Error al reenviar OTP';
      console.error(err);
    }
  });
});
