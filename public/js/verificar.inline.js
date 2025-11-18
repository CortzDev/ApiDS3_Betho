async function verificar(){
  const email=document.getElementById('email').value;
  const codigo=document.getElementById('codigo').value;
  const res = await fetch('/verificar',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, codigo }) });
  const j = await res.json();
  if(!j.ok){ document.getElementById('msg').className='text-red-600'; document.getElementById('msg').innerText=j.error; return; }
  document.getElementById('msg').className='text-green-600'; document.getElementById('msg').innerText=j.message;
  setTimeout(()=>{ location.href='/'; }, 1500);
}
async function reenviar(){
  const email=document.getElementById('email').value;
  const res = await fetch('/reenviar',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email }) });
  const j = await res.json();
  if(!j.ok){ document.getElementById('msg').className='text-red-600'; document.getElementById('msg').innerText=j.error; return; }
  if (j.otp) { document.getElementById('msg').className='text-yellow-600'; document.getElementById('msg').innerText='OTP (prueba): '+j.otp; }
  else { document.getElementById('msg').className='text-green-600'; document.getElementById('msg').innerText=j.message; }
}

