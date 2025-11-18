function back(){ location.href='/' }
async function register(){
  const email=document.getElementById('email').value;
  const pass=document.getElementById('pass').value;
  const res = await fetch('/register',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, password: pass }) });
  const j = await res.json();
  if(!j.ok){ document.getElementById('msg').className='text-red-600 mt-2'; document.getElementById('msg').innerText=j.error; return; }
  if (j.otp) {
    document.getElementById('msg').className='text-yellow-600 mt-2';
    document.getElementById('msg').innerText='Registro creado. OTP (prueba): '+j.otp;
  } else {
    document.getElementById('msg').className='text-green-600 mt-2';
    document.getElementById('msg').innerText='Registro creado. Revisa tu correo.';
  }
  setTimeout(()=>{ location.href='/verificar.html'; }, 1500);
}

