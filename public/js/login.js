document.getElementById("btnLogin").addEventListener("click", login);
document.getElementById("btnRegister").addEventListener("click", () => {
  location.href = "/register.html";
});

async function login() {
  const email = document.getElementById("email").value;
  const pass = document.getElementById("pass").value;
  const msg = document.getElementById("msg");

  msg.textContent = "";

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email, password: pass })
    });

    const j = await res.json();

    if (!j.ok) {
      msg.textContent = j.error;
      return;
    }

    localStorage.setItem("token", j.token);
    location.href = "/dashboard.html";
  } catch (e) {
    msg.textContent = "Error de conexión";
  }
}
