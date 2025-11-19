const form = document.getElementById("formLogin");
const msg = document.getElementById("msg");
const btnRegister = document.getElementById("btnRegister");

// ➤ Redirigir a registro desde el botón
btnRegister.addEventListener("click", () => {
  window.location.href = "register.html";
});

form.addEventListener("submit", async e => {
  e.preventDefault();

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!email || !password) {
    msg.innerText = "Ingrese email y contraseña";
    msg.className = "text-danger";
    return;
  }

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (data.ok) {
      // Guardar token y rol
      localStorage.setItem("token", data.token);
      localStorage.setItem("rol", data.usuario.rol);

      // Redirigir según rol
      if (data.usuario.rol === "proveedor") {
        window.location.href = "/proveedor/dashboard";
      } else if (data.usuario.rol === "admin") {
        window.location.href = "/dashboard";
      } else {
        msg.innerText = "Rol no permitido";
        msg.className = "text-danger";
      }
    } else {
      msg.innerText = "Usuario o contraseña incorrectos";
      msg.className = "text-danger";
    }
  } catch (err) {
    console.error(err);
    msg.innerText = "Error de conexión";
    msg.className = "text-danger";
  }
});
