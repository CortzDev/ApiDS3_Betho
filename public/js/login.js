const form = document.getElementById("loginForm");

form.addEventListener("submit", async e => {
  e.preventDefault();
  
  const email = form.email.value.trim();
  const password = form.password.value.trim();

  if (!email || !password) return;

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (data.ok) {
      localStorage.setItem("token", data.token);
      localStorage.setItem("rol", data.usuario.rol);

      if (data.usuario.rol === "proveedor") {
        window.location.href = "/proveedor/dashboard";
      } else if (data.usuario.rol === "admin") {
        window.location.href = "/dashboard";
      } else {
        alert("Rol no permitido");
      }
    } else {
      alert("Usuario o contraseña incorrectos");
    }
  } catch (err) {
    console.error(err);
    alert("Error de conexión");
  }
});
