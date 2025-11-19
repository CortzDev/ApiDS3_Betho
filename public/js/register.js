document.getElementById("formRegistro").addEventListener("submit", async (e) => {
    e.preventDefault();

    const nombre = document.getElementById("nombre").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const rol_id = document.getElementById("rol").value;

    const res = await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nombre, email, password, rol_id })
    });

    const data = await res.json();

    const msg = document.getElementById("msg");

    if (data.ok) {
        msg.innerHTML = "Registro exitoso. Redirigiendo...";
        msg.style.color = "green";

        setTimeout(() => {
            window.location.href = "login.html";
        }, 1500);

    } else {
        msg.innerHTML = data.error || "Error al registrar";
        msg.style.color = "red";
    }
});
