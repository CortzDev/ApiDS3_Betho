document.getElementById("formLogin").addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("emailLogin").value;
    const password = document.getElementById("passwordLogin").value;

    const res = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
    });

    const data = await res.json();
    const msg = document.getElementById("msgLogin");

    if (!data.ok) {
        msg.innerHTML = data.error;
        msg.style.color = "red";
        return;
    }

    // Guardar token
    localStorage.setItem("token", data.token);
    localStorage.setItem("rol_id", data.rol_id);

    msg.innerHTML = "Ingresando...";
    msg.style.color = "green";

    // Redirección según rol
    if (data.rol_id == 2) window.location.href = "admin.html";
    else window.location.href = "usuario.html";
});
