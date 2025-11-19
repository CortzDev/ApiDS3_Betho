document.getElementById("formLogin").addEventListener("submit", async (e) => {
    e.preventDefault();

    const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            email: email.value,
            password: password.value
        })
    });

    const json = await res.json();

    if (json.ok) {
        localStorage.setItem("token", json.token);
        msg.textContent = "Login correcto";
        window.location.href = "roles.html";
    } else {
        msg.textContent = "Credenciales incorrectas";
    }
});
