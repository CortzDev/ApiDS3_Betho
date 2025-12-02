document.addEventListener("DOMContentLoaded", () => {

    const form = document.getElementById("formRegister");
    const msg = document.getElementById("msg");

    // Detectar entorno automáticamente
    const API_BASE = window.location.hostname.includes("localhost")
        ? "http://localhost:3000"
        : "https://apids3betho-production.up.railway.app";

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const data = {
            nombre: document.getElementById("nombre").value.trim(),
            email: document.getElementById("email").value.trim(),
            password: document.getElementById("password").value.trim(),
            rol: document.getElementById("rol").value.trim()
        };

        msg.innerHTML = "";

        try {
            const res = await fetch(`${API_BASE}/api/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            });

            let json = await res.json();

            if (!res.ok || !json.ok) {
                msg.innerHTML = `
                    <div class="alert alert-danger">
                        ${json.error || json.message || "Error en el registro"}
                    </div>`;
                return;
            }

            msg.innerHTML = `
                <div class="alert alert-success">
                    ${json.message || "Usuario registrado correctamente"}
                </div>`;

            form.reset();

        } catch (err) {
            console.error("Fetch error:", err);
            msg.innerHTML = `
                <div class="alert alert-danger">
                    No se pudo conectar con el servidor.
                </div>`;
        }
    });

});
