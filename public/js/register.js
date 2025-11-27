document.addEventListener("DOMContentLoaded", () => {

    const form = document.getElementById("formRegister");
    const msg = document.getElementById("msg");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const data = {
            nombre: document.getElementById("nombre").value.trim(),
            email: document.getElementById("email").value.trim(),
            password: document.getElementById("password").value.trim(),
            rol: document.getElementById("rol").value.trim()
        };

        msg.innerHTML = ""; // limpiar mensaje

        try {
            // 🔥 IMPORTANTE → usar HTTP, no HTTPS
            const res = await fetch("https://localhost:3000/api/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            });

            // Si la respuesta NO ES JSON válido (causa del ERR_INVALID_HTTP_RESPONSE)
            let json;
            try {
                json = await res.json();
            } catch {
                msg.innerHTML = `
                    <div class="alert alert-danger">
                        Respuesta inválida del servidor.
                    </div>`;
                return;
            }

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

