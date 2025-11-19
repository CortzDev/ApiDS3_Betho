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

        try {
            const res = await fetch("http://localhost:3000/api/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            });

            const json = await res.json();

            if (!res.ok) {
                msg.innerHTML = `<div class="alert alert-danger">${json.error || json.message}</div>`;
                return;
            }

            msg.innerHTML = `<div class="alert alert-success">${json.message}</div>`;
            form.reset();

        } catch (err) {
            msg.innerHTML = `<div class="alert alert-danger">Error del servidor</div>`;
        }
    });

});

