document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btnVerify").addEventListener("click", verify);
});

async function verify() {
  const email = sessionStorage.getItem("verify_email");
  const code = document.getElementById("otp").value;

  const r = await fetch("/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, otp: code })
  });

  const data = await r.json();

  if (!data.ok) return msg.textContent = data.error;

  location.href = "login.html";
}
