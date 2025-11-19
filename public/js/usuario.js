document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btnLogout").addEventListener("click", logout);
});

async function logout() {
  await fetch("/logout", { method: "POST" });
  location.href = "login.html";
}
