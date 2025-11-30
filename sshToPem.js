const crypto = require("crypto");

/**
 * Convierte una clave pública OpenSSH (ssh-rsa AAAAB3...) a PEM.
 * Retorna null si el formato no es OpenSSH válido.
 */
function sshToPem(sshKey) {
  sshKey = sshKey.trim();

  // Si es PEM, no convertir
  if (sshKey.includes("BEGIN PUBLIC KEY")) {
    return sshKey;
  }

  // Formato Openssh
  if (!sshKey.startsWith("ssh-rsa ")) {
    return null;
  }

  try {
    const parts = sshKey.split(" ");
    if (parts.length < 2) return null;

    const keyBuffer = Buffer.from(parts[1], "base64");

    // Importar a estructura de clave
    const rsaKey = crypto.createPublicKey({
      key: keyBuffer,
      format: "ssh"
    });

    // export PEM
    return rsaKey.export({
      type: "spki",
      format: "pem"
    }).toString();
  } catch (err) {
    console.error("Error convirtiendo SSH -> PEM:", err);
    return null;
  }
}

module.exports = { sshToPem };
