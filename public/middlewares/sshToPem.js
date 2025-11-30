/**
 * Convierte una clave pública OpenSSH (ssh-rsa ...) a PEM
 * compatible con crypto.publicEncrypt
 */

const crypto = require("crypto");

function sshToPem(input) {
  try {
    if (!input || typeof input !== "string") return null;

    input = input.trim();

    // 1) Si ya es PEM, la devolvemos
    if (input.includes("-----BEGIN PUBLIC KEY-----")) {
      return input;
    }
    if (input.includes("-----BEGIN RSA PUBLIC KEY-----")) {
      return input;
    }

    // 2) Validar si empieza como clave OpenSSH
    if (!input.startsWith("ssh-rsa ")) {
      return null; // No es un formato soportado
    }

    // 3) Extraer la parte Base64
    const parts = input.split(" ");
    if (parts.length < 2) return null;

    const sshBase64 = parts[1];
    const sshBuffer = Buffer.from(sshBase64, "base64");

    // 4) Decodificar la estructura SSH RSA (RFC4253)
    let offset = 0;

    function readLength() {
      const len = sshBuffer.readUInt32BE(offset);
      offset += 4;
      return len;
    }

    function readBuffer() {
      const len = readLength();
      const buf = sshBuffer.slice(offset, offset + len);
      offset += len;
      return buf;
    }

    // Leer tipo de clave
    const type = readBuffer().toString();
    if (type !== "ssh-rsa") return null;

    // Leer exponent e y n (modulus)
    const e = readBuffer(); // exponent
    const n = readBuffer(); // modulus

    // 5) Crear JWK para pasarlo a crypto.createPublicKey
    const jwk = {
      kty: "RSA",
      n: n.toString("base64url"),
      e: e.toString("base64url"),
    };

    // 6) Convertir JWK a clave pública PEM
    const pubKey = crypto.createPublicKey({
      key: jwk,
      format: "jwk"
    });

    const pem = pubKey.export({ type: "spki", format: "pem" });

    return pem;
  } catch (err) {
    console.error("sshToPem ERROR:", err);
    return null;
  }
}

module.exports = { sshToPem };
