const crypto = require("crypto");

const ENC_KEY = Buffer.from(process.env.BLOCKS_KEY, "base64");
const IV_LENGTH = 12;

function encryptJSON(obj) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);

  const json = JSON.stringify(obj);

  const encrypted = Buffer.concat([
    cipher.update(json, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString("base64"),
    ciphertext: encrypted.toString("base64"),
    tag: tag.toString("base64")
  };
}

function decryptJSON(enc) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    ENC_KEY,
    Buffer.from(enc.iv, "base64")
  );

  decipher.setAuthTag(Buffer.from(enc.tag, "base64"));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(enc.ciphertext, "base64")),
    decipher.final()
  ]);

  return JSON.parse(decrypted.toString("utf8"));
}

module.exports = { encryptJSON, decryptJSON };
