const crypto = require("crypto");

const ENC_KEY = Buffer.from(process.env.BLOCKS_KEY, "base64");
const IV_LENGTH = 12;

function encryptJSON(obj) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const text = JSON.stringify(obj);

  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");

  const tag = cipher.getAuthTag().toString("base64");

  return { iv: iv.toString("base64"), value: encrypted, tag };
}

function decryptJSON(enc) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    ENC_KEY,
    Buffer.from(enc.iv, "base64")
  );

  decipher.setAuthTag(Buffer.from(enc.tag, "base64"));

  let decrypted = decipher.update(enc.value, "base64", "utf8");
  decrypted += decipher.final("utf8");

  return JSON.parse(decrypted);
}

module.exports = { encryptJSON, decryptJSON };
