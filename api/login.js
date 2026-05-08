const crypto = require("crypto");

function sign(secret, payload) {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function createToken(secret, username) {
  const ts = Date.now();
  const payload = `${ts}:${username}`;
  const sig = sign(secret, payload);
  return Buffer.from(`${payload}:${sig}`).toString("base64");
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end("Method not allowed");

  const { username, password } = req.body || {};

  const validUser = process.env.AUTH_USER;
  const validPass = process.env.AUTH_PASS;
  const secret = process.env.AUTH_SECRET;

  if (!validUser || !validPass || !secret) {
    return res.status(500).json({ error: "Servidor no configurado correctamente. Revisa las variables de entorno." });
  }

  const userMatch = typeof username === "string" && username.trim() === validUser;
  const passMatch = typeof password === "string" &&
    crypto.timingSafeEqual(
      Buffer.from(password),
      Buffer.from(validPass)
    );

  if (!userMatch || !passMatch) {
    return res.status(401).json({ error: "Usuario o contraseña incorrectos." });
  }

  const token = createToken(secret, username.trim());
  const maxAge = 30 * 24 * 60 * 60; // 30 days

  res.setHeader(
    "Set-Cookie",
    `examia_auth=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}; Path=/`
  );
  res.status(200).json({ ok: true });
}
