const crypto = require("crypto");

function sign(secret, payload) {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function parseCookie(header, name) {
  if (!header) return null;
  for (const part of header.split(";")) {
    const [k, v] = part.trim().split("=");
    if (k === name) return v || null;
  }
  return null;
}

function verifyToken(secret, token) {
  try {
    const decoded = Buffer.from(token, "base64").toString();
    const lastColon = decoded.lastIndexOf(":");
    const payload = decoded.substring(0, lastColon);
    const sig = decoded.substring(lastColon + 1);
    const ts = parseInt(payload.split(":")[0]);
    if (isNaN(ts) || Date.now() - ts > 30 * 24 * 60 * 60 * 1000) return false;
    const expected = sign(secret, payload);
    if (sig.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
  } catch {
    return false;
  }
}

export default function handler(req, res) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return res.status(500).json({ error: "No configurado" });

  const token = parseCookie(req.headers.cookie, "examia_auth");
  if (!token || !verifyToken(secret, token)) {
    return res.status(401).json({ error: "No autenticado" });
  }
  res.status(200).json({ ok: true });
}
