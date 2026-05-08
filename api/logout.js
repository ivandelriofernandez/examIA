export default function handler(req, res) {
  res.setHeader(
    "Set-Cookie",
    "examia_auth=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/"
  );
  res.status(200).json({ ok: true });
}
