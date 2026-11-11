async function hash(text) {
  const data = new TextEncoder().encode(text);
  const result = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(result)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/login" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));

      if (!env.ADMIN_PASSWORD || body.password !== env.ADMIN_PASSWORD) {
        return json({ error: "Password salah" }, 401);
      }

      const token = [...crypto.getRandomValues(new Uint8Array(32))]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

      const tokenHash = await hash(token);
      const expires = new Date(Date.now() + 86400000).toISOString();

      await env.DB.prepare(
        "INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)"
      ).bind(tokenHash, expires).run();

      return json({ success: true }, 200, {
        "Set-Cookie": `pito_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`
      });
    }

    if (path === "/api/logout" && request.method === "POST") {
      const cookie = request.headers.get("Cookie") || "";
      const token = cookie.match(/pito_session=([^;]+)/)?.[1];

      if (token) {
        await env.DB.prepare(
          "DELETE FROM admin_sessions WHERE token_hash = ?"
        ).bind(await hash(token)).run();
      }

      return json({ success: true }, 200, {
        "Set-Cookie": "pito_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
      });
    }

    if (path === "/api/stats") {
      const cookie = request.headers.get("Cookie") || "";
      const token = cookie.match(/pito_session=([^;]+)/)?.[1];

      if (!token) return json({ error: "Unauthorized" }, 401);

      const session = await env.DB.prepare(
        "SELECT expires_at FROM admin_sessions WHERE token_hash = ?"
      ).bind(await hash(token)).first();

      if (!session || Date.parse(session.expires_at) <= Date.now()) {
        return json({ error: "Session expired" }, 401);
      }

      const result = await env.DB.prepare(
        "SELECT COUNT(*) AS total FROM visits"
      ).first();

      return json({ total_visits: result.total });
    }

    if (path === "/" || path === "/index.html") {
      await env.DB.prepare(
        "INSERT INTO visits DEFAULT VALUES"
      ).run();
    }

    return env.ASSETS.fetch(request);
  }
};
