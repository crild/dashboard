export default {
  async fetch(request) {
    const url = new URL(request.url);
    const target = url.searchParams.get("url");

    if (!target) {
      return new Response("Missing ?url= parameter", { status: 400 });
    }

    // Only allow Yahoo Finance requests
    if (!target.startsWith("https://query1.finance.yahoo.com/") &&
        !target.startsWith("https://query2.finance.yahoo.com/")) {
      return new Response("Forbidden", { status: 403 });
    }

    const resp = await fetch(target, {
      headers: { "User-Agent": "Mozilla/5.0" }
    });

    const body = await resp.text();
    return new Response(body, {
      status: resp.status,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }
};
