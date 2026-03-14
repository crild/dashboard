addEventListener("fetch", function(event) {
  event.respondWith(handleRequest(event.request));
});

// Allowed URL prefixes
var ALLOWED = [
  "https://query1.finance.yahoo.com/",
  "https://query2.finance.yahoo.com/",
  "https://www.nrk.no/",
  "https://feeds.bbci.co.uk/",
  "https://www.theverge.com/",
  "https://feeds.arstechnica.com/"
];

async function handleRequest(request) {
  var url = new URL(request.url);
  var target = url.searchParams.get("url");

  if (!target) {
    return new Response("Missing ?url= parameter", {
      status: 400,
      headers: { "Content-Type": "text/plain", "Access-Control-Allow-Origin": "*" }
    });
  }

  var allowed = false;
  for (var i = 0; i < ALLOWED.length; i++) {
    if (target.indexOf(ALLOWED[i]) === 0) {
      allowed = true;
      break;
    }
  }

  if (!allowed) {
    return new Response("Forbidden", {
      status: 403,
      headers: { "Content-Type": "text/plain", "Access-Control-Allow-Origin": "*" }
    });
  }

  try {
    var resp = await fetch(target, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      }
    });

    var body = await resp.text();
    var contentType = resp.headers.get("Content-Type") || "text/plain";

    return new Response(body, {
      status: resp.status,
      headers: {
        "Content-Type": contentType,
        "Access-Control-Allow-Origin": "*"
      }
    });
  } catch (err) {
    return new Response(err.message, {
      status: 500,
      headers: { "Content-Type": "text/plain", "Access-Control-Allow-Origin": "*" }
    });
  }
}
