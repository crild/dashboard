addEventListener("fetch", function(event) {
  event.respondWith(handleRequest(event.request));
});

var ALLOWED = [
  "https://query1.finance.yahoo.com/",
  "https://query2.finance.yahoo.com/",
  "https://www.nrk.no/",
  "https://feeds.bbci.co.uk/",
  "https://www.theverge.com/",
  "https://feeds.arstechnica.com/",
  "https://query1.finance.yahoo.com/v1/finance/search",
  "https://query2.finance.yahoo.com/v1/finance/search",
  "https://ws.geonorge.no/",
  "https://news.google.com/"
];

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}
  });
}

function dashboardSecret() {
  return typeof DASHBOARD_TOKEN !== "undefined" ? DASHBOARD_TOKEN : "";
}

// Compare without leaking a per-character timing signal.
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Header-only, and fails CLOSED: with no DASHBOARD_TOKEN configured every
// protected route is refused rather than served wide open. 503 rather than 401
// when the secret is missing, so a misconfigured Worker is distinguishable
// from a bad token.
// Returns null when the request may proceed, otherwise the Response to send.
function requireDashboardToken(request) {
  var expected = dashboardSecret();
  if (!expected) return jsonResponse({error: "Server auth not configured"}, 503);
  if (!safeEqual(request.headers.get("X-Dashboard-Token") || "", expected)) {
    return jsonResponse({error: "Unauthorized"}, 401);
  }
  return null;
}

// The OAuth start URLs are top-level navigations, so they cannot carry a
// request header. They use a single-use ticket instead, which keeps the
// long-lived token out of URLs, Referer headers and request logs.
async function issueAuthTicket() {
  var bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  var ticket = "";
  for (var i = 0; i < bytes.length; i++) ticket += ("0" + bytes[i].toString(16)).slice(-2);
  await KV.put("authticket_" + ticket, "1", {expirationTtl: 120});
  return ticket;
}

async function consumeAuthTicket(url) {
  var ticket = url.searchParams.get("ticket") || "";
  if (!/^[0-9a-f]{48}$/.test(ticket)) return false;
  if (!(await KV.get("authticket_" + ticket))) return false;
  await KV.delete("authticket_" + ticket);
  return true;
}

async function handleRequest(request) {
  var url = new URL(request.url);
  var path = url.pathname;

  // Handle CORS preflight first (before any auth check)
  if (request.method === "OPTIONS") {
    return new Response(null, {headers: {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,X-Dashboard-Token"}});
  }

  // Protected endpoints. /callback/* is deliberately exempt: it is redirected
  // to by the OAuth provider, not called by the dashboard.
  if (path.startsWith("/auth/")) {
    if (path === "/auth/ticket") {
      var ticketDenied = requireDashboardToken(request);
      if (ticketDenied) return ticketDenied;
      return jsonResponse({ticket: await issueAuthTicket(), expires_in: 120});
    }
    if (path === "/auth/netatmo" || path === "/auth/hue") {
      if (!dashboardSecret()) {
        return new Response("Server auth not configured.", {status: 503});
      }
      if (!(await consumeAuthTicket(url))) {
        return new Response("Invalid or expired authorization ticket. Start authorization from the dashboard.", {status: 401});
      }
    } else {
      var authDenied = requireDashboardToken(request);
      if (authDenied) return authDenied;
    }
  } else if (path.startsWith("/netatmo") || path.startsWith("/hue") ||
             path.startsWith("/index/") || path.startsWith("/session")) {
    var denied = requireDashboardToken(request);
    if (denied) return denied;
  }

  // Tier 2: the money. Needs the token AND an approved home network, so a
  // leaked token on its own is not enough to read net worth or savings goals.
  if (path.startsWith("/private/") || path.startsWith("/brief/")) {
    var homeDenied = await requireHomeNetwork(request);
    if (homeDenied) return homeDenied;
  }

  // What is this browser allowed to see? Drives which widgets render.
  if (path === "/session") {
    var sessionIp = clientIp(request);
    var nets = await homeNetworks();
    return jsonResponse({
      token: true,
      home: nets.length > 0 && ipInList(sessionIp, nets),
      ip: sessionIp,
      configured: nets.length > 0
    });
  }

  // Managing the allowlist is itself tier 2: you can only add a network while
  // already on a trusted one. HOME_NETWORKS bootstraps the first entry.
  if (path === "/private/home-networks") {
    if (request.method === "POST") {
      var body = await request.json().catch(function() { return {}; });
      var entry = body.cidr || defaultCidrFor(clientIp(request));
      if (!entry || !parseIp(entry.split("/")[0])) {
        return jsonResponse({error: "Not a usable network"}, 400);
      }
      var stored = await kvHomeNetworks();
      if (stored.indexOf(entry) < 0) stored.push(entry);
      await KV.put("home_networks", stored.join(","));
      return jsonResponse({networks: stored, added: entry});
    }
    if (request.method === "DELETE") {
      var toDrop = url.searchParams.get("cidr") || "";
      var kept = (await kvHomeNetworks()).filter(function(n) { return n !== toDrop; });
      await KV.put("home_networks", kept.join(","));
      return jsonResponse({networks: kept, removed: toDrop});
    }
    return jsonResponse({
      networks: await kvHomeNetworks(),
      bootstrap: configuredHomeNetworks(),
      current: clientIp(request)
    });
  }

  if (path === "/auth/netatmo") {
    var clientId = typeof NETATMO_CLIENT_ID !== "undefined" ? NETATMO_CLIENT_ID : "";
    var redirect = url.origin + "/callback/netatmo";
    var authUrl = "https://api.netatmo.com/oauth2/authorize?client_id=" + clientId + "&redirect_uri=" + encodeURIComponent(redirect) + "&scope=read_station&state=dashboard";
    return Response.redirect(authUrl, 302);
  }

  if (path === "/callback/netatmo") {
    var code = url.searchParams.get("code");
    if (!code) {
      return new Response("Missing code", {status: 400});
    }
    var clientId = typeof NETATMO_CLIENT_ID !== "undefined" ? NETATMO_CLIENT_ID : "";
    var clientSecret = typeof NETATMO_CLIENT_SECRET !== "undefined" ? NETATMO_CLIENT_SECRET : "";
    var redirect = url.origin + "/callback/netatmo";
    var body = "grant_type=authorization_code&client_id=" + clientId + "&client_secret=" + clientSecret + "&code=" + code + "&redirect_uri=" + encodeURIComponent(redirect) + "&scope=read_station";
    var resp = await fetch("https://api.netatmo.com/oauth2/token", {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: body
    });
    var data = await resp.json();
    if (data.access_token) {
      await KV.put("netatmo_access_token", data.access_token);
      await KV.put("netatmo_refresh_token", data.refresh_token);
      await KV.put("netatmo_expires", String(Date.now() + data.expires_in * 1000));
      return new Response("Netatmo authorized successfully! You can close this tab.", {headers: {"Content-Type": "text/plain"}});
    }
    return new Response("Auth failed: " + JSON.stringify(data), {status: 400});
  }

  if (path === "/netatmo/measure") {
    var token = await getNetatmoToken();
    if (!token) {
      return new Response(JSON.stringify({error: "Not authorized."}), {status: 401, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    var deviceId = url.searchParams.get("device_id");
    var moduleId = url.searchParams.get("module_id");
    var measType = url.searchParams.get("type") || "CO2";
    var dateBegin = url.searchParams.get("date_begin") || String(Math.floor(Date.now() / 1000) - 86400);
    var measureUrl = "https://api.netatmo.com/api/getmeasure?device_id=" + encodeURIComponent(deviceId) + "&type=" + encodeURIComponent(measType) + "&scale=30min&date_begin=" + dateBegin + "&optimize=false";
    if (moduleId) measureUrl += "&module_id=" + encodeURIComponent(moduleId);
    var resp = await fetch(measureUrl, {
      headers: {"Authorization": "Bearer " + token}
    });
    var body = await resp.text();
    return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  if (path === "/netatmo/data") {
    var token = await getNetatmoToken();
    if (!token) {
      return new Response(JSON.stringify({error: "Not authorized. Visit /auth/netatmo first."}), {status: 401, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    var resp = await fetch("https://api.netatmo.com/api/getstationsdata", {
      headers: {"Authorization": "Bearer " + token}
    });
    var body = await resp.text();
    return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  if (path === "/auth/hue") {
    var hueClientId = typeof HUE_CLIENT_ID !== "undefined" ? HUE_CLIENT_ID : "";
    var hueAppId = typeof HUE_APP_ID !== "undefined" ? HUE_APP_ID : "";
    var redirect = url.origin + "/callback/hue";
    var authUrl = "https://api.meethue.com/v2/oauth2/authorize?client_id=" + hueClientId + "&response_type=code&state=dashboard&deviceid=" + hueAppId + "&devicename=Dashboard";
    return Response.redirect(authUrl, 302);
  }

  if (path === "/callback/hue") {
    var code = url.searchParams.get("code");
    if (!code) {
      return new Response("Missing code", {status: 400});
    }
    var hueClientId = typeof HUE_CLIENT_ID !== "undefined" ? HUE_CLIENT_ID : "";
    var hueClientSecret = typeof HUE_CLIENT_SECRET !== "undefined" ? HUE_CLIENT_SECRET : "";
    var authHeader = "Basic " + btoa(hueClientId + ":" + hueClientSecret);
    var resp = await fetch("https://api.meethue.com/v2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": authHeader
      },
      body: "grant_type=authorization_code&code=" + code
    });
    var data = await resp.json();
    if (data.access_token) {
      await KV.put("hue_access_token", data.access_token);
      await KV.put("hue_refresh_token", data.refresh_token);
      await KV.put("hue_expires", String(Date.now() + (data.access_token_expires_in || 604800) * 1000));
      // Link the remote API to the bridge by pressing the link button remotely
      await fetch("https://api.meethue.com/route/api/0/config", {
        method: "PUT",
        headers: {
          "Authorization": "Bearer " + data.access_token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({linkbutton: true})
      });
      // Create a whitelist entry
      var whitelistResp = await fetch("https://api.meethue.com/route/api", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + data.access_token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({devicetype: "dashboard#browser"})
      });
      var wlData = await whitelistResp.json();
      if (wlData[0] && wlData[0].success) {
        await KV.put("hue_username", wlData[0].success.username);
      }
      return new Response("Hue authorized successfully! You can close this tab.", {headers: {"Content-Type": "text/plain"}});
    }
    return new Response("Hue auth failed: " + JSON.stringify(data), {status: 400});
  }

  if (path === "/hue/lights") {
    var token = await getHueToken();
    if (!token) {
      return new Response(JSON.stringify({error: "Not authorized. Visit /auth/hue first."}), {status: 401, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    var username = await KV.get("hue_username");
    var resp = await fetch("https://api.meethue.com/route/api/" + (username || "0") + "/lights", {
      headers: {"Authorization": "Bearer " + token}
    });
    var body = await resp.text();
    return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  if (path === "/hue/groups") {
    var token = await getHueToken();
    if (!token) {
      return new Response(JSON.stringify({error: "Not authorized. Visit /auth/hue first."}), {status: 401, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    var username = await KV.get("hue_username");
    var resp = await fetch("https://api.meethue.com/route/api/" + (username || "0") + "/groups", {
      headers: {"Authorization": "Bearer " + token}
    });
    var body = await resp.text();
    return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  if (path === "/hue/toggle" && request.method === "POST") {
    var token = await getHueToken();
    if (!token) {
      return new Response(JSON.stringify({error: "Not authorized."}), {status: 401, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    var username = await KV.get("hue_username");
    var reqBody = await request.json();
    var groupId = reqBody.group;
    var on = reqBody.on;
    var resp = await fetch("https://api.meethue.com/route/api/" + (username || "0") + "/groups/" + groupId + "/action", {
      method: "PUT",
      headers: {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({on: on})
    });
    var body = await resp.text();
    return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  if (path === "/hue/scenes") {
    var token = await getHueToken();
    if (!token) {
      return new Response(JSON.stringify({error: "Not authorized."}), {status: 401, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    var username = await KV.get("hue_username");
    var resp = await fetch("https://api.meethue.com/route/api/" + (username || "0") + "/scenes", {
      headers: {"Authorization": "Bearer " + token}
    });
    var body = await resp.text();
    return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  if (path === "/hue/scene" && request.method === "POST") {
    var token = await getHueToken();
    if (!token) {
      return new Response(JSON.stringify({error: "Not authorized."}), {status: 401, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    var username = await KV.get("hue_username");
    var reqBody = await request.json();
    var sceneId = reqBody.scene;
    var groupId = reqBody.group || "0";
    var resp = await fetch("https://api.meethue.com/route/api/" + (username || "0") + "/groups/" + groupId + "/action", {
      method: "PUT",
      headers: {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({scene: sceneId})
    });
    var body = await resp.text();
    return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  if (path === "/waste/calendar") {
    var kommunenr = url.searchParams.get("kommunenr") || "0301";
    var gatekode = url.searchParams.get("gatekode");
    var gatenavn = url.searchParams.get("gatenavn") || "";
    var husnr = url.searchParams.get("husnr") || "1";
    if (!gatekode) {
      return new Response(JSON.stringify({error: "Missing gatekode"}), {status: 400, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }

    // Oslo has its own API
    if (kommunenr === "0301" || kommunenr === "301") {
      var osloUrl = "https://www.oslo.kommune.no/xmlhttprequest.php?service=ren.search&street=" + encodeURIComponent(gatenavn) + "&number=" + encodeURIComponent(husnr) + "&street_id=" + encodeURIComponent(gatekode);
      var resp = await fetch(osloUrl, {
        headers: {"User-Agent": "Mozilla/5.0"}
      });
      var body = await resp.text();
      return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }

    // All other municipalities: Norkart Min Renovasjon
    var today = new Date();
    var fraDato = today.toISOString().split("T")[0];
    var endDate = new Date(today);
    endDate.setMonth(endDate.getMonth() + 6);
    var dato = endDate.toISOString().split("T")[0];
    var calUrl = "https://norkartrenovasjon.azurewebsites.net/proxyserver.ashx?server=" +
      encodeURIComponent("https://komteksky.norkart.no/MinRenovasjon.Api/api/tommekalender/?gatenavn=" + gatenavn + "&gatekode=" + gatekode + "&husnr=" + husnr + "&fraDato=" + fraDato + "&dato=" + dato + "&api-version=2");
    var resp = await fetch(calUrl, {
      headers: {
        "RenovasjonAppKey": "AE13DEEC-804F-4615-A74E-B4FAC11F0A30",
        "Kommunenr": kommunenr
      }
    });
    var body = await resp.text();
    return new Response(body, {status: resp.status, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  if (path.startsWith("/index/")) {
    var indexName = decodeURIComponent(path.slice("/index/".length));

    // Catalogue, so the dashboard can offer whatever the Worker knows about
    // without a frontend change.
    if (indexName === "_list") {
      return jsonResponse({indexes: Object.keys(INDEX_SOURCES).map(function(k) {
        var s = INDEX_SOURCES[k];
        return {
          name: k, label: s.label, emoji: s.emoji || "", unit: s.unit || "",
          scale: s.scale || null, ttl: s.ttl, unverified: !!s.unverified
        };
      })});
    }

    var source = INDEX_SOURCES[indexName];
    if (!source) return jsonResponse({error: "Unknown index", name: indexName}, 404);
    return await serveIndex(indexName, source, url.searchParams.get("force") === "1");
  }

  if (path === "/config/save" && request.method === "POST") {
    try {
      var configData = await request.text();
      var parsed = JSON.parse(configData);
      var code = generateCode();
      await KV.put("config_" + code, configData, {expirationTtl: 31536000});
      return new Response(JSON.stringify({code: code}), {headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    } catch (err) {
      return new Response(JSON.stringify({error: "Invalid config"}), {status: 400, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
  }

  if (path === "/config/load") {
    var code = url.searchParams.get("code");
    if (!code) {
      return new Response(JSON.stringify({error: "Missing code"}), {status: 400, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    var configData = await KV.get("config_" + code);
    if (!configData) {
      return new Response(JSON.stringify({error: "Config not found"}), {status: 404, headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
    }
    return new Response(configData, {headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}});
  }

  var target = url.searchParams.get("url");
  if (!target) {
    return new Response("Missing url parameter", {status: 400, headers: {"Access-Control-Allow-Origin": "*"}});
  }

  var allowed = false;
  for (var i = 0; i < ALLOWED.length; i++) {
    if (target.indexOf(ALLOWED[i]) === 0) { allowed = true; break; }
  }
  if (!allowed) {
    return new Response("Forbidden", {status: 403, headers: {"Access-Control-Allow-Origin": "*"}});
  }

  try {
    var resp = await fetch(target, {headers: {"User-Agent": "Mozilla/5.0"}});
    var body = await resp.text();
    var ct = resp.headers.get("Content-Type") || "text/plain";
    return new Response(body, {status: resp.status, headers: {"Content-Type": ct, "Access-Control-Allow-Origin": "*"}});
  } catch (err) {
    return new Response(err.message, {status: 500, headers: {"Access-Control-Allow-Origin": "*"}});
  }
}

async function getNetatmoToken() {
  var token = await KV.get("netatmo_access_token");
  var expires = await KV.get("netatmo_expires");
  if (token && expires && Date.now() < Number(expires) - 60000) {
    return token;
  }
  var refresh = await KV.get("netatmo_refresh_token");
  if (!refresh) return null;
  var clientId = typeof NETATMO_CLIENT_ID !== "undefined" ? NETATMO_CLIENT_ID : "";
  var clientSecret = typeof NETATMO_CLIENT_SECRET !== "undefined" ? NETATMO_CLIENT_SECRET : "";
  var body = "grant_type=refresh_token&client_id=" + clientId + "&client_secret=" + clientSecret + "&refresh_token=" + refresh;
  var resp = await fetch("https://api.netatmo.com/oauth2/token", {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: body
  });
  var data = await resp.json();
  if (data.access_token) {
    await KV.put("netatmo_access_token", data.access_token);
    await KV.put("netatmo_refresh_token", data.refresh_token);
    await KV.put("netatmo_expires", String(Date.now() + data.expires_in * 1000));
    return data.access_token;
  }
  return null;
}

async function getHueToken() {
  var token = await KV.get("hue_access_token");
  var expires = await KV.get("hue_expires");
  if (token && expires && Date.now() < Number(expires) - 60000) {
    return token;
  }
  var refresh = await KV.get("hue_refresh_token");
  if (!refresh) return null;
  var hueClientId = typeof HUE_CLIENT_ID !== "undefined" ? HUE_CLIENT_ID : "";
  var hueClientSecret = typeof HUE_CLIENT_SECRET !== "undefined" ? HUE_CLIENT_SECRET : "";
  var authHeader = "Basic " + btoa(hueClientId + ":" + hueClientSecret);
  var resp = await fetch("https://api.meethue.com/v2/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": authHeader
    },
    body: "grant_type=refresh_token&refresh_token=" + refresh
  });
  var data = await resp.json();
  if (data.access_token) {
    await KV.put("hue_access_token", data.access_token);
    await KV.put("hue_refresh_token", data.refresh_token);
    await KV.put("hue_expires", String(Date.now() + (data.access_token_expires_in || 604800) * 1000));
    return data.access_token;
  }
  return null;
}

function generateCode() {
  var chars = "abcdefghijkmnpqrstuvwxyz23456789";
  var code = "";
  for (var i = 0; i < 8; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

// ── Vibes indexes ────────────────────────────────────────────────────────────
// Adding a source is one entry here; the dashboard reads /index/_list and needs
// no change. Fields:
//   ttl         seconds a value stays fresh in KV before refetching
//   type        json | sdmx | text-column | regex
//   pick        dot path into a JSON body, e.g. "data.0.value"
//   captionPick dot path to a short label shown under the value
//   column      whitespace-column index, for text-column sources
//   scale       [min, max] to draw a gauge bar; omit for open-ended series
//   unverified  endpoint not yet confirmed end-to-end from a Worker
var INDEX_SOURCES = {
  "crypto-fng": {
    label: "Crypto Fear & Greed",
    emoji: "₿",
    url: "https://api.alternative.me/fng/?limit=1",
    type: "json",
    pick: "data.0.value",
    captionPick: "data.0.value_classification",
    scale: [0, 100],
    decimals: 0,
    ttl: 3600
  },
  "co2": {
    label: "CO₂ Mauna Loa",
    emoji: "🌍",
    url: "https://gml.noaa.gov/webdata/ccgg/trends/co2/co2_weekly_mlo.txt",
    type: "text-column",
    column: 4,
    unit: " ppm",
    decimals: 2,
    ttl: 86400
  },
  "eurnok": {
    label: "EUR/NOK",
    emoji: "💱",
    url: "https://data.norges-bank.no/api/data/EXR/B.EUR.NOK.SP?format=sdmx-json&lastNObservations=1",
    type: "sdmx",
    decimals: 4,
    ttl: 21600
  },
  "styringsrente": {
    label: "Styringsrente",
    emoji: "🏦",
    url: "https://data.norges-bank.no/api/data/IR/B.KPRA.SD.R?format=sdmx-json&lastNObservations=1",
    type: "sdmx",
    unit: " %",
    decimals: 2,
    ttl: 86400
  },
  // Bot-protected. Parses correctly and only answers with a full browser UA
  // (a short UA gets "I'm a teapot"). Verified from a residential IP; Cloudflare
  // egress IPs are likelier to be challenged, so confirm after deploying.
  "cnn-fng": {
    label: "CNN Fear & Greed",
    emoji: "📈",
    url: "https://production.dataviz.cnn.io/index/fearandgreed/graphdata",
    type: "json",
    pick: "fear_and_greed.score",
    captionPick: "fear_and_greed.rating",
    scale: [0, 100],
    decimals: 0,
    ttl: 3600,
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    unverified: true
  },
  // HTTP-only origin — it serves no TLS at all, so https fails outright.
  // Parses correctly over http; confirm a Worker subrequest is not upgraded.
  "people-in-space": {
    label: "People in space",
    emoji: "🚀",
    url: "http://api.open-notify.org/astros.json",
    type: "json",
    pick: "number",
    decimals: 0,
    ttl: 86400,
    unverified: true
  }
};

function pickPath(obj, path) {
  var parts = String(path).split(".");
  var cur = obj;
  for (var i = 0; i < parts.length; i++) {
    if (cur === null || cur === undefined) return undefined;
    cur = cur[parts[i]];
  }
  return cur;
}

// Norges Bank SDMX-JSON: one series, take its highest-numbered observation.
function parseSdmxLatest(body) {
  var root = JSON.parse(body);
  root = root.data || root;
  var series = root.dataSets[0].series;
  var seriesKey = Object.keys(series)[0];
  var obs = series[seriesKey].observations;
  var obsKey = Object.keys(obs).sort(function(a, b) { return Number(a) - Number(b); }).pop();
  var caption = "";
  try {
    var vals = root.structure.dimensions.observation[0].values;
    caption = vals[vals.length - 1].id || "";
  } catch (e) {}
  return {value: Number(obs[obsKey][0]), caption: caption};
}

// Fixed-width text (NOAA): walk back from the end past comments and the
// -999.99 sentinel rows that mark gaps in the series.
function parseTextColumn(body, column) {
  var lines = body.split("\n");
  for (var i = lines.length - 1; i >= 0; i--) {
    var line = lines[i].trim();
    if (!line || line.charAt(0) === "#") continue;
    var cols = line.split(/\s+/);
    var value = Number(cols[column]);
    if (isFinite(value) && value > -999) {
      return {value: value, caption: cols.slice(0, 3).join("-")};
    }
  }
  return null;
}

async function fetchIndexValue(source) {
  var resp = await fetch(source.url, {
    headers: {"User-Agent": source.ua || "Mozilla/5.0 (compatible; dashboard/1.0)"}
  });
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  var body = await resp.text();

  if (source.type === "sdmx") return parseSdmxLatest(body);

  if (source.type === "text-column") {
    var row = parseTextColumn(body, source.column);
    if (!row) throw new Error("No usable row");
    return row;
  }

  if (source.type === "regex") {
    var m = body.match(new RegExp(source.regex));
    if (!m) throw new Error("Pattern did not match");
    return {value: Number(String(m[1]).replace(/,/g, "")), caption: source.caption || ""};
  }

  var data = JSON.parse(body);
  var caption = source.captionPick ? pickPath(data, source.captionPick) : "";
  return {
    value: Number(pickPath(data, source.pick)),
    caption: caption === undefined || caption === null ? "" : String(caption)
  };
}

function decorateIndex(name, source, entry, stale) {
  var decimals = source.decimals === undefined ? 2 : source.decimals;
  return {
    name: name,
    label: source.label,
    emoji: source.emoji || "",
    value: entry.value,
    display: entry.value.toFixed(decimals),
    caption: entry.caption || "",
    unit: source.unit || "",
    scale: source.scale || null,
    ts: entry.ts,
    ttl: source.ttl || 3600,
    stale: !!stale
  };
}

// Fail soft by design: a broken source returns its last known value with
// stale:true and HTTP 200, so one dead endpoint greys out a single tile
// instead of breaking the widget.
async function serveIndex(name, source, force) {
  var cacheKey = "index_" + name;
  var cached = null;
  try {
    var raw = await KV.get(cacheKey);
    if (raw) cached = JSON.parse(raw);
  } catch (e) {}

  var ttlMs = (source.ttl || 3600) * 1000;
  if (!force && cached && (Date.now() - cached.ts) < ttlMs) {
    return jsonResponse(decorateIndex(name, source, cached, false));
  }

  try {
    var parsed = await fetchIndexValue(source);
    if (!parsed || !isFinite(parsed.value)) throw new Error("No value parsed");
    var fresh = {value: parsed.value, caption: parsed.caption || "", ts: Date.now()};
    // Retained for a year: the last good value is what a grey tile falls back to.
    await KV.put(cacheKey, JSON.stringify(fresh), {expirationTtl: 31536000});
    return jsonResponse(decorateIndex(name, source, fresh, false));
  } catch (err) {
    if (cached) {
      var out = decorateIndex(name, source, cached, true);
      out.error = err.message;
      return jsonResponse(out);
    }
    return jsonResponse({
      name: name, label: source.label, emoji: source.emoji || "",
      value: null, display: "—", caption: "", unit: source.unit || "",
      scale: source.scale || null, ts: null, ttl: source.ttl || 3600,
      stale: true, error: err.message
    });
  }
}

// ── Home-network tier ────────────────────────────────────────────────────────
// Cloudflare cannot see a LAN. CF-Connecting-IP is the house's *public* IP,
// which is the practical stand-in for "on my wifi". Known limits: anyone else
// on the same broadband passes, mobile data at home does not, and the entry
// needs re-adding when the ISP rotates the lease.
function clientIp(request) {
  // Dev-only escape hatch: `wrangler dev` sets no CF-Connecting-IP. Never set
  // DEV_CLIENT_IP in production — Cloudflare always supplies the real header
  // there, and this would override it.
  if (typeof DEV_CLIENT_IP !== "undefined" && DEV_CLIENT_IP) return DEV_CLIENT_IP;
  // Only CF-Connecting-IP. X-Forwarded-For is attacker-controlled and must
  // never be trusted for an access decision.
  return request.headers.get("CF-Connecting-IP") || "";
}

function ipv4ToBytes(str) {
  var parts = str.split(".");
  if (parts.length !== 4) return null;
  var out = new Uint8Array(4);
  for (var i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    var n = Number(parts[i]);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

function ipv6ToBytes(str) {
  str = str.split("%")[0];

  // ::ffff:1.2.3.4 and friends — peel the dotted quad off the end.
  var v4 = null;
  var tail = str.match(/:((?:\d{1,3}\.){3}\d{1,3})$/);
  if (tail) {
    v4 = ipv4ToBytes(tail[1]);
    if (!v4) return null;
    str = str.slice(0, str.length - tail[1].length) + "0:0";
  }

  var halves = str.split("::");
  if (halves.length > 2) return null;
  function groups(part) {
    return part ? part.split(":").filter(function(g) { return g.length > 0; }) : [];
  }
  var head = groups(halves[0]);
  var rear = halves.length === 2 ? groups(halves[1]) : [];
  if (halves.length === 1 && head.length !== 8) return null;
  if (head.length + rear.length > 8) return null;

  var all = head.concat(new Array(8 - head.length - rear.length).fill("0"), rear);
  var out = new Uint8Array(16);
  for (var i = 0; i < 8; i++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(all[i])) return null;
    var v = parseInt(all[i], 16);
    out[i * 2] = (v >> 8) & 0xff;
    out[i * 2 + 1] = v & 0xff;
  }
  if (v4) out.set(v4, 12);
  return out;
}

// Normalises ::ffff:a.b.c.d down to plain IPv4 so a v4 rule still matches a
// v4-mapped client address.
function parseIp(str) {
  str = (str || "").trim();
  if (!str) return null;
  if (str.indexOf(":") < 0) {
    var b4 = ipv4ToBytes(str);
    return b4 ? {family: 4, bytes: b4} : null;
  }
  var b6 = ipv6ToBytes(str);
  if (!b6) return null;
  var mapped = true;
  for (var i = 0; i < 10; i++) if (b6[i] !== 0) { mapped = false; break; }
  if (mapped && b6[10] === 0xff && b6[11] === 0xff) {
    return {family: 4, bytes: b6.slice(12)};
  }
  return {family: 6, bytes: b6};
}

function ipMatches(ip, cidr) {
  var slash = cidr.lastIndexOf("/");
  var network = parseIp(slash >= 0 ? cidr.slice(0, slash) : cidr);
  var addr = parseIp(ip);
  if (!network || !addr || network.family !== addr.family) return false;

  var width = addr.bytes.length * 8;
  var bits = slash >= 0 ? Number(cidr.slice(slash + 1)) : width;
  if (!isFinite(bits) || bits < 0 || bits > width) return false;

  // A /0 rule would match every address on earth and silently disable the
  // gate, so it is never honoured in an allowlist.
  if (bits === 0) return false;

  var whole = bits >> 3;
  for (var i = 0; i < whole; i++) {
    if (addr.bytes[i] !== network.bytes[i]) return false;
  }
  var rem = bits & 7;
  if (rem) {
    var mask = (0xff << (8 - rem)) & 0xff;
    if ((addr.bytes[whole] & mask) !== (network.bytes[whole] & mask)) return false;
  }
  return true;
}

function ipInList(ip, list) {
  for (var i = 0; i < list.length; i++) {
    if (ipMatches(ip, list[i])) return true;
  }
  return false;
}

// A whole IPv4 address, but only the routed prefix of an IPv6 one: ISPs move
// clients around inside their delegation, so /56 survives a reconnect.
function defaultCidrFor(ip) {
  var parsed = parseIp(ip);
  if (!parsed) return null;
  return parsed.family === 4 ? ip + "/32" : ip + "/56";
}

function splitList(str) {
  return (str || "").split(",").map(function(x) { return x.trim(); })
                    .filter(function(x) { return x.length > 0; });
}

function configuredHomeNetworks() {
  return splitList(typeof HOME_NETWORKS !== "undefined" ? HOME_NETWORKS : "");
}

async function kvHomeNetworks() {
  return splitList(await KV.get("home_networks"));
}

// Bootstrap entries come from the HOME_NETWORKS var; anything added later
// lives in KV. Both count.
async function homeNetworks() {
  return configuredHomeNetworks().concat(await kvHomeNetworks());
}

async function requireHomeNetwork(request) {
  var denied = requireDashboardToken(request);
  if (denied) return denied;

  var nets = await homeNetworks();
  if (!nets.length) {
    return jsonResponse({error: "Home network not configured", tier: "remote"}, 503);
  }
  var ip = clientIp(request);
  if (!ip) return jsonResponse({error: "Client IP unavailable", tier: "remote"}, 503);
  if (!ipInList(ip, nets)) {
    return jsonResponse({error: "Only available on the home network", tier: "remote"}, 403);
  }
  return null;
}
