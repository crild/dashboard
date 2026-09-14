addEventListener("fetch", function(event) {
  event.respondWith(handleRequest(event.request));
});

// Static baseline for the /proxy host allowlist. Deliberately an allowlist and
// not an open proxy: this Worker is public, and an open proxy is an SSRF and
// abuse vector. It can be widened at runtime through /private/proxy-hosts,
// which is tier-2 gated so only the owner, at home, can add a host.
//
// The news widget shipped with feeds whose hosts were never listed here (E24,
// VG, TechCrunch, Hacker News are all named in CLAUDE.md), so those tabs had
// never once loaded.
// The only keys a share code may carry. Financial data must never appear here:
// /config/save is unauthenticated by design, and the receiving dashboard writes
// the result into localStorage on the origin holding the owner token.
var SHAREABLE_CONFIG_KEYS = [
  "stops", "stocks", "location", "feeds", "indexes",
  "mobility", "_widgetOrder", "_theme", "_layout"
];

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
  "https://news.google.com/",
  "https://e24.no/",
  "https://www.vg.no/",
  "https://www.aftenposten.no/",
  "https://www.dn.no/",
  "https://techcrunch.com/",
  "https://news.ycombinator.com/",
  "https://hnrss.org/",
  "https://www.nrk.no/nyheter/",
  "https://api.entur.io/"
];

// Static list plus anything the owner has added from home.
async function allowedPrefixes() {
  var extra = [];
  try { extra = splitList(await KV.get("proxy_hosts")); } catch (e) {}
  return ALLOWED.concat(extra);
}

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
    return new Response(null, {headers: {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,X-Dashboard-Token", "Access-Control-Max-Age": "86400"}});
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
  } else if (path.startsWith("/hue") ||
             path.startsWith("/index/") || path.startsWith("/session")) {
    var denied = requireDashboardToken(request);
    if (denied) return denied;
  }

  // Tier 2: the money. Needs the token AND an approved home network, so a
  // leaked token on its own is not enough to read net worth or savings goals.
  // Netatmo is tier 2 alongside the money: it is a live readout of conditions
  // inside the house, and the token alone should not expose that from anywhere
  // in the world. Hue stays tier 1 deliberately — controlling lights remotely is
  // a feature, not a leak.
  if (path.startsWith("/private/") || path.startsWith("/brief/") ||
      path.startsWith("/netatmo")) {
    var homeDenied = await requireHomeNetwork(request);
    if (homeDenied) return homeDenied;
  }

  // What is this browser allowed to see? Drives which widgets render.
  if (path === "/session") {
    var sessionIp = clientIp(request);
    var nets = await homeNetworks();
    var resolvedNets = await expandNetworks(nets);
    return jsonResponse({
      token: true,
      home: resolvedNets.length > 0 && ipInList(sessionIp, resolvedNets),
      ip: sessionIp,
      configured: nets.length > 0
    });
  }

  // Managing the allowlist is itself tier 2: you can only add a network while
  // already on a trusted one. HOME_NETWORKS bootstraps the first entry.
  if (path === "/private/nw/projection") {
    return await nwProjection(request);
  }

  if (path === "/private/nw/config") {
    if (request.method === "PUT" || request.method === "POST") {
      var incoming = await request.json().catch(function () { return null; });
      if (!incoming || typeof incoming !== "object") {
        return jsonResponse({error: "Expected a config object"}, 400);
      }
      // Optimistic concurrency: KV has no compare-and-swap, so a client must
      // say which revision it edited. Two devices editing at once then collide
      // loudly instead of one silently discarding the other.
      var current = await nwLoadConfig();
      var expected = current.rev || 0;
      if (incoming.rev !== undefined && Number(incoming.rev) !== expected) {
        return jsonResponse({error: "Config changed since you loaded it", rev: expected}, 409);
      }
      incoming.rev = expected + 1;
      incoming.placeholder = false;
      incoming.updated = new Date().toISOString().slice(0, 10);
      await KV.put("nw_config", JSON.stringify(incoming));
      return jsonResponse({ok: true, rev: incoming.rev});
    }
    return jsonResponse(await nwLoadConfig());
  }

  if (path === "/private/proxy-hosts") {
    if (request.method === "POST") {
      var body = await request.json().catch(function() { return {}; });
      var prefix = String(body.prefix || "").trim();
      // Must be an https origin prefix; anything looser re-opens the proxy.
      if (!/^https:\/\/[a-z0-9.-]+\/[a-zA-Z0-9._~:\/?#\[\]@!$&'()*+,;=%-]*$/i.test(prefix)) {
        return jsonResponse({error: "Expected an https:// prefix ending in a path, e.g. https://example.com/"}, 400);
      }
      var hosts = await kvProxyHosts();
      if (hosts.indexOf(prefix) < 0) hosts.push(prefix);
      await KV.put("proxy_hosts", hosts.join(","));
      return jsonResponse({hosts: hosts, added: prefix});
    }
    if (request.method === "DELETE") {
      var drop = url.searchParams.get("prefix") || "";
      var kept = (await kvProxyHosts()).filter(function(h) { return h !== drop; });
      await KV.put("proxy_hosts", kept.join(","));
      return jsonResponse({hosts: kept, removed: drop});
    }
    return jsonResponse({hosts: await kvProxyHosts(), builtin: ALLOWED});
  }

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
    var allNets = await homeNetworks();
    return jsonResponse({
      networks: await kvHomeNetworks(),
      bootstrap: configuredHomeNetworks(),
      resolved: await expandNetworks(allNets),
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

    // Oslo has its own API. The old xmlhttprequest.php endpoint was removed by
    // the kommune and 404s for every address; this is the endpoint their own
    // renovation search now uses. It wants the house number and its letter as
    // SEPARATE parameters, and returns nothing unless all four are supplied.
    if (kommunenr === "0301" || kommunenr === "301") {
      var split = splitHouseNumber(husnr);
      var osloUrl = "https://www.oslo.kommune.no/actions/snap-lib-waste-complaint/search-by-address" +
        "?street=" + encodeURIComponent(gatenavn) +
        "&number=" + encodeURIComponent(split.number) +
        "&letter=" + encodeURIComponent(split.letter) +
        "&street_id=" + encodeURIComponent(gatekode);
      var resp = await fetch(osloUrl, {
        headers: {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
      });
      var body = await resp.text();
      if (!resp.ok) {
        return jsonResponse({error: "Oslo waste API returned " + resp.status, result: []}, 502);
      }
      var parsed;
      try {
        parsed = JSON.parse(body);
      } catch (err) {
        // The kommune serves an HTML error page on failure. Never pass that to
        // the dashboard, which would throw on res.json().
        return jsonResponse({error: "Oslo waste API did not return JSON", result: []}, 502);
      }
      // A search returns neighbouring addresses too (12B also yields 12C), so
      // narrow to the exact house before the dashboard sees it. If nothing
      // matches exactly, hand back everything rather than an empty widget.
      var all = parsed.result || [];
      var exact = all.filter(function(r) {
        return String(r.Husnummer) === String(split.number) &&
               String(r.Bokstav || "").toUpperCase() === split.letter.toUpperCase();
      });
      return jsonResponse({result: exact.length ? exact : all, matched: exact.length > 0});
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
          category: s.category || "other", scale: s.scale || null,
          ttl: s.ttl, unverified: !!s.unverified
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
      // This route is deliberately unauthenticated so a share link works for
      // anyone, which means the body is untrusted input from the open
      // internet. It used to be JSON.parsed and stored VERBATIM under a
      // guessable 8-char code, and the dashboard's ?config= loader writes
      // whatever comes back straight into localStorage on the origin that
      // holds the owner token. So the stored object is now rebuilt from an
      // explicit allowlist: anything not named here never round-trips.
      if (configData.length > 64 * 1024) {
        return jsonResponse({error: "Config too large"}, 413);
      }
      var parsed = JSON.parse(configData);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return jsonResponse({error: "Invalid config"}, 400);
      }
      var safe = {};
      for (var k = 0; k < SHAREABLE_CONFIG_KEYS.length; k++) {
        var key = SHAREABLE_CONFIG_KEYS[k];
        if (Object.prototype.hasOwnProperty.call(parsed, key)) safe[key] = parsed[key];
      }
      var dropped = Object.keys(parsed).filter(function(key) {
        return SHAREABLE_CONFIG_KEYS.indexOf(key) < 0;
      });
      var code = generateCode();
      await KV.put("config_" + code, JSON.stringify(safe), {expirationTtl: 31536000});
      return jsonResponse({code: code, dropped: dropped});
    } catch (err) {
      return jsonResponse({error: "Invalid config"}, 400);
    }
  }

  if (path === "/config/load") {
    var code = url.searchParams.get("code");
    // generateCode() uses this alphabet; anything else is someone probing.
    if (code && !/^[a-hj-np-z2-9]{8}$/.test(code)) {
      return jsonResponse({error: "Invalid code"}, 400);
    }
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

  var prefixes = await allowedPrefixes();
  var allowed = false;
  for (var i = 0; i < prefixes.length; i++) {
    if (target.indexOf(prefixes[i]) === 0) { allowed = true; break; }
  }
  if (!allowed) {
    // Say WHY. A bare "Forbidden" made an unlisted feed look like a broken one,
    // and the settings UI happily accepted hosts this would always refuse.
    var host = "";
    try { host = new URL(target).host; } catch (e) {}
    return jsonResponse({
      error: "Host not allowed by the dashboard proxy",
      host: host,
      hint: "Add it from the dashboard while on the home network."
    }, 403);
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
//   category    groups the source in the dashboard picker:
//               geopolitics | markets | planet | norge | tull
//   unverified  endpoint not yet confirmed end-to-end from a Worker
var INDEX_SOURCES = {
  "crypto-fng": {
    category: "markets",
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
    category: "planet",
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
    category: "norge",
    label: "EUR/NOK",
    emoji: "💱",
    url: "https://data.norges-bank.no/api/data/EXR/B.EUR.NOK.SP?format=sdmx-json&lastNObservations=1",
    type: "sdmx",
    decimals: 4,
    ttl: 21600
  },
  "styringsrente": {
    category: "norge",
    label: "Styringsrente",
    emoji: "🏦",
    url: "https://data.norges-bank.no/api/data/IR/B.KPRA.SD.R?format=sdmx-json&lastNObservations=1",
    type: "sdmx",
    unit: " %",
    decimals: 2,
    ttl: 86400
  },
  // Trump pressure index. Next.js server-renders the numbers into the flight
  // payload, so a loose regex beats unescaping the JSON out of the HTML.
  "salsa": {
    category: "geopolitics",
    label: "SALSA Index",
    emoji: "🌶",
    url: "https://www.salsa-index.com/",
    type: "regex",
    regex: "indexValue[^0-9]{0,4}([0-9.]+)",
    caption: "presidential pressure",
    scale: [0, 100],
    decimals: 1,
    ttl: 3600,
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"
  },
  "salsa-taco": {
    category: "geopolitics",
    label: "TACO Probability",
    emoji: "🌮",
    url: "https://www.salsa-index.com/",
    type: "regex",
    regex: "tacoProbability[^0-9]{0,4}([0-9.]+)",
    caption: "chance he blinks",
    unit: " %",
    scale: [0, 100],
    decimals: 0,
    ttl: 3600,
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"
  },
  // One JSON call carries six sub-indices; each is exposed as its own tile.
  "ai-bubble": {
    category: "markets",
    label: "AI Bubble",
    emoji: "🫧",
    url: "https://aibubblemonitor.com/api/index/current",
    type: "json",
    pick: "overall",
    captionPick: "label",
    scale: [0, 100],
    decimals: 0,
    ttl: 3600
  },
  "ai-bubble-valuation": {
    category: "markets",
    label: "AI Valuation",
    emoji: "💸",
    url: "https://aibubblemonitor.com/api/index/current",
    type: "json",
    pick: "valuation",
    scale: [0, 100],
    decimals: 0,
    ttl: 3600
  },
  "ai-bubble-systemic": {
    category: "markets",
    label: "AI Systemic Risk",
    emoji: "⚠",
    url: "https://aibubblemonitor.com/api/index/current",
    type: "json",
    pick: "systemicRisk",
    scale: [0, 100],
    decimals: 1,
    ttl: 3600
  },
  // Average tone of world coverage matching a query; more negative = grimmer.
  // The query is the point: one source becomes many trackers. GDELT rate-limits
  // to one request per 5s, which the KV cache absorbs.
  "gdelt-conflict": {
    category: "geopolitics",
    label: "World Mood: Conflict",
    emoji: "🌐",
    url: "https://api.gdeltproject.org/api/v2/doc/doc?query=(war%20OR%20conflict)&mode=timelinetone&timespan=3d&format=json",
    type: "gdelt",
    scale: [-10, 10],
    decimals: 2,
    ttl: 3600
  },
  // Bot-protected. Parses correctly and only answers with a full browser UA
  // (a short UA gets "I'm a teapot"). Verified from a residential IP; Cloudflare
  // egress IPs are likelier to be challenged, so confirm after deploying.
  "cnn-fng": {
    category: "markets",
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
    category: "planet",
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

  if (source.type === "gdelt") {
    var tl = JSON.parse(body).timeline || [];
    var series = tl.length ? tl[0].data || [] : [];
    if (!series.length) throw new Error("Empty timeline");
    var last = series[series.length - 1];
    return {value: Number(last.value), caption: String(last.date || "").slice(0, 8)};
  }

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
  // Hostnames are resolved here, so a DDNS name tracks the lease by itself.
  if (!ipInList(ip, await expandNetworks(nets))) {
    return jsonResponse({error: "Only available on the home network", tier: "remote"}, 403);
  }
  return null;
}

// ── Dynamic DNS support ──────────────────────────────────────────────────────
// A HOME_NETWORKS entry may be a hostname instead of a CIDR. The router's DDNS
// client keeps that hostname pointed at the current lease, and the Worker
// follows it, so an ISP rotation stops being something to fix by hand.
//
// Resolution goes over DNS-over-HTTPS (Workers have no DNS API) and is cached
// in KV. A lookup that fails contributes no addresses at all, so a DNS outage
// closes the gate rather than opening it.
var DNS_CACHE_TTL = 300;

function looksLikeHostname(entry) {
  if (!entry || entry.indexOf("/") >= 0) return false;
  if (parseIp(entry)) return false;
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(entry);
}

async function dohQuery(host, type) {
  var resp = await fetch(
    "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(host) + "&type=" + type,
    {headers: {"Accept": "application/dns-json"}}
  );
  if (!resp.ok) throw new Error("DoH HTTP " + resp.status);
  var data = await resp.json();
  var answers = data.Answer || [];
  var addrs = [];
  var ttl = 0;
  for (var i = 0; i < answers.length; i++) {
    // 1 = A, 28 = AAAA. CNAME hops in the chain are ignored; only addresses count.
    if ((answers[i].type === 1 || answers[i].type === 28) && parseIp(answers[i].data)) {
      addrs.push(answers[i].data);
      if (!ttl || answers[i].TTL < ttl) ttl = answers[i].TTL;
    }
  }
  return {addrs: addrs, ttl: ttl};
}

async function resolveHostname(host) {
  var key = "dns_" + host.toLowerCase();
  var cached = await KV.get(key);
  if (cached !== null) return splitList(cached);

  var found, ttl;
  try {
    var a = await dohQuery(host, "A");
    var aaaa = await dohQuery(host, "AAAA");
    found = a.addrs.concat(aaaa.addrs);
    var ttls = [a.ttl, aaaa.ttl].filter(function(t) { return t > 0; });
    ttl = ttls.length ? Math.min.apply(null, ttls.concat([DNS_CACHE_TTL])) : DNS_CACHE_TTL;
  } catch (e) {
    // Transient failure: grant nothing, and do not cache the emptiness.
    return [];
  }
  // KV refuses any expiration under 60 seconds.
  await KV.put(key, found.join(","), {expirationTtl: Math.max(60, ttl)});
  return found;
}

// Turns a mixed list of CIDRs, bare IPs and hostnames into addresses only.
async function expandNetworks(list) {
  var out = [];
  for (var i = 0; i < list.length; i++) {
    if (looksLikeHostname(list[i])) {
      var addrs = await resolveHostname(list[i]);
      for (var j = 0; j < addrs.length; j++) out.push(addrs[j]);
    } else {
      out.push(list[i]);
    }
  }
  return out;
}

// "12B", "33 e" and "33" all have to reach the Oslo API as a number plus a
// separate letter. Anything unparseable degrades to the digits it can find.
function splitHouseNumber(raw) {
  var m = String(raw == null ? "" : raw).trim().match(/^(\d+)\s*([A-Za-z]?)/);
  if (!m) return {number: "", letter: ""};
  return {number: m[1], letter: (m[2] || "").toUpperCase()};
}

async function kvProxyHosts() {
  return splitList(await KV.get("proxy_hosts"));
}

// ── Net worth & 2030 equity tracker ──────────────────────────────────────────
// Design: "Anchors & Generators". Nothing stores a running balance. Each asset
// and loan is one DATED ANCHOR plus a RULE for how it evolves — a contribution
// schedule, an amortisation schedule, an expected return, or a market index.
// Every figure is computed by evaluating those rules at a month. That is what
// makes "set a savings plan once" work instead of logging what you saved.
//
// Tier 2 only (token AND home network). Financial data must never reach
// /config/save, which is unauthenticated — hence SHAREABLE_CONFIG_KEYS above.

// Placeholders. Every figure here is invented; the owner replaces them from the
// dashboard. They exist so the card can be seen working before real numbers.
var NW_PLACEHOLDER = {
  rev: 0,
  placeholder: true,
  policy: {
    targetMonth: "2030-06",
    nextPurchasePriceNok: 12000000,
    priceSetOn: "2026-09",
    indexNextPurchase: true,
    // 2025 utlånsforskrift: 10% egenkapitalkrav, so LTV max 90%. The design
    // originally assumed 0.85, which is the PRE-2025 15% rule and would have
    // invented ~600 000 kr of phantom deposit on a 12 MNOK purchase.
    ltvMax: 0.90,
    gjeldsgradMax: 5.0,
    stressTestPp: 3.0,
    stressTestFloorPct: 7.0,
    grossHouseholdIncomeNok: 1800000,
    incomeGrowthPct: 3.0,
    dokumentavgiftPct: 2.5,
    purchaseFeesNok: 25000,
    housingGrowthPctBeyondIndex: 3.0
  },
  assets: [
    { id: "home", kind: "property", label: "Nåværende bolig", anchorValueNok: 8500000,
      anchorOn: "2026-06", ownershipShare: 0.5, eieform: "selveier", fellesgjeldNok: 0,
      isPrimaryHome: true },
    { id: "ask", kind: "fund", wrapper: "ask", label: "Indeksfond (ASK)",
      anchorValueNok: 1200000, anchorOn: "2026-09", innskuttKapitalNok: 900000,
      akkumulertSkjermingNok: 45000, expectedReturnPct: 6.0, ownershipShare: 1.0,
      contributionNokPerMonth: 15000 },
    { id: "buffer", kind: "cash", wrapper: "none", label: "Bufferkonto",
      anchorValueNok: 250000, anchorOn: "2026-09", expectedReturnPct: 3.0,
      ownershipShare: 1.0, contributionNokPerMonth: 0 },
    { id: "restricted", kind: "cash", wrapper: "none", label: "Øremerket pott",
      anchorValueNok: 300000, anchorOn: "2026-09", expectedReturnPct: 3.0,
      ownershipShare: 1.0, contributionNokPerMonth: 0, restricted: true }
  ],
  liabilities: [
    { id: "mortgage", kind: "annuitetslan", label: "Boliglån", anchorBalanceNok: 4200000,
      anchorOn: "2026-09", ratePct: 5.4, termMonths: 300, extraPrincipalNokPerMonth: 8000,
      ownershipShare: 0.5 }
  ]
};

function nwMonthIndex(ym) {
  var m = String(ym || "").match(/^(\d{4})-(\d{2})$/);
  if (!m) return null;
  return Number(m[1]) * 12 + (Number(m[2]) - 1);
}

function nwMonthsBetween(fromYm, toYm) {
  var a = nwMonthIndex(fromYm), b = nwMonthIndex(toYm);
  return (a === null || b === null) ? 0 : b - a;
}

// SSB 07221, region 001 "Oslo med Bærum", 2015=100, quarterly back to 1992.
// Cached for a week: it only moves once a quarter.
async function nwHousingIndex() {
  var cached = await KV.get("nw_housing_index");
  if (cached) { try { return JSON.parse(cached); } catch (e) {} }
  var resp = await fetch("https://data.ssb.no/api/v0/no/table/07221", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      query: [
        {code: "Region", selection: {filter: "item", values: ["001"]}},
        {code: "Boligtype", selection: {filter: "item", values: ["00"]}},
        {code: "ContentsCode", selection: {filter: "item", values: ["Boligindeks"]}}
      ],
      response: {format: "json-stat2"}
    })
  });
  if (!resp.ok) throw new Error("SSB HTTP " + resp.status);
  var d = await resp.json();
  var periods = Object.keys(d.dimension.Tid.category.index);
  var values = d.value;
  var series = {};
  for (var i = 0; i < periods.length; i++) {
    if (values[i] !== null && values[i] !== undefined) series[periods[i]] = values[i];
  }
  var out = {series: series, fetched: Date.now(), source: "SSB 07221 Oslo med Bærum (2015=100)"};
  await KV.put("nw_housing_index", JSON.stringify(out), {expirationTtl: 7 * 86400});
  return out;
}

// Quarterly series -> a value for any month. Before the series starts, clamp.
// After it ends, grow at the declared rate rather than freezing: a frozen index
// would silently stop the largest asset moving and look like calm.
function nwIndexAt(series, ym, growthPctBeyond) {
  var keys = Object.keys(series).sort();
  if (!keys.length) return null;
  var mi = nwMonthIndex(ym);
  if (mi === null) return null;

  function qIndex(q) {
    var m = q.match(/^(\d{4})K(\d)$/);
    return m ? Number(m[1]) * 12 + (Number(m[2]) - 1) * 3 : null;
  }
  var first = keys[0], last = keys[keys.length - 1];
  if (mi <= qIndex(first)) return series[first];
  if (mi >= qIndex(last)) {
    var monthsPast = mi - qIndex(last);
    var g = (growthPctBeyond || 0) / 100;
    return series[last] * Math.pow(1 + g, monthsPast / 12);
  }
  // Linear between the bracketing quarters.
  var prevK = first, nextK = last;
  for (var i = 0; i < keys.length; i++) {
    if (qIndex(keys[i]) <= mi) prevK = keys[i];
    if (qIndex(keys[i]) >= mi) { nextK = keys[i]; break; }
  }
  var p = qIndex(prevK), n = qIndex(nextK);
  if (n === p) return series[prevK];
  var t = (mi - p) / (n - p);
  return series[prevK] + (series[nextK] - series[prevK]) * t;
}

// Value of one asset at month ym, before ownership share.
function nwAssetValue(asset, ym, idx) {
  var months = Math.max(0, nwMonthsBetween(asset.anchorOn, ym));
  var base = Number(asset.anchorValueNok) || 0;

  if (asset.kind === "property") {
    // Indexed, never guessed: with no index the caller reports the asset as
    // missing rather than substituting an invented growth rate.
    if (!idx || !idx.at || !idx.anchor) return null;
    return base * (idx.at / idx.anchor);
  }

  var r = (Number(asset.expectedReturnPct) || 0) / 100;
  var monthlyR = Math.pow(1 + r, 1 / 12) - 1;
  var value = base * Math.pow(1 + monthlyR, months);
  // Contributions are the whole point of declaring a plan once: each month's
  // deposit compounds for the months remaining.
  var c = Number(asset.contributionNokPerMonth) || 0;
  if (c > 0 && months > 0) {
    value += monthlyR === 0 ? c * months
      : c * ((Math.pow(1 + monthlyR, months) - 1) / monthlyR);
  }
  return value;
}

// Total paid into an ASK by month ym. Innskutt kapital comes out FIRST and
// tax-free, which is why it is tracked apart from market value.
function nwInnskuttAt(asset, ym) {
  var months = Math.max(0, nwMonthsBetween(asset.anchorOn, ym));
  return (Number(asset.innskuttKapitalNok) || 0) +
         (Number(asset.contributionNokPerMonth) || 0) * months;
}

// Annuity amortisation with optional extra principal.
function nwLoanBalance(loan, ym) {
  var months = nwMonthsBetween(loan.anchorOn, ym);
  var bal = Number(loan.anchorBalanceNok) || 0;
  if (months <= 0) return bal;
  var i = (Number(loan.ratePct) || 0) / 100 / 12;
  var n = Number(loan.termMonths) || 300;
  var extra = Number(loan.extraPrincipalNokPerMonth) || 0;
  var pay = i === 0 ? bal / n : bal * i / (1 - Math.pow(1 + i, -n));
  for (var m = 0; m < months && bal > 0; m++) {
    var principal = pay - bal * i + extra;
    if (principal <= 0) break;            // negative amortisation: stop
    bal = Math.max(0, bal - principal);
  }
  return bal;
}

// ASK withdrawal tax: innskutt kapital comes out first and tax-free; only the
// rest is gain, taxed at 22% uplifted by 1.72, less accumulated skjerming.
// Applied ONLY to the target, never to net worth — net worth is what you own,
// the target is what you can actually hand to a seller.
function nwRealisationTax(asset, ym, value) {
  if (asset.kind !== "fund" || value === null) return 0;
  if (asset.wrapper === "ask") {
    var gain = Math.max(0, value - nwInnskuttAt(asset, ym) -
                           (Number(asset.akkumulertSkjermingNok) || 0));
    return gain * 0.22 * 1.72;
  }
  var basis = Number(asset.costBasisNok) || nwInnskuttAt(asset, ym) || 0;
  return Math.max(0, value - basis) * 0.22 * 1.72;
}

function nwEvaluate(cfg, ym, housing) {
  var pol = cfg.policy || {};
  var beyond = pol.housingGrowthPctBeyondIndex;
  var series = housing && housing.series;
  var idxAt = series ? nwIndexAt(series, ym, beyond) : null;
  var missing = [];
  var sum = function (arr, f) { return arr.reduce(function (n, x) { return n + f(x); }, 0); };

  var assets = (cfg.assets || []).map(function (a) {
    var idx = null;
    if (a.kind === "property") {
      var anchorIdx = series ? nwIndexAt(series, a.anchorOn, beyond) : null;
      idx = (idxAt && anchorIdx) ? {at: idxAt, anchor: anchorIdx} : null;
    }
    var raw = nwAssetValue(a, ym, idx);
    if (raw === null) missing.push(a.label || a.id);
    var share = a.ownershipShare === undefined ? 1 : Number(a.ownershipShare);
    var free = a.wrapper === "ask"
      ? nwInnskuttAt(a, ym) + (Number(a.akkumulertSkjermingNok) || 0) : 0;
    return {
      id: a.id, label: a.label, kind: a.kind, wrapper: a.wrapper || "none",
      restricted: !!a.restricted, isPrimaryHome: !!a.isPrimaryHome,
      raw: raw, share: share, mine: raw === null ? null : raw * share,
      tax: raw === null ? 0 : nwRealisationTax(a, ym, raw) * share,
      taxFree: raw === null ? 0 : Math.min(raw, free) * share
    };
  });

  var liabilities = (cfg.liabilities || []).map(function (l) {
    var bal = nwLoanBalance(l, ym);
    var share = l.ownershipShare === undefined ? 1 : Number(l.ownershipShare);
    return {id: l.id, label: l.label, raw: bal, share: share, mine: bal * share};
  });

  // A value once known is never dropped to zero, and one never known is never
  // guessed. If anything is unpriced the totals are withheld: a total missing
  // its largest asset is not stale, it is wrong.
  if (missing.length) {
    return {ym: ym, incomplete: true, missing: missing, assets: assets, liabilities: liabilities};
  }

  var netWorthMine = sum(assets, function (a) { return a.mine; })
                   - sum(liabilities, function (l) { return l.mine; });
  var netWorthHousehold = sum(assets, function (a) { return a.raw; })
                        - sum(liabilities, function (l) { return l.raw; });

  var isLiquid = function (a) { return !a.isPrimaryHome && !a.restricted; };
  var homeValueMine = sum(assets.filter(function (a) { return a.isPrimaryHome; }),
                          function (a) { return a.mine; });
  var homeLoanMine = sum(liabilities, function (l) { return l.mine; });
  var homeEquityMine = Math.max(0, homeValueMine - homeLoanMine);
  var liquidMine = sum(assets.filter(isLiquid), function (a) { return a.mine; });
  var taxOnLiquid = sum(assets.filter(isLiquid), function (a) { return a.tax; });
  var restrictedMine = sum(assets.filter(function (a) { return a.restricted; }),
                           function (a) { return a.mine; });

  var equitySupply = homeEquityMine + liquidMine - taxOnLiquid;

  // Demand side indexed to the SAME series as the current home, so a housing
  // boom reads as roughly neutral. Trading up in a rising market does not make
  // the upgrade easier, and a meter that fills on it is lying.
  var priceIdx = series ? nwIndexAt(series, pol.priceSetOn, beyond) : null;
  var nextPrice = Number(pol.nextPurchasePriceNok) || 0;
  if (pol.indexNextPurchase && priceIdx && idxAt) nextPrice *= idxAt / priceIdx;

  var years = Math.max(0, nwMonthsBetween(pol.priceSetOn, ym)) / 12;
  var grossIncome = (Number(pol.grossHouseholdIncomeNok) || 0) *
                    Math.pow(1 + (Number(pol.incomeGrowthPct) || 0) / 100, years);

  // The constraint the bank actually applies. Equity is often NOT what binds:
  // utlånsforskriften caps total debt at 5x gross income, so a tracker that
  // only asks "do I have the deposit" can show green for years while the bank
  // would decline on income alone.
  var maxLoanByLtv = nextPrice * (Number(pol.ltvMax) || 0.9);
  var maxLoanByIncome = grossIncome * (Number(pol.gjeldsgradMax) || 5);
  var maxLoan = Math.min(maxLoanByLtv, maxLoanByIncome);
  var binding = maxLoanByIncome < maxLoanByLtv ? "gjeldsgrad" : "egenkapital";

  var costs = nextPrice * (Number(pol.dokumentavgiftPct) || 0) / 100
            + (Number(pol.purchaseFeesNok) || 0);
  var equityNeeded = Math.max(0, nextPrice - maxLoan + costs);

  var loanRate = (cfg.liabilities && cfg.liabilities[0] &&
                  Number(cfg.liabilities[0].ratePct)) || 5.4;
  var stressRate = Math.max(loanRate + (Number(pol.stressTestPp) || 3),
                            Number(pol.stressTestFloorPct) || 7) / 100;

  return {
    ym: ym, incomplete: false, assets: assets, liabilities: liabilities,
    netWorthMine: netWorthMine, netWorthHousehold: netWorthHousehold,
    homeEquityMine: homeEquityMine, liquidMine: liquidMine,
    restrictedMine: restrictedMine, realisationTax: taxOnLiquid,
    // The tranche that costs nothing to move, because ASK innskutt kapital is
    // withdrawn first and tax-free. None of the source designs produced this.
    taxFreeTranche: sum(assets, function (a) { return a.taxFree; }),
    nextPrice: nextPrice, grossIncome: grossIncome,
    maxLoanByLtv: maxLoanByLtv, maxLoanByIncome: maxLoanByIncome,
    maxLoan: maxLoan, binding: binding, costs: costs,
    equityNeeded: equityNeeded, equitySupply: equitySupply,
    gap: equitySupply - equityNeeded, onTrack: equitySupply >= equityNeeded,
    stressAnnual: maxLoan * stressRate, stressRatePct: stressRate * 100,
    housingIndex: idxAt, housingSource: housing && housing.source
  };
}

async function nwLoadConfig() {
  var raw = await KV.get("nw_config");
  if (!raw) return NW_PLACEHOLDER;
  try {
    var cfg = JSON.parse(raw);
    return (cfg && typeof cfg === "object") ? cfg : NW_PLACEHOLDER;
  } catch (e) { return NW_PLACEHOLDER; }
}

function nwThisMonth(now) {
  var d = new Date(now);
  return d.getUTCFullYear() + "-" + ("0" + (d.getUTCMonth() + 1)).slice(-2);
}

async function nwProjection(request) {
  var cfg = await nwLoadConfig();
  var housing = null, housingError = null;
  try { housing = await nwHousingIndex(); }
  catch (e) { housingError = e.message; }

  var nowYm = nwThisMonth(Date.now());
  var targetYm = (cfg.policy && cfg.policy.targetMonth) || "2030-06";
  var now = nwEvaluate(cfg, nowYm, housing);
  var target = nwEvaluate(cfg, targetYm, housing);

  // A yearly track for the chart, so the card can show the path rather than
  // only the endpoints.
  var track = [];
  var startY = Number(nowYm.slice(0, 4));
  var endY = Number(targetYm.slice(0, 4));
  for (var y = startY; y <= endY; y++) {
    var ym = y === endY ? targetYm : y + "-12";
    var e = nwEvaluate(cfg, ym, housing);
    track.push({
      ym: ym,
      netWorthMine: e.incomplete ? null : Math.round(e.netWorthMine),
      equitySupply: e.incomplete ? null : Math.round(e.equitySupply),
      equityNeeded: e.incomplete ? null : Math.round(e.equityNeeded)
    });
  }

  return jsonResponse({
    placeholder: !!cfg.placeholder,
    rev: cfg.rev || 0,
    now: now, target: target, track: track,
    housingError: housingError,
    generatedAt: Date.now()
  });
}
