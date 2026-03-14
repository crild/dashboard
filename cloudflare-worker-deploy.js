addEventListener("fetch", function(event) {
  event.respondWith(handleRequest(event.request));
});

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
  var path = url.pathname;

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

  if (request.method === "OPTIONS") {
    return new Response(null, {headers: {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type"}});
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

function generateCode() {
  var chars = "abcdefghijkmnpqrstuvwxyz23456789";
  var code = "";
  for (var i = 0; i < 8; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}
