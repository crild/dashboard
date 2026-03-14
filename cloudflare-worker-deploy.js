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

function checkDashboardToken(request) {
  var expected = typeof DASHBOARD_TOKEN !== "undefined" ? DASHBOARD_TOKEN : "";
  if (!expected) return true; // no token configured = no protection
  var token = request.headers.get("X-Dashboard-Token") || new URL(request.url).searchParams.get("token");
  return token === expected;
}

async function handleRequest(request) {
  var url = new URL(request.url);
  var path = url.pathname;

  // Protected endpoints: netatmo and hue
  if (path.startsWith("/netatmo") || path.startsWith("/hue") || path.startsWith("/auth/") || path.startsWith("/callback/")) {
    // Allow callbacks (they come from OAuth providers, not the dashboard)
    if (!path.startsWith("/callback/")) {
      if (!checkDashboardToken(request)) {
        return new Response(JSON.stringify({error: "Unauthorized"}), {
          status: 403,
          headers: {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}
        });
      }
    }
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
    return new Response(null, {headers: {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,X-Dashboard-Token"}});
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
