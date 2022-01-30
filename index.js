blacklist = []; // regexp for blacklisted urls
whitelist = [".*"]; // regexp for whitelisted origins

const isListed = (uri, listing) => {
  let ret = false;
  if (typeof uri == "string") {
    listing.forEach((m) => {
      if (uri.match(m) != null) ret = true;
    });
  } else {
    //   decide what to do when Origin is null
    ret = true; // true accepts null origins false rejects them.
  }
  return ret;
};

addEventListener("fetch", async (event) => {
  event.respondWith(
    (async () => {
      const isOPTIONS = event.request.method == "OPTIONS";

      const fix = myHeaders => {
        myHeaders.set(
          "Access-Control-Allow-Origin",
          event.request.headers.get("Origin")
        );
        if (isOPTIONS) {
          myHeaders.set(
            "Access-Control-Allow-Methods",
            event.request.headers.get("access-control-request-method")
          );
          acrh = event.request.headers.get("access-control-request-headers");

          if (acrh) {
            myHeaders.set("Access-Control-Allow-Headers", acrh);
          }

          myHeaders.delete("X-Content-Type-Options");
        }
        return myHeaders;
      }

      let originUrl = new URL(event.request.url);

      const fetchUrl = decodeURIComponent(
        originUrl.search.split("url=")[1]
      );

      let orig = event.request.headers.get("Origin");

      let remIp = event.request.headers.get("CF-Connecting-IP");

      if (!isListed(fetchUrl, blacklist) && isListed(orig, whitelist)) {
        let xheaders = event.request.headers.get("x-cors-headers");

        if (xheaders != null) {
          try {
            xheaders = JSON.parse(xheaders);
          } catch (e) {}
        }

        if (originUrl.search.startsWith("?")) {
          recv_headers = {};
          for (let pair of event.request.headers.entries()) {
            if (
              pair[0].match("^origin") == null &&
              pair[0].match("eferer") == null &&
              pair[0].match("^cf-") == null &&
              pair[0].match("^x-forw") == null &&
              pair[0].match("^x-cors-headers") == null
            )
              recv_headers[pair[0]] = pair[1];
          }

          if (xheaders != null) {
            Object.entries(xheaders).forEach(
              (c) => (recv_headers[c[0]] = c[1])
            );
          }

          newreq = new Request(event.request, {
            headers: recv_headers,
          });

          let response = await fetch(fetchUrl, newreq);
          let myHeaders = new Headers(response.headers);
          const corsHeaders = [];
          const allh = {};

          for (let pair of response.headers.entries()) {
            corsHeaders.push(pair[0]);
            allh[pair[0]] = pair[1];
          }

          corsHeaders.push("cors-received-headers");
          myHeaders = fix(myHeaders);

          myHeaders.set(
            "Access-Control-Expose-Headers",
            corsHeaders.join(",")
          );

          myHeaders.set("cors-received-headers", JSON.stringify(allh));

          let body

          if (isOPTIONS) {
            body = null;
          } else {
            body = await response.arrayBuffer();
          }

          let init = {
            headers: myHeaders,
            status: isOPTIONS ? 200 : response.status,
            statusText: isOPTIONS ? "OK" : response.statusText,
          };
          return new Response(body, init);
        } else {
          let myHeaders = new Headers();
          myHeaders = fix(myHeaders);

          if (typeof event.request.cf != "undefined") {
            if (typeof event.request.cf.country != "undefined") {
              country = event.request.cf.country;
            } else country = false;

            if (typeof event.request.cf.colo != "undefined") {
              colo = event.request.cf.colo;
            } else colo = false;
          } else {
            country = false;
            colo = false;
          }

          return new Response(
              "Usage:\n" +
              originUrl.origin +
              "/?uri\n\n" +
              (orig != null ? "Origin: " + orig + "\n" : "") +
              "Ip: " +
              remIp +
              "\n" +
              (country ? "Country: " + country + "\n" : "") +
              (colo ? "Datacenter: " + colo + "\n" : "") +
              "\n" +
              (xheaders != null
                ? "\nx-cors-headers: " + JSON.stringify(xheaders)
                : ""),
            { status: 200, headers: myHeaders }
          );
        }
      } else {
        return new Response(
          "CORS Proxy",
          {
            status: 403,
            statusText: "Forbidden",
            headers: {
              "Content-Type": "text/html",
            },
          }
        );
      }
    })()
  );
});
