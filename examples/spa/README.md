# Single-Page App (SPA)

Serve a client-rendered app (React, Vue, Angular, ...) whose routes are
handled in the browser.

## What it does

- Serves the build output (e.g. `dist/` or `build/`) as static files.
- Falls back to `index.html` for unknown paths, so deep links like
  `/users/42` work after a refresh — the client-side router takes over.
- Caches fingerprinted bundles under `/assets/` aggressively.
- Marks `index.html` as `no-cache` so deployments take effect
  immediately.

## Run locally

Use your app's build output, or a minimal stand-in:

```sh
mkdir -p dist/assets
echo '<h1>SPA entry point</h1>' > dist/index.html
echo 'console.log("bundle")' > dist/assets/app.a1b2c3.js

docker run --rm -p 8080:8080 \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/dist:/usr/share/nginx/html:ro" \
    nginx:alpine
```

Test:

```sh
curl http://localhost:8080/some/client/route   # returns index.html
curl -I http://localhost:8080/assets/app.a1b2c3.js  # long cache
```

## Notes

- The fallback `try_files $uri $uri/ /index.html;` is the key
  difference from the [static-site](../static-site/) example, which
  returns `404` instead.
- If the app calls an API on the same origin, add a `location /api/`
  block with `proxy_pass` (see the
  [reverse-proxy](../reverse-proxy/) example).

## Learn more

- https://nginx.org/en/docs/http/ngx_http_core_module.html#try_files
