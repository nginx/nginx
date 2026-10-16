# Static site

Serve static files directly from disk with compression and caching.

## What it does

- Serves files from `/usr/share/nginx/html` (the document root).
- Returns `404` for missing files via `try_files`.
- Compresses text responses with `gzip`.
- Sends long-lived, immutable cache headers for files under `/assets/`
  (use a fingerprinted filename, e.g. `app.a1b2c3.js`, so browsers can
  cache them safely).

## Run locally

```sh
mkdir -p html
echo '<h1>Hello from NGINX</h1>' > html/index.html

docker run --rm -p 8080:8080 \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/html:/usr/share/nginx/html:ro" \
    nginx:alpine
```

Open http://localhost:8080.

## Notes

- Verify the cache headers: `curl -I http://localhost:8080/assets/app.js`
  should show `Cache-Control: public, immutable`.
- HTML files are intentionally *not* cached aggressively, so new
  deployments are picked up immediately.

## Learn more

- https://nginx.org/en/docs/http/ngx_http_core_module.html#try_files
- https://nginx.org/en/docs/http/ngx_http_headers_module.html#expires
- https://nginx.org/en/docs/http/ngx_http_gzip_module.html
