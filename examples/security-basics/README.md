# Security basics

A few safe defaults that apply to almost any site.

## What it does

- `server_tokens off` — hides the exact NGINX version from error pages
  and the `Server` header.
- Blocks requests for hidden dotfiles (`.git`, `.env`, ...) while
  keeping `/.well-known/` reachable for ACME challenges and
  `security.txt`.
- Sends defensive response headers:
  - `X-Content-Type-Options: nosniff` — stop MIME-type sniffing.
  - `X-Frame-Options: SAMEORIGIN` — basic clickjacking protection.
  - `Referrer-Policy: strict-origin-when-cross-origin` — limit what is
    leaked in the `Referer` header.

## Run locally

```sh
mkdir -p html
echo '<h1>Hello</h1>' > html/index.html
echo 'SECRET=1' > html/.env

docker run --rm -p 8080:8080 \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/html:/usr/share/nginx/html:ro" \
    nginx:alpine
```

Test:

```sh
curl -I http://localhost:8080/       # no version in Server header
curl -i http://localhost:8080/.env   # 403 Forbidden
```

## Notes

- These headers are a baseline, not a complete policy. Depending on
  your app, also consider a `Content-Security-Policy` and, for HTTPS
  sites, HSTS (see the [tls-https](../tls-https/) example).
- Hiding the version is defense in depth, not a substitute for keeping
  NGINX up to date.

## Learn more

- https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens
- https://nginx.org/en/docs/http/ngx_http_access_module.html
- https://nginx.org/en/docs/http/ngx_http_headers_module.html
