# NGINX Configuration Examples

Practical, copy-paste friendly NGINX configuration examples for common
use cases. Each directory contains a complete, self-contained
`nginx.conf` and a README explaining what it does and how to run it.

## Examples

| Directory | Description |
|---|---|
| [static-site](static-site/) | Serve static files with gzip and cache headers |
| [reverse-proxy](reverse-proxy/) | Reverse proxy to an application server |
| [tls-https](tls-https/) | HTTPS with HTTP to HTTPS redirect |
| [load-balancing](load-balancing/) | Distribute traffic across multiple backends |
| [websockets](websockets/) | Proxy WebSocket connections |
| [rate-limiting](rate-limiting/) | Rate limit an API with `limit_req` / `limit_conn` |
| [security-basics](security-basics/) | Safe defaults: tokens, hidden files, headers |
| [spa](spa/) | Single-Page App with `try_files` fallback |
| [php-fpm](php-fpm/) | Minimal PHP-FPM setup |
| [docker](docker/) | Run NGINX with Docker Compose |

## Conventions

- Examples listen on port `8080` (and `8443` for TLS) so they can run
  without root privileges. Use `80`/`443` in production.
- Paths such as `/etc/nginx/` and `/usr/share/nginx/html/` follow the
  official NGINX Docker image and common Linux packages. Adjust them
  for your distribution.
- Each config is a complete `nginx.conf`, not a snippet to paste into
  an existing `http {}` block.

## Validating a config

```sh
nginx -t -c /path/to/examples/static-site/nginx.conf
```

## Running an example with Docker

```sh
docker run --rm -p 8080:8080 \
    -v "$PWD/examples/static-site/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/examples/static-site/html:/usr/share/nginx/html:ro" \
    nginx:alpine
```

Then open http://localhost:8080.
