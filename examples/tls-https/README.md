# TLS / HTTPS

Terminate TLS in NGINX and redirect all HTTP traffic to HTTPS.

## What it does

- Listens on `8080` (HTTP) and permanently redirects to HTTPS.
- Listens on `8443` (HTTPS) with TLS 1.2 and 1.3 only.
- Enables a shared TLS session cache for faster handshakes.
- Sends an HSTS header so browsers stick to HTTPS.

## Run locally

Generate a self-signed certificate:

```sh
mkdir -p certs html
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/privkey.pem -out certs/fullchain.pem \
    -subj "/CN=localhost"
echo '<h1>Hello over HTTPS</h1>' > html/index.html
```

Run NGINX:

```sh
docker run --rm -p 8080:8080 -p 8443:8443 \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/certs:/etc/nginx/certs:ro" \
    -v "$PWD/html:/usr/share/nginx/html:ro" \
    nginx:alpine
```

Test (the `-k` flag accepts the self-signed certificate):

```sh
curl -k https://localhost:8443
curl -I http://localhost:8080   # 301 redirect to https://
```

## Notes

- For real certificates use a CA such as Let's Encrypt; point
  `ssl_certificate` at `fullchain.pem` and `ssl_certificate_key` at
  `privkey.pem`.
- Only enable HSTS (`Strict-Transport-Security`) once HTTPS works
  reliably — browsers remember it for the whole `max-age`.
- To proxy the HTTPS traffic to an app instead of serving files,
  combine this with the [reverse-proxy](../reverse-proxy/) example.

## Learn more

- https://nginx.org/en/docs/http/ngx_http_ssl_module.html
- https://nginx.org/en/docs/http/configuring_https_servers.html
