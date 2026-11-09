# Reverse proxy to an app

Forward requests to an application server (Node, Python, Go, ...)
listening on `127.0.0.1:3000`.

## What it does

- Proxies all requests to the `app` upstream.
- Keeps up to 32 idle keepalive connections to the app, avoiding the
  cost of a new TCP connection per request.
- Forwards standard headers (`Host`, `X-Real-IP`, `X-Forwarded-For`,
  `X-Forwarded-Proto`) so the app sees the real client.
- Sets explicit timeouts and buffers responses.

## Run locally

Start any app on port 3000, e.g.:

```sh
docker run --rm -p 3000:3000 hashicorp/http-echo -text "hello from app"
```

Or use your own application. Then run NGINX:

```sh
docker run --rm --network host \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    nginx:alpine
```

(`--network host` lets the container reach `127.0.0.1:3000` on your
machine. On Docker Desktop for Mac/Windows, replace `127.0.0.1` in
`nginx.conf` with `host.docker.internal` and use `-p 8080:8080`
instead.)

Test:

```sh
curl http://localhost:8080
```

## Notes

- `proxy_connect_timeout` should stay small: if the app cannot accept a
  connection, fail fast instead of making clients wait.
- For multiple backends, see the [load-balancing](../load-balancing/)
  example.
- For WebSocket endpoints, see the [websockets](../websockets/) example.

## Learn more

- https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive
