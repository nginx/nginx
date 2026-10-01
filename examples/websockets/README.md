# WebSockets

Proxy WebSocket connections through NGINX.

## What it does

- Handles the WebSocket handshake by forwarding the `Upgrade` and
  `Connection` headers (NGINX does not do this automatically).
- Uses a `map` so the same location keeps working for plain HTTP
  requests without an `Upgrade` header.
- Raises `proxy_read_timeout` to one hour so idle connections are not
  dropped (the default is 60 seconds).
- Proxies `/ws/` to the app while `/` remains a normal HTTP proxy.

## Run locally

Start any WebSocket echo server on port 3000, e.g. with Node.js:

```sh
npx --yes wscat --listen 3000
```

Run NGINX (Linux):

```sh
docker run --rm --network host \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    nginx:alpine
```

(On Docker Desktop for Mac/Windows, replace `127.0.0.1` in
`nginx.conf` with `host.docker.internal` and use `-p 8080:8080`.)

Test:

```sh
npx --yes wscat --connect ws://localhost:8080/ws/
```

Type a message — the echo server sends it back through NGINX.

## Notes

- If your app sends no traffic while idle, enable WebSocket
  ping/pong keepalives in the app, or raise `proxy_read_timeout`
  further.
- With multiple backends, WebSocket sessions may need `ip_hash`
  stickiness (see the [load-balancing](../load-balancing/) example).

## Learn more

- https://nginx.org/en/docs/http/websocket.html
- https://nginx.org/en/docs/http/ngx_http_map_module.html
