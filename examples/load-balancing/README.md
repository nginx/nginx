# Load balancing

Distribute traffic across multiple application backends using an
`upstream` block.

## What it does

- Round-robins requests across three backends on ports 3001–3003.
- Marks a backend as temporarily down after 3 failures in 30 seconds
  (passive health checks, built into NGINX OSS).
- Retries a failed request on the next backend (`proxy_next_upstream`).
- Keeps idle keepalive connections to the backends.

Alternative balancing methods are commented in `nginx.conf`:
`least_conn` (fewest active connections) and `ip_hash` (client-IP
stickiness).

## Run locally

Start three demo backends:

```sh
for port in 3001 3002 3003; do
    docker run -d --rm -p $port:3000 \
        hashicorp/http-echo -text "backend on $port"
done
```

Run NGINX (Linux):

```sh
docker run --rm --network host \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    nginx:alpine
```

(On Docker Desktop for Mac/Windows, replace the `127.0.0.1` addresses
with `host.docker.internal` and use `-p 8080:8080` instead of
`--network host`.)

Test — the response rotates between backends:

```sh
curl http://localhost:8080
```

## Notes

- Active health checks (proactively probing backends) require NGINX
  Plus or a third-party module; OSS uses passive checks only.
- `ip_hash` breaks when clients sit behind NAT or CGNAT; prefer
  application-level sessions when possible.

## Learn more

- https://nginx.org/en/docs/http/ngx_http_upstream_module.html
- https://nginx.org/en/docs/http/load_balancing.html
