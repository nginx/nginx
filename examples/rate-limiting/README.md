# API + rate limiting

Protect an API with request-rate and connection-count limits.

## What it does

- `limit_req` caps each client IP at an average of 10 requests/second,
  with bursts of up to 20 requests allowed through immediately.
- `limit_conn` caps each client IP at 10 simultaneous connections.
- Excess requests get a `429 Too Many Requests` response.

## Run locally

Start any app on port 3000, then run NGINX (Linux):

```sh
docker run --rm --network host \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    nginx:alpine
```

(On Docker Desktop for Mac/Windows, replace `127.0.0.1` in
`nginx.conf` with `host.docker.internal` and use `-p 8080:8080`.)

Test — after ~30 quick requests you should start seeing `429`:

```sh
for i in $(seq 1 50); do
    curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/
done
```

## Notes

- Remove `nodelay` to instead queue burst requests and serve them at
  the configured rate — gentler on the backend, slower for clients.
- Tune `rate` and `burst` to your API's real capacity; 10 r/s is a
  conservative starting point, not a recommendation.
- If NGINX sits behind another proxy or CDN, `$binary_remote_addr`
  shows the proxy's IP. Use the
  [real_ip](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
  module to key limits on the real client IP.

## Learn more

- https://nginx.org/en/docs/http/ngx_http_limit_req_module.html
- https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html
- https://www.nginx.com/blog/rate-limiting-nginx/
