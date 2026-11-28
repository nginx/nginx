---
name: nginx-config
description: >-
  Write or review nginx.conf and included configs: directive contexts, location
  matching, reverse proxy and upstream, TLS/HTTPS, HTTP/2, and HTTP/3/QUIC.
  Use when editing conf/, diagnosing config test failures, or choosing listen,
  location, proxy_*, ssl_*, http2, or http3 directives.
---

# NGINX configuration

Ground answers in this repository: default `conf/nginx.conf`, directive tables
in `src/http/ngx_http_core_module.c`, `src/http/modules/ngx_http_*_module.c`,
`src/http/v2/`, `src/http/v3/`, and docs at https://nginx.org/en/docs/. Prefer
`nginx -t` after edits. Available directives depend on which modules were built
(`nginx -V`).

## Contexts and structure

Typical nesting (see `conf/nginx.conf`):

- main: `worker_processes`, `error_log`, `pid`, `events { ... }`, `http { ... }`
  (also `stream` / `mail` when those modules are built)
- `events`: `worker_connections`
- `http`: shared HTTP settings, `upstream`, one or more `server` blocks
- `server`: `listen`, `server_name`, nested `location` blocks
- `location`: handlers such as `root`/`alias`, `proxy_pass`, `fastcgi_pass`

Directive context is enforced in source via flags such as
`NGX_HTTP_MAIN_CONF`, `NGX_HTTP_SRV_CONF`, `NGX_HTTP_LOC_CONF` on each
`ngx_command_t`. Do not invent directives; verify names against the module that
implements them.

## Location matching

`location` is registered in `ngx_http_core_module` (`NGX_HTTP_SRV_CONF` /
`NGX_HTTP_LOC_CONF`). Matching order (see `ngx_http_core_find_location()`):

1. Exact `location = /uri` (static tree; wins when URI matches exactly)
2. Longest prefix match among prefix locations; `^~` stops regex search
3. First matching regex `location ~` / `location ~*` (definition order)
4. Otherwise the longest prefix match

Nested locations inherit and merge loc conf. Prefer exact/`^~` for static
assets; keep regex locations few and ordered deliberately.

## Reverse proxy and upstream

Core upstream block and variables live in `src/http/ngx_http_upstream.c`
(`upstream`, `$upstream_addr`, `$upstream_status`, timing/cache variables).
HTTP proxy directives are in `src/http/modules/ngx_http_proxy_module.c`,
including `proxy_pass`, `proxy_set_header`, `proxy_redirect`, buffering
(`proxy_buffering`, `proxy_buffers`, `proxy_buffer_size`), timeouts
(`proxy_connect_timeout`, `proxy_send_timeout`, `proxy_read_timeout`), and
cache (`proxy_cache`, `proxy_cache_path`, `proxy_cache_valid`, …).

Load-balancing methods are separate modules under
`src/http/modules/ngx_http_upstream_*_module.c` (round-robin by default;
`hash`, `ip_hash`, `least_conn`, `least_time`, `random`, `sticky` when built).

Minimal reverse-proxy pattern:

```nginx
upstream backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name example.com;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header Connection        "";
        proxy_pass http://backend;
    }
}
```

`proxy_pass` with a URI path replaces the matched location prefix; without a
path it forwards the full original URI. Confirm trailing-slash intent.

## TLS / HTTPS

Requires `--with-http_ssl_module` at build time. Directives are defined in
`src/http/modules/ngx_http_ssl_module.c`, including `ssl_certificate`,
`ssl_certificate_key`, `ssl_protocols`, `ssl_ciphers`,
`ssl_prefer_server_ciphers`, `ssl_session_cache`, `ssl_session_timeout`,
`ssl_session_tickets`, OCSP stapling (`ssl_stapling*`), and client verification
(`ssl_verify_client`, `ssl_client_certificate`, …).

Enable TLS on the socket with `listen ... ssl` (parsed in
`ngx_http_core_listen()`). Example:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
}
```

`ssl_protocols` accepts `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`, `TLSv1.2`,
`TLSv1.3` (prefer modern TLS only).

## HTTP/2 and HTTP/3 (QUIC)

- HTTP/2: build with `--with-http_v2_module`. Prefer the `http2 on;` directive
  from `src/http/v2/ngx_http_v2_module.c`. The legacy `listen ... http2`
  parameter still parses but emits a deprecation warning favoring `http2`.
- HTTP/3 / QUIC: build with `--with-http_v3_module`. Use `listen ... quic`
  (UDP). In `ngx_http_core_listen()`, `quic` is incompatible with `ssl`,
  `http2`, `fastopen`, `backlog`, `deferred`, `so_keepalive`, and
  `proxy_protocol` on the same listen. TLS for QUIC is configured with the
  usual `ssl_certificate` / `ssl_certificate_key` in the server. Related
  directives in `src/http/v3/ngx_http_v3_module.c`: `http3`, `http3_hq`,
  `http3_max_concurrent_streams`, `http3_stream_buffer_size`, `quic_retry`,
  `quic_gso`, `quic_host_key`, `quic_active_connection_id_limit`.

Typical dual-stack HTTPS + HTTP/3:

```nginx
server {
    listen 443 ssl;
    listen 443 quic reuseport;
    http2 on;
    http3 on;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        # advertise HTTP/3
        add_header Alt-Svc 'h3=":443"; ma=86400';
    }
}
```

## Review checklist

- Run `nginx -t` (or `objs/nginx -t -c ...` for a source build)
- Confirm every directive exists in the built modules (`nginx -V`)
- Check location match type (`=`, prefix, `^~`, `~`, `~*`) and order
- For `proxy_pass`, verify scheme, upstream name, and URI replacement
- For TLS, pair `listen ... ssl` with certificate directives; for QUIC use
  `listen ... quic` without the `ssl` listen parameter
- Prefer shared memory zones where workers must coordinate (limiters, SSL
  session cache, upstream zone)
