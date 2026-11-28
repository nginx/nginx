---
name: nginx-build
description: >-
  Configure and build NGINX from this repository with auto/configure and make,
  including path options, optional HTTP/stream modules, OpenSSL/PCRE/zlib,
  static vs dynamic modules, and --add-module / --add-dynamic-module. Use when
  compiling NGINX, choosing configure flags, or debugging build failures.
---

# Building NGINX from source

Primary references in this tree: `auto/configure`, `auto/options`,
`auto/modules`, `auto/module`, and the README “Building from source” section.
Official option list: https://nginx.org/en/docs/configure.html.

## Workflow

From the repository root:

```bash
auto/configure [options]
make
# optional install into prefix (default /usr/local/nginx):
sudo make install
```

`auto/configure` writes `Makefile` and `objs/` (including `objs/ngx_auto_config.h`
and the binary at `objs/nginx` after `make`). Re-run `auto/configure` after
changing flags; then `make`.

Minimal dependencies on Debian/Ubuntu-style systems (from README): `gcc`,
`make`, `libpcre3-dev`, `zlib1g-dev`. Add `libssl-dev` when enabling SSL/HTTP/3.

## Path and layout options (`auto/options`)

Common install-layout flags:

| Flag | Purpose |
| --- | --- |
| `--prefix=PATH` | Installation prefix |
| `--sbin-path=PATH` | nginx binary path |
| `--modules-path=PATH` | Dynamic modules directory |
| `--conf-path=PATH` | Default `nginx.conf` |
| `--error-log-path=PATH` | Default error log |
| `--pid-path=PATH` | PID file |
| `--lock-path=PATH` | Lock file |
| `--http-log-path=PATH` | Default access log |
| `--http-client-body-temp-path=PATH` | Client body temp |
| `--http-proxy-temp-path=PATH` | Proxy temp |
| `--with-cc-opt=...` / `--with-ld-opt=...` | Extra compiler/linker flags |

## Feature toggles (verify against `auto/options`)

Often enabled for modern builds:

- `--with-http_ssl_module` — `ngx_http_ssl_module`
- `--with-http_v2_module` — HTTP/2
- `--with-http_v3_module` — HTTP/3 / QUIC
- `--with-http_realip_module` — real client IP from proxy headers
- `--with-stream` / `--with-stream=dynamic` — TCP/UDP proxy
- `--with-stream_ssl_module`, `--with-stream_ssl_preread_module`
- `--with-threads` — thread pools
- `--with-file-aio` — file AIO
- `--with-pcre=DIR` / `--with-pcre-jit` — PCRE from source / JIT
- `--with-openssl=DIR` — build against OpenSSL sources
- `--with-debug` — debug logging support
- `--without-http` / `--without-http-cache` — strip HTTP (or cache)

Many HTTP modules are on by default and disabled with `--without-http_*_module`
(examples: `rewrite`, `proxy`, `fastcgi`, `gzip`, `map`, `limit_req`). Optional
modules use `--with-http_*_module` (examples: `ssl`, `v2`, `v3`, `xslt`,
`image_filter`, `geoip`, `perl`, `auth_request`). Always confirm the exact flag
spelling in `auto/options` rather than guessing.

Example feature-rich configure line:

```bash
auto/configure \
  --prefix=/usr/local/nginx \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_v3_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-threads \
  --with-file-aio
```

## Third-party and dynamic modules

From `auto/options` / `auto/module`:

- `--add-module=PATH` — link an external module statically
- `--add-dynamic-module=PATH` — build a loadable module (`.so` under
  `objs/` / `--modules-path`)

External modules supply a `config` script that sets `ngx_addon_name`,
`ngx_module_type`, `ngx_module_name`, `ngx_module_srcs`, and optionally
`ngx_module_libs` / `ngx_module_incs`. `auto/module` honors
`ngx_module_link=YES` (static) vs `DYNAMIC`.

Built-in modules can also be dynamic when the option accepts `=dynamic`
(for example `--with-stream=dynamic`, `--with-http_image_filter_module=dynamic`
where supported).

At runtime, dynamic modules are loaded from the main context with
`load_module` (`src/core/nginx.c`), for example:

```nginx
load_module modules/ngx_http_image_filter_module.so;
```

## Checking the build

```bash
objs/nginx -V          # configure arguments and compiler
objs/nginx -t -c conf/nginx.conf
make -j"$(nproc)"
```

If configure fails, read the error and `objs/autoconf.err` when present; missing
headers usually mean install the matching `-dev` package or pass
`--with-cc-opt=-I...` / library source paths (`--with-openssl`, `--with-pcre`,
`--with-zlib`).

## Agent guidance

- Prefer flags that exist verbatim in `auto/options`; do not invent synonyms
- SSL/HTTP/2/HTTP/3 are **off** by default (`HTTP_SSL=NO`, `HTTP_V2=NO`,
  `HTTP_V3=NO` in `auto/options`) — enable explicitly
- Changing modules requires reconfigure + rebuild; binary modules must match
  the nginx build they load into
- Keep build instructions reproducible: record the full `auto/configure` line
  in PR/commit notes when the change depends on non-default modules
