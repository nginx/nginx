---
name: nginx-modules
description: >-
  Develop or review NGINX C modules using the Development Guide, src/ layout,
  ngx_module_t / ngx_command_t patterns, HTTP phases, configuration merging,
  and code style from in-tree modules. Use when adding handlers, filters,
  directives, or third-party module config scripts.
---

# Developing NGINX modules

Authoritative guide: https://nginx.org/en/docs/dev/development_guide.html
Match style and structure to existing modules under `src/` rather than
introducing foreign abstractions.

## Source layout

| Path | Role |
| --- | --- |
| `src/core/` | Core types, cycle, log, conf parser (`ngx_conf_file.*`) |
| `src/event/` | Event loop, connections; OpenSSL glue; `quic/` |
| `src/http/` | HTTP core (`ngx_http_core_module.*`, request, upstream) |
| `src/http/modules/` | Built-in HTTP modules (proxy, ssl, rewrite, …) |
| `src/http/v2/`, `src/http/v3/` | HTTP/2 and HTTP/3 implementations |
| `src/stream/` | TCP/UDP stream proxy modules |
| `src/mail/` | Mail proxy modules |
| `src/os/` | OS-specific code |

Study a small complete example such as
`src/http/modules/ngx_http_access_module.c` before scaffolding a new module.

## Module anatomy

An HTTP module typically defines:

1. **`ngx_command_t` array** — directive names, context flags, argument counts
   (`NGX_CONF_TAKE1`, `NGX_CONF_FLAG`, `NGX_CONF_BLOCK`, …), set handler, and
   conf offset. Terminate with `ngx_null_command`.
2. **`ngx_http_module_t` context** — optional `preconfiguration` /
   `postconfiguration`, and create/merge callbacks for main/server/location
   conf.
3. **`ngx_module_t`** — `NGX_MODULE_V1`, module context, commands,
   `NGX_HTTP_MODULE` type, init/exit hooks as needed, `NGX_MODULE_V1_PADDING`.

Context flags on commands must match where the directive is legal, e.g.
`NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF`.

Configuration structs are allocated in `create_*_conf`, defaulted with
`NGX_CONF_UNSET` / `NGX_CONF_UNSET_PTR`, and combined in `merge_*_conf` via
helpers like `ngx_conf_merge_value` / `ngx_conf_merge_ptr_value`.

## HTTP request phases

Handlers register into phases during `postconfiguration` (see access module’s
`ngx_http_access_init`). Important phases include
`NGX_HTTP_SERVER_REWRITE_PHASE`, `NGX_HTTP_REWRITE_PHASE`,
`NGX_HTTP_ACCESS_PHASE`, `NGX_HTTP_CONTENT_PHASE`, and filter chains for
output. Return `NGX_OK`, `NGX_DECLINED`, `NGX_ERROR`, or an HTTP status as
appropriate; use `NGX_DECLINED` when not handling the request.

Content handlers often set `clcf->handler` for a location. Filters chain
through `ngx_http_top_body_filter` / header filter pointers.

## Memory, strings, and logging

- Allocate from the request or connection pool (`r->pool`, `cf->pool`); do not
  `free` pool memory manually
- NGINX strings are `ngx_str_t` (`data` + `len`), not always NUL-terminated
- Use `ngx_log_error` / `ngx_log_debug*` with the connection or cycle log
- Prefer existing helpers (`ngx_pnalloc`, `ngx_pcalloc`, `ngx_snprintf`,
  `ngx_strcasecmp`) over libc equivalents when in-tree code does

## Code style (Development Guide + surrounding code)

- K&R-ish C style matching neighboring files: 4-space indent, spaces around
  operators, `/* */` comments with copyright headers
- Keep lines readable; follow patterns in the file you edit
- Typedefs end with `_t`; macros often `NGX_` / `ngx_`
- Avoid C++ comments; avoid unnecessary `#ifdef` layers
- New files need the standard copyright banner used in this repo

## Wiring a new in-tree or external module

**In-tree:** add sources under the right `src/` tree and register them in
`auto/modules` / related auto scripts as existing modules do.

**External:** provide a `config` shell snippet setting at least:

```bash
ngx_addon_name=ngx_http_example_module
ngx_module_type=HTTP
ngx_module_name=ngx_http_example_module
ngx_module_srcs="$ngx_addon_dir/ngx_http_example_module.c"
. auto/module
```

Build with `--add-module=/path/to/module` or
`--add-dynamic-module=/path/to/module` (see the `nginx-build` skill). Dynamic
modules are loaded with `load_module` in `nginx.conf`.

`ngx_module_type` values include `HTTP`, `HTTP_FILTER`, `HTTP_AUX_FILTER`,
`STREAM`, `MAIL`, `CORE`, etc., as consumed by `auto/module`.

## Review checklist

- Directive names and contexts match `ngx_command_t` flags
- create/merge conf handle `NGX_CONF_UNSET*` correctly
- Phase handler or filter registration is idempotent and ordered correctly
- No blocking syscalls on the event loop without thread pool / AIO patterns
- Style matches adjacent modules; builds with `auto/configure && make`
- Tests added or updated under https://github.com/nginx/nginx-tests when
  behavior is user-visible
