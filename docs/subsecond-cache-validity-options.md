# Sub-second cache validity – implementation options

This document summarizes how cache validity (TTL) is implemented today and lists the **simplest implementation options** for sub-second precision (e.g. 100 ms for 10 Hz API proxy), as requested in [nginx/nginx#1156](https://github.com/nginx/nginx/issues/1156) and [trac #1505](https://trac.nginx.org/nginx/ticket/1505#no1).

## Tests and documentation (for contributors)

- **Tests:** A regression test for sub-second cache validity is provided in `contrib/nginx-tests/proxy_cache_valid_subsecond.t`. It is intended to be run from the [nginx-tests](https://github.com/nginx/nginx-tests) repository (copy the `.t` file to the nginx-tests root and run `prove proxy_cache_valid_subsecond.t`). Adding this test (or equivalent) to nginx-tests is recommended so that the behavior is enforced and regressions are avoided. See CONTRIBUTING.md: *"Passing your changes through the test suite is a good way to ensure that they do not cause a regression."*
- **Changelog:** A feature entry has been added to `docs/xml/nginx/changes.xml` for the new "ms" suffix in `proxy_cache_valid`, `fastcgi_cache_valid`, `scgi_cache_valid`, and `uwsgi_cache_valid`.
- **Directive reference:** The official directive reference is maintained at [nginx.org](https://nginx.org/en/docs/). When this feature is merged, the docs for the above directives should mention that the time parameter accepts an optional `ms` suffix for millisecond precision (e.g. `100ms`).

---

## Current implementation (seconds only)

### Config and types

- **Directives:** `proxy_cache_valid`, `fastcgi_cache_valid`, `scgi_cache_valid`, `uwsgi_cache_valid` all use the same implementation.
- **Config type:** `ngx_http_cache_valid_t` in `src/http/ngx_http_cache.h`:
  - `ngx_uint_t status` (HTTP status or 0 for “any”)
  - `time_t valid` — **duration in seconds only**
- **Parsing:** `ngx_http_file_cache_valid_set_slot()` in `src/http/ngx_http_file_cache.c` calls `ngx_parse_time(&value[n], 1)`. The second argument `1` means “parse as seconds” (no `ms` suffix; see `src/core/ngx_parse.c`).

### Where validity is stored and used

- **In-memory:** `ngx_http_cache_t` has `time_t valid_sec` (absolute expiry) and **`ngx_uint_t valid_msec`** (already present, but never set from config).
- **On-disk header:** `ngx_http_file_cache_header_t` has `time_t valid_sec` and **`u_short valid_msec`** — both already exist.
- **Shared memory node:** `ngx_http_file_cache_node_t` has `time_t valid_sec` and **`valid_msec:10`** (bitfield, 0–1023 ms) — both already exist.

So **sub-second storage (valid_msec) is already in place**; it is just never populated from the config path and expiration is only compared in seconds.

### Expiration check (seconds only)

- **Primary check** in `ngx_http_file_cache.c` (around 654–656):
  - `now = ngx_time();`  // seconds only
  - `if (c->valid_sec < now)` → expired. `valid_msec` is not used.
- **Node lookup** (around 904): `if (fcn->valid_sec < ngx_time())` — again seconds only.

### Where `valid_sec` is set from config

All go through `ngx_http_file_cache_valid(cache_valid, status)`, which returns a **duration in seconds** (`time_t`). Call sites then set absolute expiry as `valid_sec = ngx_time() + valid` (and never set `valid_msec`):

- `src/http/ngx_http_upstream.c`:
  - ~2876, ~2974 (revalidate path)
  - ~3413 (after upstream response)
  - ~4857 (error path: 502/504)
- **Other headers:** `Cache-Control` max-age, `X-Accel-Expires`, `Expires` also set `valid_sec` only (seconds); sub-second support there is optional and can be done later.

### Time API

- `ngx_time()` → seconds only (`ngx_cached_time->sec`).
- `ngx_timeofday()` → `ngx_time_t *` with **`.sec` and `.msec`** — suitable for sub-second expiry and comparison.

---

## Simplest implementation options (ordered)

### Option 1: Config stores ms; API returns (sec, msec) — minimal surface (recommended baseline)

**Idea:** Keep a single “duration” in the config, but allow it to be specified in milliseconds when &lt; 1 s (e.g. `100ms`, `0.5s`), and feed the existing `valid_sec` + `valid_msec` storage and comparison.

**Changes:**

1. **Config**
   - Extend `ngx_http_cache_valid_t` with **`ngx_uint_t valid_msec`** (default 0).
   - In `ngx_http_file_cache_valid_set_slot()`:
     - Try parsing with **`ngx_parse_time(..., 0)`** (milliseconds). If the string looks like a “ms” duration (e.g. contains `ms` or numeric value &lt; 1000 with optional `s`), use that and set `v->valid = 0`, `v->valid_msec = result` (capped at 999).
     - Otherwise keep current behavior: **`ngx_parse_time(..., 1)`** and set `v->valid = result`, `v->valid_msec = 0`.
   - Alternatively: always parse with `is_sec=0` and support both `100ms` and `1s` (then `valid = total_ms / 1000`, `valid_msec = total_ms % 1000`). Requires deciding how “bare” numbers are interpreted (current: minutes with `is_sec=1`).

2. **Lookup API**
   - Change **`ngx_http_file_cache_valid()`** to either:
     - Return duration in seconds and add **`ngx_http_file_cache_valid_msec(cache_valid, status)`** returning msec, or
     - Replace with **`void ngx_http_file_cache_valid_ex(cache_valid, status, time_t *valid_sec, ngx_uint_t *valid_msec)`** and update the 4 call sites in `ngx_http_upstream.c` to pass two out-params and set both `r->cache->valid_sec` and `r->cache->valid_msec`.

3. **Setting expiry**
   - At each place that currently does `valid_sec = ngx_time() + valid`:
     - Get **`tp = ngx_timeofday()`**.
     - Compute expiry in (sec, msec): e.g. `valid_sec = tp->sec + valid_sec + (tp->msec + valid_msec) / 1000`, `valid_msec = (tp->msec + valid_msec) % 1000`.
   - Set **`r->cache->valid_sec`** and **`r->cache->valid_msec`**.

4. **Expiration comparison**
   - In **`ngx_http_file_cache.c`** (and any other place that compares with `ngx_time()`):
     - Replace `if (c->valid_sec < now)` with a helper that compares `(c->valid_sec, c->valid_msec)` to `(tp->sec, tp->msec)` (e.g. “expired if valid_sec < sec, or valid_sec == sec && valid_msec < msec”).
   - Same for **`fcn->valid_sec < ngx_time()`** in the node path: compare using `(fcn->valid_sec, fcn->valid_msec)` vs `ngx_timeofday()`.

5. **Header/node**
   - No struct or version change: `valid_msec` is already in the header and node. Old cache files have `valid_msec == 0`, which remains correct for second-granularity expiry.

**Pros:** Reuses existing `valid_msec` everywhere; small, localized changes.  
**Cons:** Need to define syntax (e.g. `100ms` vs `0.1s`) and possibly bump cache version if semantics of `valid_msec` are ever extended.

---

### Option 2: New directive for ms only (e.g. `proxy_cache_valid_ms`)

**Idea:** Add a separate directive that takes only a millisecond value (e.g. `proxy_cache_valid_ms 200 100`) so that existing `proxy_cache_valid` is untouched and no parsing ambiguity.

**Changes:**

- New directive (e.g. `proxy_cache_valid_ms`) that accepts the same status list but a **single numeric ms** value (or use `ngx_parse_time(..., 0)` and allow `100ms`).
- Store in a separate array or in the same `cache_valid` array with a “is_msec” flag or by overloading: e.g. when `valid == 0 && valid_msec > 0` treat as “valid for valid_msec milliseconds”.
- Same runtime changes as Option 1: set/compare using `valid_sec` + `valid_msec`, use `ngx_timeofday()` where needed.

**Pros:** No change to existing directive semantics or parsing.  
**Cons:** Two directives to maintain and document; config can be redundant (e.g. `1s` vs `1000ms`).

---

### Option 3: Single “duration in ms” in config (internal representation only)

**Idea:** Store cache validity as a single duration in milliseconds in config (e.g. `ngx_msec_t` or `ngx_uint_t`), and convert to (sec, msec) only when setting expiry.

**Changes:**

- Replace `time_t valid` in `ngx_http_cache_valid_t` by **`ngx_msec_t valid_ms`** (or keep both for backward compat and deprecate `valid`).
- **Parsing:** Always use `ngx_parse_time(..., 0)` and accept `100ms`, `1s`, `60s`, etc.; store result in `valid_ms`.
- **Lookup:** `ngx_http_file_cache_valid()` (or _ex) returns duration as (sec, msec) derived from `valid_ms`.
- Rest as in Option 1: set expiry from `ngx_timeofday()` + (sec, msec), compare using (valid_sec, valid_msec).

**Pros:** One internal representation; flexible syntax.  
**Cons:** Slightly larger change to config type and all code that reads `valid`; need to ensure all callers use the new (sec,msec) return.

---

### Option 4: Extend `ngx_parse_time()` to return sub-second when `is_sec=1`

**Idea:** Allow `ngx_parse_time(..., 1)` to accept an optional fractional part or `ms` suffix and return a value that encodes sub-second (e.g. in a larger type or as a struct). Then cache validity could stay “one value” from the parser’s point of view.

**Changes:**

- **`ngx_parse_time()`** in `src/core/ngx_parse.c`: when `is_sec=1`, allow optional `.NNN` or `ms` and return a type that can represent sub-second (e.g. `double` seconds, or a new struct, or a fixed-point value). This would affect **all** users of `ngx_parse_time(..., 1)` (e.g. resolver TTL, SSL session cache, various timeouts). So either:
  - Add a new function (e.g. `ngx_parse_time_ex()`) that returns (sec, msec), or
  - Limit the new syntax to cache valid only by not using this in the core parser and instead parsing in the cache module (e.g. “if string ends with ‘ms’, parse with is_sec=0 and convert”).

**Pros:** Consistent time format across the codebase if done in core.  
**Cons:** Touches core parsing and many callers; risk of breaking existing configs. Safer to keep sub-second parsing in the HTTP cache module only (as in Option 1).

---

## Recommendation

- **Option 1** is the smallest change that achieves sub-second cache validity: the storage (`valid_msec`) and types already exist; only config parsing, the lookup/setting API, and expiration comparison need to be updated. Supporting a syntax like `100ms` or `0.1s` (via existing or minimal parsing) keeps the surface small.
- **Option 2** is a good alternative if the project prefers not to change the behavior or syntax of existing directives at all.
- **Option 3** is a clean internal refactor but touches more code than Option 1.
- **Option 4** is the most invasive and is only worth considering if the goal is to add sub-second support to many directives at once; for cache validity alone, Option 1 or 2 is simpler.

---

## Files to touch (for Option 1)

| File | Change |
|------|--------|
| `src/http/ngx_http_cache.h` | Add `valid_msec` to `ngx_http_cache_valid_t`; optional new API for (sec, msec) lookup. |
| `src/http/ngx_http_file_cache.c` | Parse ms in `ngx_http_file_cache_valid_set_slot`; extend `ngx_http_file_cache_valid` (or add _ex) to return msec; set `valid_msec` when writing header/node; compare expiry using (valid_sec, valid_msec) vs `ngx_timeofday()`. |
| `src/http/ngx_http_upstream.c` | In all 4 places that call `ngx_http_file_cache_valid` and set `valid_sec`: use (sec, msec) and `ngx_timeofday()` to set both `r->cache->valid_sec` and `r->cache->valid_msec`. |
| `src/core/ngx_parse.c` | No change if “ms” is only parsed in cache module (e.g. by calling `ngx_parse_time(..., 0)` for ms and `..., 1` for seconds). |

No change to cache header version or on-disk layout is strictly required, since `valid_msec` is already present; only its meaning (and population from config) is extended.
