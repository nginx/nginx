# PHP-FPM

Serve a PHP application through PHP-FPM.

## What it does

- Serves static files directly and passes `.php` requests to PHP-FPM.
- Uses `try_files $uri =404` inside the PHP block so non-existent
  `.php` paths never reach PHP-FPM (a classic security pitfall).
- Falls back to `index.php` for clean URLs, as front-controller
  frameworks (Laravel, Symfony, WordPress) expect.
- Blocks hidden files.

## Run locally

The easiest reproducible setup is two containers sharing the document
root:

```sh
mkdir -p html
echo '<?php phpinfo();' > html/index.php

docker network create php-demo

docker run -d --rm --name fpm --network php-demo \
    -v "$PWD/html:/usr/share/nginx/html:ro" \
    php:fpm-alpine

docker run -d --rm --name web --network php-demo -p 8080:8080 \
    -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/html:/usr/share/nginx/html:ro" \
    nginx:alpine
```

Since PHP-FPM runs in a separate container here, change `fastcgi_pass`
in `nginx.conf` from `127.0.0.1:9000` to `fpm:9000` (the container
name). Then open http://localhost:8080.

Cleanup:

```sh
docker stop web fpm && docker network rm php-demo
```

## Notes

- On a single host (no containers), prefer the Unix socket:
  `fastcgi_pass unix:/run/php/php-fpm.sock;` — check your distro's
  PHP-FPM pool config (`listen = ...`) for the exact path.
- Both containers must mount the same document root, because PHP-FPM
  reads the script from disk itself.

## Learn more

- https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html
- https://www.php.net/manual/en/install.fpm.php
