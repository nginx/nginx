# Docker / local dev

Run NGINX in Docker Compose for local development.

## What it does

- Starts the official `nginx:alpine` image with the local `nginx.conf`
  and `html/` directory mounted read-only.
- Exposes the site on http://localhost:8080.

## Run locally

```sh
mkdir -p html
echo '<h1>Hello from Docker Compose</h1>' > html/index.html

docker compose up
```

Edit `html/index.html` and refresh — static files are served from the
mounted directory, so no restart is needed. After changing
`nginx.conf`, reload NGINX:

```sh
docker compose exec web nginx -s reload
```

Stop with `Ctrl+C` or `docker compose down`.

## Notes

- Mounting configs read-only (`:ro`) prevents accidental edits from
  inside the container.
- To validate a config change before reloading:
  `docker compose exec web nginx -t`
- The other examples in this repository can be run the same way: mount
  their `nginx.conf` into the container as `/etc/nginx/nginx.conf`.

## Learn more

- https://hub.docker.com/_/nginx
