FROM debian:bookworm-slim

# Copy entire NGINX install directory
COPY ./nginx /usr/local/nginx

EXPOSE 80 443

# Use full path to NGINX binary and it will find its own config and logs
ENTRYPOINT ["/usr/local/nginx/sbin/nginx", "-g", "daemon off;"]
