# Start with a minimal base image
FROM debian:bullseye-slim

# Copy the Nginx binary from the build environment
# Ensure you have already compiled Nginx and have it in your host directory under /usr/local/nginx/sbin/nginx
COPY ./nginx /usr/local/bin/nginx

# Expose the required ports
EXPOSE 80 443

# Set the entrypoint and run Nginx in the foreground
ENTRYPOINT ["/usr/local/bin/nginx", "-g", "daemon off;"]
