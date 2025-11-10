# Small, production-ready base with NGINX pre-installed
FROM nginx:stable-alpine

# Build-time args (populated from your Build & Push step)
ARG IMAGE_TAG
ARG BUILD_COMMIT_SHA

# Optional: surface build args as env/labels for traceability
ENV IMAGE_TAG="${IMAGE_TAG}" \
    BUILD_COMMIT_SHA="${BUILD_COMMIT_SHA}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT_SHA}" \
      org.opencontainers.image.version="${IMAGE_TAG}"

# If your repo has static site files, copy them to the default NGINX root.
# Remove/change this line if you don't want to serve repo files.
COPY . /usr/share/nginx/html

# NGINX base image already exposes 80 and sets entrypoint/cmd
EXPOSE 80
