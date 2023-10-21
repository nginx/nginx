FROM ubuntu:latest

# Env vars
ENV DEBIAN_FRONTEND=noninteractive

# Package updates and install packages
RUN apt-get update \
    && apt-get -y install \
    gcc \
    make \
    libpcre3 libpcre3-dev \
    zlib1g zlib1g-dev \
    openssl libssl-dev
