FROM debian:trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential libpcre2-dev zlib1g-dev golang-go python3 perl \
        procps util-linux rsync git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /w
