FROM rockylinux/rockylinux:9.2

RUN dnf clean all && \
    dnf update -y && \
    dnf install -y \
    yum-utils \
    epel-release

RUN dnf update -y && \
    dnf install -y \
    git \
    vim \
    gcc-c++ \
    make \
    pcre-devel \
    zlib-devel \
    openssl-devel \
    dnf-plugins-core \
    autoconf \
    automake \
    curl-devel \
    libgeoip-devel \
    liblmdb-devel \
    libpcre++-devel \
    libtool \
    libxml2-devel \
    libyajl \
    pkgconf \
    wget
