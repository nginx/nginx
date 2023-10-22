FROM rockylinux/rockylinux:9.2

RUN dnf clean all && \
    dnf update -y && \
    dnf install -y \
    yum-utils \
    epel-release \
    ncurses \
    git \
    vim \
    tmux \
    gcc-c++ \
    make \
    pcre-devel \
    zlib-devel \
    openssl-devel \
    dnf-plugins-core \
    autoconf \
    automake \
    curl-devel \
    libtool \
    libxml2-devel \
    pkgconf \
    wget

# libzip-devel from Rocky CRB repository
RUN dnf config-manager --set-enabled crb && \
    dnf install -y libzip-devel

# enable devel repo and install devel packages
RUN dnf config-manager --set-enabled devel && \
    dnf install -y \
    lmdb-devel \
    yajl-devel \
    pcre-devel

# download and install the geoipupdate rpm 
RUN wget -O /tmp/geoipupdate.rpm https://github.com/maxmind/geoipupdate/releases/download/v6.0.0/geoipupdate_6.0.0_linux_amd64.rpm && \
    dnf install -y /tmp/geoipupdate.rpm

COPY stafford.sh /usr/local/bin/stafford.sh

ENTRYPOINT ["/usr/local/bin/stafford.sh"]

CMD ["/bin/bash"]
