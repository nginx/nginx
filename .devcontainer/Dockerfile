FROM centos:8

RUN dnf -y update && \
    dnf -y install epel-release dnf-plugins-core && \
    dnf config-manager --set-enabled powertools

RUN dnf -y install gcc-c++ pcre pcre-devel zlib zlib-devel make openssl openssl-devel

RUN dnf clean all
