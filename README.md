<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/9335b488-ffcc-4157-8364-2370a0b70ad0">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/3a7eeb08-1133-47f5-859c-fad4f5a6a013">
  <img alt="nginx Banner">
</picture>

# Table of contents
- [Overview](#overview)
- [Documentation](#documentation)
- [Installation](#installation)
  - [Stable and mainline versions](#stable-and-mainline-versions)
  - [Prebuilt binary package](#prebuilt-binary-package)
  - [Building from source](#building-from-source)
- [Windows](#windows)
- [Support](#support)
- [Contributing](#contributing)
- [Security](#security)
- [Changelog](#changelog)
- [License](#license)

# Overview
nginx ("<i>engine x</i>") is an HTTP web server, reverse proxy,
content cache, load balancer, TCP/UDP proxy server, and mail proxy server.
Known for flexibility and high performance with low resource utilization.
Originally written by [Igor Sysoev](http://sysoev.ru/en/).

nginx runs on most popupar [operating systems](https://nginx.org/en/#tested_os_and_platforms).

The official home page of the nginx project is [nginx.org](https://nginx.org).

# Documentation
Reference documentation is available at: https://nginx.org/en/docs.

# Installation
nginx can be installed in [various ways](https://nginx.org/en/docs/install.html)
depending on your requirement.

## Stable and mainline versions
nginx is available in two versions:
- **mainline** includes the latest features and bug fixes and is always up to date
- **stable** doesn’t include all of the latest features, but has critical bug fixes that are always backported from the mainline version

## Prebuilt binary package
This is a quick and easy way to install nginx.
The package includes almost all official nginx modules and is available
for most popular operating systems.
See [Installing a Prebuilt Package](http://nginx.org/en/linux_packages.html).

## Building from source
This way is more flexible: you can add particular modules, including
third‑party modules, or apply the latest security patches.

### Building from source tarballs
Official nginx tarballs: https://nginx.org/en/download.html.
```bash
tar xf nginx-1.X.Y.tar.gz
cd nginx-1.X.Y
./configure ...
make
```

See [configure options](https://nginx.org/en/docs/configure.html).

### Building from source repository
```bash
git clone https://github.com/nginx/nginx.git
cd nginx
auto/configure ...
make
```

See [configure options](https://nginx.org/en/docs/configure.html).

# Windows
[Windows executables](https://nginx.org/en/download.html) are tested
on Windows XP, Windows Server 2003, Windows 7, Windows 10.
Note that nginx for Windows is considered to be of a
[beta](http://nginx.org/en/docs/windows.html) quality and should only
be used for development and testing purposes.

# Support
Enterprise distributions, commercial support and training are
available from [F5, Inc](https://www.f5.com/products/nginx).

# Contributing
We encourage you to engage with us.

- [GitHub Issues](https://github.com/nginx/nginx/issues)
offers space to report specific issues, bugs, and suggest enhancements
- [GitHub Pull Requests](https://github.com/nginx/nginx/pulls)
offers space to contribute your changes
- [GitHub Discussions](https://github.com/nginx/nginx/discussions)
is the go-to place to start asking questions and sharing your thoughts

See [Contributing Guidelines](CONTRIBUTING.md) for information on how
to participate in nginx development.

# Security
See [Security Policy](SECURITY.md) for information on how to report
a vulnerability.

# Changelog
See [CHANGES](https://nginx.org/en/CHANGES) to keep track of updates.

# License
nginx is distributed under the terms of the simplified
[2-clause BSD-like license](LICENSE).
