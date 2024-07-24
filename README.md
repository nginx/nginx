![NGINX Banner](docs/img/logo.png "NGINX Banner")

NGINX (pronounced "engine x" or "en-jin-eks") is the world's most popular Web Server, high performance Load Balancer, Reverse Proxy, API Gateway and Content Cache.

NGINX is free and open source software, distributed under the terms of a simplified [2-clause BSD-like license](LICENSE.md).

A commercial version, [NGINX Plus](https://www.f5.com/products/nginx/nginx-plus), with additional enterprise features and support, is available from [F5, Inc](https://www.f5.com/).

> [!IMPORTANT]
> The goal of this README is to provide a basic, structured introduction to NGINX for novice users. Please refer to the [full NGINX documentation](https://nginx.org/en/docs/) for detailed information on [installing](https://nginx.org/en/docs/install.html), [building](https://nginx.org/en/docs/configure.html), [configuring](https://nginx.org/en/docs/dirindex.html), [debugging](https://nginx.org/en/docs/debugging_log.html), etc... These documentation pages also contain a more detailed [Beginners Guide](https://nginx.org/en/docs/beginners_guide.html), How-Tos, [Development guides](https://nginx.org/en/docs/dev/development_guide.html), and a complete module and [directive reference](https://nginx.org/en/docs/dirindex.html).

# Table of contents
- [How it works](#how-it-works)
  - [Modules](#modules)
  - [Configurations](#configurations)
  - [Runtime](#runtime)
- [Downloading and installing](#downloading-and-installing)
  - [Stable and Mainline binaries](#stable-and-mainline-binaries)
  - [Linux binary installation process](#linux-binary-installation-process)
  - [FreeBSD installation process](#freebsd-installation-process)
  - [Windows executables](#windows-executables)
  - [Dynamic modules](#dynamic-modules)
- [Getting started with NGINX](#getting-started-with-nginx)
  - [Installing SSL certificates and enabling TLS encryption](#installing-ssl-certificates-and-enabling-tls-encryption)
  - [Load Balancing](#load-balancing)
  - [Rate limiting](#rate-limiting)
  - [Content caching](#content-caching)
- [Building from source](#building-from-source)
- [Technical specifications](#technical-specifications)
- [Asking questions and reporting issues](#asking-questions-reporting-issues-and-contributing)
- [Contributing code](#contributing-code)
- [Additional help and resources](#additional-help-and-resources)
- [Changelog](#changelog)
- [License](#license)

# How it works
NGINX is installed software with binary packages available for all major operating systems and Linux distributions. See [Tested OS and Platforms](https://nginx.org/en/#tested_os_and_platforms) for a full list of compatible systems.

> [!IMPORTANT]
> While nearly all popular Linux-based operating systems are distributed with a community version of nginx, we highly advise installation and usage of official [packages](https://nginx.org/en/linux_packages.html) or sources from this repository. Doing so ensures that you're using the most recent release or source code, including the latest feature-set, fixes and security patches.

## Modules
NGINX is comprised of individual modules, each extending core functionality by providing additional, configurable features. See "Modules reference" at the bottom of [nginx documentation](https://nginx.org/en/docs/) for a complete list of native modules.

NGINX supports static and dynamic modules. Static modules are defined at build-time and compiled into the resulting binaries. Dynamic modules (eg. [njs](https://github.com/nginx/njs)) are built and distributed separately. They can be added to, or removed from, an NGINX installation at any time.

> [!IMPORTANT]
> Official NGINX package distributions are built with all native open-source static modules.

## Configurations
NGINX is highly flexible and configurable. Provisioning the software is achieved via text-based config file(s) organized in functional sections called "Contexts", accepting a vast amount of configuration parameters called "[Directives](https://nginx.org/en/docs/dirindex.html)". See [Configuration File's Structure](https://nginx.org/en/docs/beginners_guide.html#conf_structure) for a comprehensive definition of Directives and Contexts.

> [!NOTE]
> The set of directives available to your distribution of NGINX is dependent on which [modules](#modules) have been made available to it.

## Runtime
Rather than running in a single, monolithic processes, NGINX is architected to scale beyond OS process stack limitations. To achieve this, the software operates as a collection of processes that include:
- A "master" process that maintains worker processes, as well as, reads and evaluates configuration files.
- One or more "worker" processes that process data (eg. HTTP requests).

By default, the number of [worker processes](https://nginx.org/en/docs/ngx_core_module.html#worker_processes) is set to equal the number of CPU cores on the system. In most cases, this optimally balances load across available system resources, as NGINX is designed to efficiently distribute work across all available worker processes.

> [!TIP]
> Processes synchronize data through shared memory. For this reason, many NGINX directives require the allocation of shared memory zones. As an example, when configuring [rate limiting](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req), connecting clients must be tracked in a [common memory zone](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req_zone) so all worker processes can know how many times a particular client has accessed the server in a span of time.

# Downloading and installing
Follow these steps to download and install precompiled NGINX binaries. You may also choose to [build the module locally from source code](#building-from-source).

## Stable and Mainline binaries
NGINX binaries are built and distributed in two versions. You'll need to decide which is appropriate for your purposes.

### Mainline builds 
Contain the latest features and bug fixes and are always up to date. However, they may include experimental modules and/or features which introduce new defects.

### Stable builds
May not contain all of the latest modules and/or features, but do include all of the latest critical bug and security patches, which are ported from the mainline version. We recommend the stable version for production servers.

## Linux binary installation process
NGINX binary installation process takes advantage of package managers native to specific Linux distributions. For this reason, first-time installations involve adding the official NGINX package repository to the package manager.

### GPG keys
GPG signing keys are used to verify the authenticity of packages. Read more [important details](https://nginx.org/en/linux_packages.html#signatures) on our GPG/PGP keys.

### Upgrades
Future upgrades to the latest version can be managed using the same package manager without the need to manually download and authenticate binaries.

### Installation instructions
Once a repository has been added and authenticated, follow [these steps](https://nginx.org/en/linux_packages.html) to install NGINX binaries using the package manager native to your Linux distribution.

## FreeBSD installation process
For more information on installing NGINX on FreeBSD system, visit https://nginx.org/en/docs/install.html

## Windows executables
Windows executables for mainline and stable versions can be found on the main [NGINX download page](https://nginx.org/en/download.html).

## Dynamic modules
NGINX version 1.9.11 added support for [Dynamic Modules](https://nginx.org/en/docs/ngx_core_module.html#load_module). Unlike standard, Static modules, which must be complied into NGINX binaries at build-time, Dynamic modules can be downloaded, installed, and configured at any point. [Official dynamic module binaries](https://nginx.org/en/linux_packages.html#dynmodules) are available from the same package repository as the core NGINX binaries described in previous steps.

> [!TIP]
> [NGINX JavaScript (NJS)](https://github.com/nginx/njs), is a popular NGINX dynamic module that enables the extension of core NGINX functionality using familiar JavaScript syntax.

# Getting started with NGINX
For a gentle introduction to NGINX basics, please see our [Beginner’s Guide](https://nginx.org/en/docs/beginners_guide.html)

## Installing SSL certificates and enabling TLS encryption
See [Configuring HTTPS servers](https://nginx.org/en/docs/http/configuring_https_servers.html) for a quick guide on how to enable secure traffic to your NGINX installation.

## Load Balancing
For a quick start guide on configuring NGINX as a Load Balancer, please see [Using nginx as HTTP load balancer](https://nginx.org/en/docs/http/load_balancing.html)

## Rate limiting
See our [Rate Limiting with NGINX](https://blog.nginx.org/blog/rate-limiting-nginx) blog post for an overview of a core concept of provisioning NGINX as an API Gateway

## Content caching
See [A Guide to Caching with NGINX and NGINX Plus](https://blog.nginx.org/blog/nginx-caching-guide) blog post for an overview of how to use NGINX as a content cache (eg. edge server of a content delivery network).

# Building from source

# Technical specifications

# Asking questions and reporting issues
We encourage you to engage with us.
- [NGINX GitHub Discussions](https://github.com/nginx/nginx/discussions), is the go-to place to start asking questions and sharing your thoughts.
- Our [GitHub Issues](https://github.com/nginx/nginx/issues) page offers space to submit and discuss specific issues

# Contributing code 
Please see the [Contributing](CONTRIBUTING.md) guide for information on how to contribute code.

# Additional help and resources
- See the [NGINX Community Blog](https://blog.nginx.org/) for more tips, tricks and HOW-TOs related to NGINX and related projects.
- Access [nginx.org](https://nginx.org/), your go-to source for all documentation, information and software related to the NGINX suite of projects.

# Changelog
See our [changelog](https://nginx.org/en/CHANGES) to keep track of updates.

# License
[2-clause BSD-like license](LICENSE)

---
Additional documentation available at: https://nginx.org/en/docs

©2024 F5, Inc. All rights reserved.
https://www.f5.com/products/nginx
