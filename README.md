
# NGINX
NGINX (pronounced "engine x" or "en-jin-eks") is the world's most popular Web Server, as well as a powerful, high performance Load Balancer, Reverse Proxy, API Gateway and Content Cache.

NGINX is free and open source software, distributed under the terms of a simplified [2-clause BSD-like license](LICENSE.md).

A commercial version, [NGINX Plus](https://www.f5.com/products/nginx/nginx-plus), with additional enterprise features and support, is available from [F5, Inc](https://www.f5.com/).

# Table of contents
- [How it works](#how-it-works)
  - [Modules](#modules)
  - [Configurations](#configurations)
  - [Runtime](#runtime)
- [Downloading and installing](#downloading-and-installing)
- [Getting started with NGINX](#getting-started-with-nginx)
- [Building from source](#building-from-source)
- [Technical specifications](#technical-specifications)
- [Asking questions, reporting issues, and contributing](#asking-questions-reporting-issues-and-contributing)
- [Changelog](#changelog)
- [License](#license)

# How it works
NGINX is installed software with binary packages available for all major operating systems and Linux distributions. See [Tested OS and Platforms](https://nginx.org/en/#tested_os_and_platforms) for a full list of compatible systems.

> [!IMPORTANT]
> While nearly all popular Linux-based operating systems are distributed with a community version of nginx, we highly advise installation and usage of official [packages](https://nginx.org/en/linux_packages.html) or sources from this repository. Doing so ensures that you're using the most recent release or source code, including the latest feature-set, fixes and security patches.

## Modules
NGINX is comprised of individual modules, each extending core functionality by providing additional, configurable features. See "Modules reference" at the bottom of [nginx documentation](https://nginx.org/en/docs/) for a complete list of native modules.

NGINX supports static and dynamic modules. Static modules are defined at build-time and compiled into the resulting binaries. Dynamic modules (eg. njs) are built and distributed separately. They can be added to, or removed from, an NGINX installation at any time.

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

# Getting started with NGINX

# Building from source

# Technical specifications

# Asking questions, reporting issues, and contributing

# Changelog
See our [changelog](https://nginx.org/en/CHANGES) to keep track of updates.

# License
[2-clause BSD-like license](LICENSE)

---
Additional documentation available at: https://nginx.org/en/docs

©2024 F5, Inc. All rights reserved.
https://www.f5.com/products/nginx
