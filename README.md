![NGINX Banner](docs/img/logo.png "NGINX Banner")

NGINX (pronounced "engine x" or "en-jin-eks") is the world's most popular Web Server, high performance Load Balancer, Reverse Proxy, API Gateway and Content Cache.

NGINX is free and open source software, distributed under the terms of a simplified [2-clause BSD-like license](LICENSE).

Enterprise distributions, commercial support and training are available from [F5, Inc](https://www.f5.com/products/nginx).

> [!IMPORTANT]
> The goal of this README is to provide a basic, structured introduction to NGINX for novice users. Please refer to the [full NGINX documentation](https://nginx.org/en/docs/) for detailed information on [installing](https://nginx.org/en/docs/install.html), [building](https://nginx.org/en/docs/configure.html), [configuring](https://nginx.org/en/docs/dirindex.html), [debugging](https://nginx.org/en/docs/debugging_log.html), and more. These documentation pages also contain a more detailed [Beginners Guide](https://nginx.org/en/docs/beginners_guide.html), How-Tos, [Development guide](https://nginx.org/en/docs/dev/development_guide.html), and a complete module and [directive reference](https://nginx.org/en/docs/dirindex.html).

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
  - [Installing dependencies](#installing-dependencies)
  - [Cloning the NGINX GitHub repository](#cloning-the-nginx-github-repository)
  - [Configuring the build](#configuring-the-build)
  - [Compiling](#compiling)
  - [Location of binary and installation](#location-of-binary-and-installation)
  - [Running and testing the installed binary](#running-and-testing-the-installed-binary)
- [Technical specifications](#technical-specifications)
  - [Supported distributions](#supported-distributions)
  - [Windows](#windows)
  - [Supported deployment environments](#supported-deployment-environments)
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

NGINX supports static and dynamic modules. Static modules are defined at build-time and compiled into the resulting binaries. [Dynamic modules](https://nginx.org/en/linux_packages.html#dynmodules) (for example, [njs](https://github.com/nginx/njs)) are built and distributed separately. They can be added to, or removed from, an NGINX installation at any time.

> [!IMPORTANT]
> Official NGINX package distributions are built with all native open source static modules.

## Configurations
NGINX is highly flexible and configurable. Provisioning the software is achieved via text-based config file(s) organized in functional sections called "Contexts", accepting a vast amount of configuration parameters called "[Directives](https://nginx.org/en/docs/dirindex.html)". See [Configuration File's Structure](https://nginx.org/en/docs/beginners_guide.html#conf_structure) for a comprehensive definition of Directives and Contexts.

> [!NOTE]
> The set of directives available to your distribution of NGINX is dependent on which [modules](#modules) have been made available to it.

## Runtime
Rather than running in a single, monolithic process, NGINX is architected to scale beyond OS process stack limitations by operating as a collection of processes. They include:
- A "master" process that maintains worker processes, as well as, reads and evaluates configuration files.
- One or more "worker" processes that process data (eg. HTTP requests).

The number of [worker processes](https://nginx.org/en/docs/ngx_core_module.html#worker_processes) is typically set to the number of CPU cores on the system. In most cases, this optimally balances load across available system resources, as NGINX is designed to efficiently distribute work across all available worker processes.

> [!TIP]
> Processes synchronize data through shared memory. For this reason, many NGINX directives require the allocation of shared memory zones. As an example, when configuring [rate limiting](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req), connecting clients must be tracked in a [common memory zone](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req_zone) so all worker processes can know how many times a particular client has accessed the server in a span of time.

# Downloading and installing
Follow these steps to download and install precompiled NGINX binaries. You may also choose to [build the module locally from source code](#building-from-source).

## Stable and Mainline binaries
NGINX binaries are built and distributed in two versions: stable and mainline. You'll need to [decide which is appropriate for your purposes](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-open-source/#choosing-between-a-stable-or-a-mainline-version).

## Linux binary installation process
The NGINX binary installation process takes advantage of package managers native to specific Linux distributions. For this reason, first-time installations involve adding the official NGINX package repository to your system's package manager.

### GPG keys
GPG signing keys are used to verify the authenticity of packages. Read more [important details](https://nginx.org/en/linux_packages.html#signatures) on our GPG/PGP keys.

### Upgrades
Future upgrades to the latest version can be managed using the same package manager without the need to manually download and verify binaries.

### Installation instructions
Once a repository has been added and verified, follow [these steps](https://nginx.org/en/linux_packages.html) to install NGINX binaries using the package manager native to your Linux distribution.

## FreeBSD installation process
For more information on installing NGINX on FreeBSD system, visit https://nginx.org/en/docs/install.html

## Windows executables
Windows executables for mainline and stable releases can be found on the main [NGINX download page](https://nginx.org/en/download.html). Note that the current implementation of NGINX for Windows is at the Proof-of-Concept stage and should only be used for development and testing purposes.

## Dynamic modules
NGINX version 1.9.11 added support for [Dynamic Modules](https://nginx.org/en/docs/ngx_core_module.html#load_module). Unlike standard, Static modules, which must be complied into NGINX binaries at build-time, Dynamic modules can be downloaded, installed, and configured at any point. [Official dynamic module binaries](https://nginx.org/en/linux_packages.html#dynmodules) are available from the same package repository as the core NGINX binaries described in previous steps.

> [!TIP]
> [NGINX JavaScript (njs)](https://github.com/nginx/njs), is a popular NGINX dynamic module that enables the extension of core NGINX functionality using familiar JavaScript syntax.

# Getting started with NGINX
For a gentle introduction to NGINX basics, please see our [Beginner’s Guide](https://nginx.org/en/docs/beginners_guide.html).

## Installing SSL certificates and enabling TLS encryption
See [Configuring HTTPS servers](https://nginx.org/en/docs/http/configuring_https_servers.html) for a quick guide on how to enable secure traffic to your NGINX installation.

## Load Balancing
For a quick start guide on configuring NGINX as a Load Balancer, please see [Using nginx as HTTP load balancer](https://nginx.org/en/docs/http/load_balancing.html).

## Rate limiting
See our [Rate Limiting with NGINX](https://blog.nginx.org/blog/rate-limiting-nginx) blog post for an overview of core concepts for provisioning NGINX as an API Gateway.

## Content caching
See [A Guide to Caching with NGINX and NGINX Plus](https://blog.nginx.org/blog/nginx-caching-guide) blog post for an overview of how to use NGINX as a content cache (e.g. edge server of a content delivery network).

# Building from source
The following steps can be used to build NGINX from source code available in this repository.

## Installing dependencies
Most Linux distributions will require several dependencies to be installed in order to build NGINX. The following instructions are specific to the `apt` package manager, widely available on most Ubuntu/Debian distributions and their derivatives.

> [!TIP]
> It is always a good idea to update your package repository lists prior to installing new packages. 
> ```bash
> sudo apt update
> ```

### Installing compiler and make utility
Use the following command to install the GNU C compiler and Make utility.

```bash
sudo apt install gcc make
```

### Installing dependency libraries

```bash
sudo apt install libpcre3-dev zlib1g-dev
```

> [!WARNING]
> This is the minimal set of dependency libraries needed to build NGINX. Other dependencies may be required if you choose to build NGINX with additional modules. Monitor the output of the `configure` command discussed in the following sections for information on which modules may be missing. For example, if you plan to use SSL certificates to encrypt traffic with TLS, you'll need to install the OpenSSL library. To do so, issue the following command.

>```bash
>sudo apt install libssl-dev

## Cloning the NGINX GitHub repository
Using your preferred method, clone the NGINX repository into your development directory. See [Cloning a GitHub Repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) for additional help.

```bash
git clone https://github.com/nginx/nginx.git
```

## Configuring the build
Prior to building NGINX (and most other Linux source packages), you must issue the `configure` command with [appropriate flags](https://nginx.org/en/docs/configure.html). This will generate a Makefile in your NGINX source root directory that can then be used to compile NGINX with [options specified during configuration](https://nginx.org/en/docs/configure.html).

From the NGINX source code repository's root directory:

```bash
auto/configure
```

> [!IMPORTANT]
> Configuring the build without any flags will compile NGINX with the minimal set of options. Please refer to https://nginx.org/en/docs/configure.html for a full list of available build configuration options.

## Compiling
The `configure` script will generate a `Makefile` in the NGINX source root directory upon successful execution. To compile NGINX into a binary, issue the following command from that same directory:

```bash
make
```

## Location of binary and installation
After successful compilation, a binary will be generated at `<NJS_SRC_ROOT_DIR>/objs/nginx`. To install this binary, issue the following command from the source root directory:

```bash
sudo make install
```

> [!IMPORTANT]
> The binary will be installed into the `/usr/local/nginx/` directory.

## Running and testing the installed binary
To run the installed binary, issue the following command:

```bash
sudo /usr/local/nginx/sbin/nginx
```

You may test NGINX operation using `curl`.

```bash
curl localhost
```

The output of which should start with:

```html
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
```

# Technical specifications
Pre-built NGINX binaries are available and supported across a wide number of operating systems. Please refer to [this complete list](https://nginx.org/en/) of operating systems, architectures, libraries and other features supported by NGINX.

## Supported distributions
A [complete list of available Linux packages](https://nginx.org/en/linux_packages.html#distributions) can be found on the binary download page.

See [Tested OS Platforms](https://nginx.org/en/#tested_os_and_platforms) for a  list of operating systems that NGINX is confirmed to run on.

## Windows 
Windows support is tested on Windows XP, Windows Server 2003, Windows 7, Windows 10. [Windows executables](https://nginx.org/en/download.html) can be found on the download page. Note that the current implementation of NGINX for Windows is at the Proof-of-Concept stage and should only be used for development and testing purposes.

## Supported deployment environments
- Container
- Public cloud (AWS, Google Cloud Platform, Microsoft Azure)
- Virtual machine

# Asking questions and reporting issues
We encourage you to engage with us.
- [NGINX GitHub Discussions](https://github.com/nginx/nginx/discussions), is the go-to place to start asking questions and sharing your thoughts.
- Our [GitHub Issues](https://github.com/nginx/nginx/issues) page offers space to submit and discuss specific issues, report bugs, and suggest enhancements.

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
