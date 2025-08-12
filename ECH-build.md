
# NGINX OpenSSL Encrypted Client Hello (ECH) integration.

> [!NOTE]
> This documentation probably doesn't belong here, nor as a single file, but
> may be useful to have in one place as we process the PR. TODO: find out where
> to put the various bits and pieces once those are stable.

ECH is specified in
[draft-ietf-tls-esni](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).
This documentation assumes a basic familiarity with the ECH specification.

This build only supports ECH "shared-mode" where the NGINX instance does the
ECH decryption and also hosts both the ECH `public-name` and `backend` web
sites.  ECH "split-mode" where the NGINX instance only does ECH decryption but
passes the TLS session on to a different backend service requires changes to
OpenSSL that have yet to be merged to the ECH feature branch. There is a
separate proof-of-concept implementation for that, but that is not documented
here.  (For more on ECH "split-mode" see the
[defo-project-PoC](https://github.com/defo-project/ech-dev-utils/blob/main/howtos/nginx.md).)

## Build

> [!NOTE]
> ECH is not yet a part of an OpenSSL release, our current goal is that ECH be
> part of an OpenSSL 4.0 release in spring 2026. 

There is client and server ECH code in the OpenSSL ECH feature branch at
[https://github.com/openssl/openssl/tree/feature/ech](https://github.com/openssl/openssl/tree/feature/ech).
At present, ECH-enabling NGINX therefore requires building from source, using
the OpenSSL ECH feature branch.

To get the ECH feature branch:

```bash
$ cd /home/user/code
$ git clone https://github.com/openssl/openssl/ openssl-for-nginx
$ cd openssl-for-nginx
$ git checkout feature/ech
```

Then an option to build NGINX is:

```bash
$ cd /home/user/code
$ git clone https://github.com/sftcd/nginx.git
$ cd nginx
$ ./auto/configure --with-debug --prefix=nginx --with-http_ssl_module --with-openssl=/home/user/code/openssl-for-nginx --with-openssl-opt="--debug" --with-http_v2_module
$ make
...stuff...
```

This results in an NGINX binary in `objs/nginx` with a statically linked
OpenSSL, so as not to disturb system libraries.

## ECH Key Generation and Publication

In the remaining, we describe a configuration that uses `example.com` as the
ECH `public-name` and where `foo.example.com` is a web-site for which we want
ECH to be used, with both hosted on the same NGINX instance.

Using ECH requries that NGINX load an ECH key pair with a private value for ECH
decryption. Browsers will require that the public component of that key pair be
published in the DNS. With OpenSSL we generate and store that key pair in a PEM
formatted file as shown below.

To generate ECH PEM files, use the openssl binary produced by the build above
(which is `/home/user/code/openssl-for-nginx/.openssl/bin/openssl`) to generate
an ECH key pair and store the result in a PEM file. You should also supply the
`public-name` required by the ECH protocol.

Key generation operations should be carried out under whatever local account is
used for NGINX configuration.

```bash
~# OSSL=/home/user/code/openssl-for-nginx/.openssl/bin/openssl
~# mkdir -p /etc/nginx/echkeydir
~# chmod 700 /etc/nginx/echkeydir
~# cd /etc/nginx/echkeydir
~# $OSSL ech -public-name example.com -o example.com.pem.ech
~# cat example.com.pem.ech
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIJi22Im2rJ/lJqzNFZdGfsVfmknXAc8xz3fYPhD0Na5I
-----END PRIVATE KEY-----
-----BEGIN ECHCONFIG-----
AD7+DQA6QwAgACA8mxkEsSTp2xXC/RUFCC6CZMMgdM4x1iTWKu3EONjbMAAEAAEA
AQALZXhhbXBsZS5vcmcAAA==
-----END ECHCONFIG-----
```

> [!NOTE]
> The January 2025 lighttpd web server release included ECH and adopted a
> naming convention for ECH PEM files that their names ought end in `.ech`.
> This PR follows that covention.

The ECHConfig value then needs to be published in an HTTPS resource record in
the DNS, so as to be accessible as shown below:

```bash
$ dig +short HTTPS foo.example.com
1 . ech=AD7+DQA6QwAgACA8mxkEsSTp2xXC/RUFCC6CZMMgdM4x1iTWKu3EONjbMAAEAAEAAQALZXhhbXBsZS5vcmcAAA==
$ 
```

Various other fields may be included in an HTTPS resource record. For many
NGINX instances, existing methods for publishing DNS records may be used to
achieve the above.  In some cases, one might use [A well-known URI for
publishing service
parameters](https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech)
designed to assist web servers in handling e.g. frequent ECH key rotation.

## Configuration

To enable ECH for an NGINX instance, configure a directory name via the
`ssl_echkeydir` directive where that directory contains a set of ECH PEM key
files.  The `ssl_echkeydir` directive should be in the "http" section of an
NGINX configuration as shown in the example below. All ECH PEM files in that
directory that are successfully decoded will be loaded. 

```
http {
    log_format withech '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" "$ech_status"';
    access_log          /var/log/nginx/access.log withech;
    ssl_echkeydir       /etc/nginx/echkeydir;
    server {
        listen              443 default_server ssl;
        http2 on;
        ssl_certificate     /etc/nginx/example.com.crt;
        ssl_certificate_key /etc/nginx/example.com.priv;
        ssl_protocols       TLSv1.3;
        server_name         example.com;
        location / {
            root   /var/www/dir-example.com;
            index  index.html index.htm;
        }
    }
    server {
        listen              443 ssl;
        http2 on;
        ssl_certificate     /etc/nginx/example.com.crt;
        ssl_certificate_key /etc/nginx/example.com.priv;
        ssl_protocols       TLSv1.3;
        server_name         foo.example.com;
        location / {
            root   /var/www/dir-foo.example.com;
            index  index.html index.htm;
        }
    }
```

## Logs

You can log ECH status information in the normal `access.log` by adding
`$ech_status` to the `log_format`, e.g. the stanza below adds ECH status to the
normal `combined` log format:

```
    log_format withech '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" "$ech_status"';
    access_log          /var/log/nginx/access.log withech;
```

That results in log lines like the following:

```
127.0.0.1 - - [26/Feb/2025:13:35:52 +0000] "GET / HTTP/1.1" 200 494 "-" "curl/8.12.0-DEV" "ECH: SSL_ECH_STATUS_GREASE/foo.example.com/"
127.0.0.1 - - [26/Feb/2025:13:39:39 +0000] "GET / HTTP/1.1" 200 494 "-" "curl/8.12.0-DEV" "ECH: SSL_ECH_STATUS_NOT_TRIED/foo.example.com/"
127.0.0.1 - - [26/Feb/2025:14:08:21 +0000] "GET / HTTP/1.1" 200 494 "-" "curl/8.12.0-DEV" "ECH: SSL_ECH_STATUS_SUCCESS/example.com/foo.example.com"
127.0.0.1 - - [26/Feb/2025:14:09:58 +0000] "GET / HTTP/1.1" 200 494 "-" "curl/8.12.0-DEV" "ECH: SSL_ECH_STATUS_NOT_TRIED/foo.example.com/"
127.0.0.1 - - [26/Feb/2025:14:11:47 +0000] "GET / HTTP/1.1" 400 255 "-" "curl/8.12.0-DEV" "ECH: no TLS connection"
```

When ECH has succeeded, then the outer SNI and inner SNI are included in that
order. If a client GREASEd or didn't try ECH at all, and no outer SNI was
provided, the HTTP host header will be shown instead. Connections that did not
use TLS show that. The TLS version is not specifically shown, so TLSv1.2
connections will show up as `SSL_ECH_STATUS_NOT_TRIED`.

At start-up, and on configuration re-load, NGINX will log (to `error.log` at
the "notice" log level) the names of ECH PEM files successfully loaded and the
total number of ECH keys loaded, for each `server` stanza in the configuration.
Errors in loading keys are also logged and may result in the server not
starting.

## CGI variables

We set the following variables for, e.g. PHP code:

- ``SSL_ECH_STATUS`` - ``success`` means that, others also mean what they say
- ``SSL_ECH_INNER_SNI`` - has value that was in inner ClientHello SNI (or
  ``NONE``)
- ``SSL_ECH_OUTER_SNI`` - has value that was in outer ClientHello SNI (or
  ``NONE``)

To see those using fastcgi you need to include the following in the relevant
NGINX config:

```
fastcgi_param SSL_ECH_STATUS $ssl_ech_status;
fastcgi_param SSL_ECH_INNER_SNI $ssl_ech_inner_sni;
fastcgi_param SSL_ECH_OUTER_SNI $ssl_ech_outer_sni;
```

## Code changes

- New code is protected using `#ifndef OPENSSL_NO_ECH` as is done in the
  OpenSSL ECH feature branch. That is set in `src/event/ngx_event_openssl.h` if
  the new ECH symbol `SSL_OP_ECH_GREASE` is not defined in `ssl.h`.  In other
  words, if NGINX is built using an OpenSSL version that has ECH support, then
  that will be used. If the OpenSSL version doesn't have ECH then the
  ECH-specific code in NGINX is compiled out.

- `src/http/modules/ngx_http_ssl_module.h` and
  `src/http/modules/ngx_http_ssl_module.c` define the new `ssl_echkeydir`
  directive and the variables that become visible to e.g. PHP code.

- `load_echkeys()` in `src/event/ngx_event_openssl.c` loads ECH PEM files as
  directed by the `ssl_echkeydir` directive, and enables shared-mode ECH
  decryption if some ECH keys are loaded. If `ssl_echkeydir` is set, but no keys
  are loaded, that results in an error and NGINX exits.

- `ngx_ssl_get_ech_status()`, `ngx_ssl_get_ech_inner_sni()` and
  `ngx_ssl_get_ech_outer_sni()` also in `src/event/ngx_event_openssl.c` provide
  for setting the CGI variables mentioned above.

- `src/http/modules/ngx_http_log_module.c` contains code to handle the new
  `$ech_status` log format, mainly in the `ngx_http_log_ech_status()` function.

> [!NOTE]
> `load_echkeys()` will include the public component all loaded keys in the ECH
> `retry-configs` in the fallback scenario. If desired, we could add a naming
> convention or additional configuration setting to distinguish which to
> include in `retry-configs` or not. For now, we assume that'd better be done
> in a subsequent PR, if experience shows the feature is really useful/needed.
> (We can envisage some odd deployments where that might be the case, but not
> clear those'd really happen - it'd seem to need loads of key pairs or else
> some that are never published in the DNS that we don't want to expose to
> random clients - neither seems compelling.)

## Reloading ECH keys

ECH uses a form of ephemeral-static (Elliptic curve) Diffie-Hellman key
exchange, so in order to get better forward secrecy, there is a need to perhaps
frequently rotate ECH keys. For example, some widely-used ECH-enabled web
services rotate ECH keys hourly. That may be done e.g.  via a cronjob and using
[A well-known URI for publishing service
parameters](https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech).  In
such a setup, the set of ECH PEM files in the `ssl_echkeydir` directory will
change hourly, with the directory likely to contain perhaps three ECH PEM files
(curent, hour-before and two-hours before). This creates a need to reload ECH
PEM files regularly.

Sending a SIGHUP signal to the running process causes it to reload it's
configuration, so if `$PIDFILE` is a file with the NGINX server process-id:

```bash
$ kill -SIGHUP `cat $PIDFILE`
```

When ECH PEM files are loaded or re-loaded that's logged to the error log,
e.g.:

```
2023/12/03 20:09:13 [notice] 273779#0: load_echkeys, total keys loaded: 2
2023/12/03 20:09:13 [notice] 273779#0: load_echkeys, worked for: /home/user/lt/echkeydir/echconfig.pem.ech
2023/12/03 20:09:13 [notice] 273779#0: load_echkeys, worked for: /home/user/lt/echkeydir/d13.pem.ech
```

> [!NOTE]
> The ECH integration released by the lighttpd web server in January 2025
> allows configuration of a timer used to cause ECH PEM files to be reloaded if
> those have changed. This PR does not include that functionality but it could
> be added if desired, e.g. if regularly reloading the entire NGINX
> configuration is considered undesirable. See the [lighttpd
> code](https://github.com/lighttpd/lighttpd1.4/blob/master/src/mod_openssl.c#L799)
> for details.

## Debugging

To run NGINX in ``gdb`` you probably want to uncomment the ``daemon off;`` and
``master_process off;`` lines in your config file. You probably also want to
build with `CFLAGS="-g -O0"` to turn off optimization, and then, e.g. if you
wanted to debug into the ``load_echkeys()`` function:

```bash
    $ gdb ~/code/nginx/objs/nginx
    GNU gdb (Ubuntu 13.1-2ubuntu2) 13.1
    Copyright (C) 2023 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    <https://www.gnu.org/software/gdb/bugs/>.
    Find the GDB manual and other documentation resources online at:
        <http://www.gnu.org/software/gdb/documentation/>.
    
    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    Reading symbols from /home/user/code/nginx/objs/nginx...
    (gdb) b load_echkeys 
    Breakpoint 1 at 0x1402e9: file src/event/ngx_event_openssl.c, line 1469.
    (gdb) r -c nginxmin.conf
    Starting program: /home/user/code/nginx/objs/nginx -c nginxmin.conf
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    
    Breakpoint 1, load_echkeys (ssl=ssl@entry=0x555555db64d8, dirname=dirname@entry=0x555555db6568)
        at src/event/ngx_event_openssl.c:1469
    1469	{
    (gdb) c
    Continuing.
    
    Breakpoint 1, load_echkeys (ssl=ssl@entry=0x555555dbad68, dirname=dirname@entry=0x555555dbadf8)
        at src/event/ngx_event_openssl.c:1469
    1469	{
    (gdb) c
    Continuing.
    [Detaching after fork from child process 522259]
```
