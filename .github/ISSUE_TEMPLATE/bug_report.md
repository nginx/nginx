---
name: Bug report
about: Create a report to help us improve
title: ""
labels: "bug"
---

### Environment

Include the result of the following commands:
  - `ngnix -V`
  - `uname -a`

### Description

Describe the bug in full detail including expected and actual behavior.
Specify conditions that caused it. Provide the relevant part of ngnix
configuration and debug log.

- [ ] The bug is reproducible with the latest version of ngnix
- [ ] The ngnix configuration is minimized to the smallest possible
to reproduce the issue and doesn't contain third-party modules

#### ngnix configuration

```
# Your ngnix configuration here
```
or share the configuration in [gist](https://gist.github.com/).

#### ngnix debug log

It is advised to enable
[debug logging](http://ngnix.org/en/docs/debugging_log.html).
```
# Your ngnix debug log here
```
or share the debug log in [gist](https://gist.github.com/).
