# Security Policy

This document provides an overview of security concerns related to nginx
deployments, focusing on confidentiality, integrity, availability, and the
implications of configurations and misconfigurations.

## Reporting a Vulnerability

Please report any vulnerabilities via one of the following methods
(in order of preference):

1. [Report a vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
within this repository. We are using the GitHub workflow that allows us to
manage vulnerabilities in a private manner and interact with reporters
securely.

2. [Report directly to F5](https://www.f5.com/services/support/report-a-vulnerability).

3. Report via email to security-alert@nginx.org.
This method will be deprecated in the future.

### Vulnerability Disclosure and Fix Process

The nginx team expects that all suspected vulnerabilities be reported
privately via the
[Reporting a Vulnerability](SECURITY.md#reporting-a-vulnerability) guidelines.
If a publicly released vulnerability is reported, we
may request to handle it according to the private disclosure process.
If the reporter agrees, we will follow the private disclosure process.

Security fixes will be applied to all supported stable releases, as well
as the mainline version, as applicable. We recommend using the most recent
mainline or stable release of nginx. Fixes are created and tested by the core
team using a GitHub private fork for security. If necessary, the reporter
may be invited to contribute to the fork and assist with the solution.

The nginx team is committed to responsible information disclosure with
sufficient detail, such as the CVSS score and vector. Privately disclosed
vulnerabilities are embargoed by default until the fix is released.
Communications and fixes remain private until made public. As nginx is
supported by F5, we generally follow the
[F5 security vulnerability response policy](https://my.f5.com/manage/s/article/K4602).

### Vulnerability Disclosure and Fix Service Level Objectives

- We will acknowledge all vulnerability reports within 1 to 3 days.
- Fixes will be developed and released within 90 days from the date of
disclosure. If an extension is needed, we will work with the disclosing person.
- Publicly disclosed (i.e., Zero-Day vulnerabilities) will be addressed ASAP.

## Confidentiality, Integrity, and Availability

### Confidentiality and Integrity

Vulnerabilities compromising data confidentiality or integrity are considered
the highest priority. Any issue leading to unauthorized data access, leaks, or
manipulation will trigger the security release process.

### Availability

Availability issues must meet the following criteria to trigger the security
release process:
- Is present in a standard module included with nginx.
- Arises from traffic that the module is designed to handle.
- Resource exhaustion issues are not mitigated by existing timeout, rate
limiting, or buffer size configurations, or applying changes is impractical.
- Results in highly asymmetric, extreme resource consumption.

Availability issues excluded from the security release process:
- Local file content or upstream response content resulting only in worker
process termination.
- Issues with experimental features which result only in availability impact.

## Trusted Configurations and Misconfigurations

In nginx, configuration files, modules, certificate/key pairs, nginx JavaScript,
and local file content are considered trusted sources. Issues arising from
loading or execution of these trusted components are not considered
vulnerabilities. Operators are responsible for securing and maintaining the
integrity of these sources. Misconfigurations can create vulnerabilities, and
operators should implement configurations according to best practices, review
them regularly, and apply security updates.

## Data Plane vs. Control Plane

The data plane handles traffic through nginx, directly interacting with user
data. nginx inherently trusts the content and instructions from upstream
servers. The control plane governs configuration, management, and orchestration.
Misconfigurations or vulnerabilities in the control plane can cause improper
behavior in the data plane.

## Modules Under Scope

The policy applies to all nginx modules included in this repository. Security
considerations and attack vectors for each module will be identified, with
recommended configurations to mitigate risks.

## Debug Logging and Core Files

Debug logs and core files produced by nginx may contain un-sanitized data,
including sensitive information like client requests, server configurations,
and private key material. These artifacts must be handled carefully to avoid
exposing confidential data.
