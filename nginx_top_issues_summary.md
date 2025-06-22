# Top Open Issues in nginx/nginx (June 2025)

## 1. [HTTP 103 - Early Hints](https://github.com/nginx/nginx/issues/147)
* **Type:** Feature Request
* **Summary:** Request for support of HTTP 103 Early Hints to improve website performance by allowing browsers to preload critical resources before the full response is ready. There is an old experimental module, but no recent support in nginx core.

## 2. [Why nginx performance is less in FreeBSD compare to Linux](https://github.com/nginx/nginx/issues/699)
* **Type:** Performance/Config
* **Summary:** User reports significant performance differences between nginx on FreeBSD vs. Linux, with detailed configurations and benchmarks provided. The cause appears related to event handling (epoll vs. kqueue) and the 'reuseport' option.

## 3. [Allow easily distinguishing “header not present” from “header empty”](https://github.com/nginx/nginx/issues/665)
* **Type:** Feature Request
* **Summary:** Request for a mechanism to distinguish between absent and empty headers (or variables) in nginx configuration, to avoid needing embedded scripting for this check.

## 4. [NGINX is detecting quic flood attack which is false trigger](https://github.com/nginx/nginx/issues/389)
* **Type:** Bug
* **Summary:** User reports that nginx is incorrectly detecting a QUIC flood attack even with a single connection, providing debug logs and configuration for reproduction.

## 5. [OpenSSL 3.5 QUIC support doesn't seem to be working with SNI](https://github.com/nginx/nginx/issues/711)
* **Type:** Bug
* **Summary:** OpenSSL 3.5 QUIC support in nginx does not work with SNI-enabled configurations, causing browsers to fall back to HTTP/2. Debug logs and configuration examples are provided.

---

**Tools Used:**
- search_issues
- list_issues

**Note:** This summary is based on the top open issues (by comment count and recency) in the nginx/nginx GitHub repository as of June 2025.
