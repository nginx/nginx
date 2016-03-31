" Vim syntax file
" Language: nginx.conf

if exists("b:current_syntax")
  finish
end

setlocal iskeyword+=.
setlocal iskeyword+=/
setlocal iskeyword+=:

syn match ngxVariable '\$\(\w\+\|{\w\+}\)'
syn match ngxVariableBlock '\$\(\w\+\|{\w\+}\)' contained
syn match ngxVariableString '\$\(\w\+\|{\w\+}\)' contained
syn region ngxBlock start=+^+ end=+{+ skip=+\${+ contains=ngxComment,ngxDirectiveBlock,ngxVariableBlock,ngxString oneline
syn region ngxString start=+\z(["']\)+ end=+\z1+ skip=+\\\\\|\\\z1+ contains=ngxVariableString
syn match ngxComment ' *#.*$'

syn keyword ngxBoolean on
syn keyword ngxBoolean off

syn keyword ngxDirectiveBlock http         contained
syn keyword ngxDirectiveBlock mail         contained
syn keyword ngxDirectiveBlock events       contained
syn keyword ngxDirectiveBlock server       contained
syn keyword ngxDirectiveBlock types        contained
syn keyword ngxDirectiveBlock location     contained
syn keyword ngxDirectiveBlock upstream     contained
syn keyword ngxDirectiveBlock charset_map  contained
syn keyword ngxDirectiveBlock limit_except contained
syn keyword ngxDirectiveBlock if           contained
syn keyword ngxDirectiveBlock geo          contained
syn keyword ngxDirectiveBlock map          contained
syn keyword ngxDirectiveBlock split_clients contained

syn keyword ngxDirectiveImportant include
syn keyword ngxDirectiveImportant root
syn keyword ngxDirectiveImportant server
syn keyword ngxDirectiveImportant server_name
syn keyword ngxDirectiveImportant listen
syn keyword ngxDirectiveImportant internal
syn keyword ngxDirectiveImportant proxy_pass
syn keyword ngxDirectiveImportant memcached_pass
syn keyword ngxDirectiveImportant fastcgi_pass
syn keyword ngxDirectiveImportant scgi_pass
syn keyword ngxDirectiveImportant uwsgi_pass
syn keyword ngxDirectiveImportant try_files

syn keyword ngxDirectiveControl break
syn keyword ngxDirectiveControl return
syn keyword ngxDirectiveControl rewrite
syn keyword ngxDirectiveControl set

syn keyword ngxDirectiveError error_page
syn keyword ngxDirectiveError post_action

syn keyword ngxDirectiveDeprecated connections
syn keyword ngxDirectiveDeprecated imap
syn keyword ngxDirectiveDeprecated limit_zone
syn keyword ngxDirectiveDeprecated mysql_test
syn keyword ngxDirectiveDeprecated open_file_cache_retest
syn keyword ngxDirectiveDeprecated optimize_server_names
syn keyword ngxDirectiveDeprecated satisfy_any
syn keyword ngxDirectiveDeprecated so_keepalive

syn keyword ngxDirective accept_mutex
syn keyword ngxDirective accept_mutex_delay
syn keyword ngxDirective acceptex_read
syn keyword ngxDirective access_log
syn keyword ngxDirective add_after_body
syn keyword ngxDirective add_before_body
syn keyword ngxDirective add_header
syn keyword ngxDirective addition_types
syn keyword ngxDirective aio
syn keyword ngxDirective alias
syn keyword ngxDirective allow
syn keyword ngxDirective ancient_browser
syn keyword ngxDirective ancient_browser_value
syn keyword ngxDirective auth_basic
syn keyword ngxDirective auth_basic_user_file
syn keyword ngxDirective auth_http
syn keyword ngxDirective auth_http_header
syn keyword ngxDirective auth_http_timeout
syn keyword ngxDirective auth_request
syn keyword ngxDirective auth_request_set
syn keyword ngxDirective autoindex
syn keyword ngxDirective autoindex_exact_size
syn keyword ngxDirective autoindex_localtime
syn keyword ngxDirective charset
syn keyword ngxDirective charset_types
syn keyword ngxDirective chunked_transfer_encoding
syn keyword ngxDirective client_body_buffer_size
syn keyword ngxDirective client_body_in_file_only
syn keyword ngxDirective client_body_in_single_buffer
syn keyword ngxDirective client_body_temp_path
syn keyword ngxDirective client_body_timeout
syn keyword ngxDirective client_header_buffer_size
syn keyword ngxDirective client_header_timeout
syn keyword ngxDirective client_max_body_size
syn keyword ngxDirective connection_pool_size
syn keyword ngxDirective create_full_put_path
syn keyword ngxDirective daemon
syn keyword ngxDirective dav_access
syn keyword ngxDirective dav_methods
syn keyword ngxDirective debug_connection
syn keyword ngxDirective debug_points
syn keyword ngxDirective default_type
syn keyword ngxDirective degradation
syn keyword ngxDirective degrade
syn keyword ngxDirective deny
syn keyword ngxDirective devpoll_changes
syn keyword ngxDirective devpoll_events
syn keyword ngxDirective directio
syn keyword ngxDirective directio_alignment
syn keyword ngxDirective disable_symlinks
syn keyword ngxDirective empty_gif
syn keyword ngxDirective env
syn keyword ngxDirective epoll_events
syn keyword ngxDirective error_log
syn keyword ngxDirective etag
syn keyword ngxDirective eventport_events
syn keyword ngxDirective expires
syn keyword ngxDirective fastcgi_bind
syn keyword ngxDirective fastcgi_buffer_size
syn keyword ngxDirective fastcgi_buffering
syn keyword ngxDirective fastcgi_buffers
syn keyword ngxDirective fastcgi_busy_buffers_size
syn keyword ngxDirective fastcgi_cache
syn keyword ngxDirective fastcgi_cache_bypass
syn keyword ngxDirective fastcgi_cache_key
syn keyword ngxDirective fastcgi_cache_lock
syn keyword ngxDirective fastcgi_cache_lock_timeout
syn keyword ngxDirective fastcgi_cache_methods
syn keyword ngxDirective fastcgi_cache_min_uses
syn keyword ngxDirective fastcgi_cache_path
syn keyword ngxDirective fastcgi_cache_revalidate
syn keyword ngxDirective fastcgi_cache_use_stale
syn keyword ngxDirective fastcgi_cache_valid
syn keyword ngxDirective fastcgi_catch_stderr
syn keyword ngxDirective fastcgi_connect_timeout
syn keyword ngxDirective fastcgi_force_ranges
syn keyword ngxDirective fastcgi_hide_header
syn keyword ngxDirective fastcgi_ignore_client_abort
syn keyword ngxDirective fastcgi_ignore_headers
syn keyword ngxDirective fastcgi_index
syn keyword ngxDirective fastcgi_intercept_errors
syn keyword ngxDirective fastcgi_keep_conn
syn keyword ngxDirective fastcgi_max_temp_file_size
syn keyword ngxDirective fastcgi_next_upstream
syn keyword ngxDirective fastcgi_next_upstream_timeout
syn keyword ngxDirective fastcgi_next_upstream_tries
syn keyword ngxDirective fastcgi_no_cache
syn keyword ngxDirective fastcgi_param
syn keyword ngxDirective fastcgi_pass_header
syn keyword ngxDirective fastcgi_pass_request_body
syn keyword ngxDirective fastcgi_pass_request_headers
syn keyword ngxDirective fastcgi_read_timeout
syn keyword ngxDirective fastcgi_send_lowat
syn keyword ngxDirective fastcgi_send_timeout
syn keyword ngxDirective fastcgi_split_path_info
syn keyword ngxDirective fastcgi_store
syn keyword ngxDirective fastcgi_store_access
syn keyword ngxDirective fastcgi_temp_file_write_size
syn keyword ngxDirective fastcgi_temp_path
syn keyword ngxDirective flv
syn keyword ngxDirective geoip_city
syn keyword ngxDirective geoip_country
syn keyword ngxDirective geoip_org
syn keyword ngxDirective geoip_proxy
syn keyword ngxDirective geoip_proxy_recursive
syn keyword ngxDirective google_perftools_profiles
syn keyword ngxDirective gunzip
syn keyword ngxDirective gunzip_buffers
syn keyword ngxDirective gzip
syn keyword ngxDirective gzip_buffers
syn keyword ngxDirective gzip_comp_level
syn keyword ngxDirective gzip_disable
syn keyword ngxDirective gzip_hash
syn keyword ngxDirective gzip_http_version
syn keyword ngxDirective gzip_min_length
syn keyword ngxDirective gzip_no_buffer
syn keyword ngxDirective gzip_proxied
syn keyword ngxDirective gzip_static
syn keyword ngxDirective gzip_types
syn keyword ngxDirective gzip_vary
syn keyword ngxDirective gzip_window
syn keyword ngxDirective hash
syn keyword ngxDirective if_modified_since
syn keyword ngxDirective ignore_invalid_headers
syn keyword ngxDirective image_filter
syn keyword ngxDirective image_filter_buffer
syn keyword ngxDirective image_filter_interlace
syn keyword ngxDirective image_filter_jpeg_quality
syn keyword ngxDirective image_filter_sharpen
syn keyword ngxDirective image_filter_transparency
syn keyword ngxDirective imap_auth
syn keyword ngxDirective imap_capabilities
syn keyword ngxDirective imap_client_buffer
syn keyword ngxDirective index
syn keyword ngxDirective iocp_threads
syn keyword ngxDirective ip_hash
syn keyword ngxDirective keepalive
syn keyword ngxDirective keepalive_disable
syn keyword ngxDirective keepalive_requests
syn keyword ngxDirective keepalive_timeout
syn keyword ngxDirective kqueue_changes
syn keyword ngxDirective kqueue_events
syn keyword ngxDirective large_client_header_buffers
syn keyword ngxDirective least_conn
syn keyword ngxDirective limit_conn
syn keyword ngxDirective limit_conn_log_level
syn keyword ngxDirective limit_conn_status
syn keyword ngxDirective limit_conn_zone
syn keyword ngxDirective limit_rate
syn keyword ngxDirective limit_rate_after
syn keyword ngxDirective limit_req
syn keyword ngxDirective limit_req_log_level
syn keyword ngxDirective limit_req_status
syn keyword ngxDirective limit_req_zone
syn keyword ngxDirective lingering_close
syn keyword ngxDirective lingering_time
syn keyword ngxDirective lingering_timeout
syn keyword ngxDirective lock_file
syn keyword ngxDirective log_format
syn keyword ngxDirective log_not_found
syn keyword ngxDirective log_subrequest
syn keyword ngxDirective map_hash_bucket_size
syn keyword ngxDirective map_hash_max_size
syn keyword ngxDirective master_process
syn keyword ngxDirective max_ranges
syn keyword ngxDirective memcached_bind
syn keyword ngxDirective memcached_buffer_size
syn keyword ngxDirective memcached_connect_timeout
syn keyword ngxDirective memcached_gzip_flag
syn keyword ngxDirective memcached_next_upstream
syn keyword ngxDirective memcached_next_upstream_timeout
syn keyword ngxDirective memcached_next_upstream_tries
syn keyword ngxDirective memcached_read_timeout
syn keyword ngxDirective memcached_send_timeout
syn keyword ngxDirective merge_slashes
syn keyword ngxDirective min_delete_depth
syn keyword ngxDirective modern_browser
syn keyword ngxDirective modern_browser_value
syn keyword ngxDirective mp4
syn keyword ngxDirective mp4_buffer_size
syn keyword ngxDirective mp4_max_buffer_size
syn keyword ngxDirective msie_padding
syn keyword ngxDirective msie_refresh
syn keyword ngxDirective multi_accept
syn keyword ngxDirective open_file_cache
syn keyword ngxDirective open_file_cache_errors
syn keyword ngxDirective open_file_cache_events
syn keyword ngxDirective open_file_cache_min_uses
syn keyword ngxDirective open_file_cache_valid
syn keyword ngxDirective open_log_file_cache
syn keyword ngxDirective output_buffers
syn keyword ngxDirective override_charset
syn keyword ngxDirective pcre_jit
syn keyword ngxDirective perl
syn keyword ngxDirective perl_modules
syn keyword ngxDirective perl_require
syn keyword ngxDirective perl_set
syn keyword ngxDirective pid
syn keyword ngxDirective pop3_auth
syn keyword ngxDirective pop3_capabilities
syn keyword ngxDirective port_in_redirect
syn keyword ngxDirective post_acceptex
syn keyword ngxDirective postpone_gzipping
syn keyword ngxDirective postpone_output
syn keyword ngxDirective protocol
syn keyword ngxDirective proxy
syn keyword ngxDirective proxy_bind
syn keyword ngxDirective proxy_buffer
syn keyword ngxDirective proxy_buffer_size
syn keyword ngxDirective proxy_buffering
syn keyword ngxDirective proxy_buffers
syn keyword ngxDirective proxy_busy_buffers_size
syn keyword ngxDirective proxy_cache
syn keyword ngxDirective proxy_cache_bypass
syn keyword ngxDirective proxy_cache_key
syn keyword ngxDirective proxy_cache_lock
syn keyword ngxDirective proxy_cache_lock_timeout
syn keyword ngxDirective proxy_cache_methods
syn keyword ngxDirective proxy_cache_min_uses
syn keyword ngxDirective proxy_cache_path
syn keyword ngxDirective proxy_cache_revalidate
syn keyword ngxDirective proxy_cache_use_stale
syn keyword ngxDirective proxy_cache_valid
syn keyword ngxDirective proxy_connect_timeout
syn keyword ngxDirective proxy_cookie_domain
syn keyword ngxDirective proxy_cookie_path
syn keyword ngxDirective proxy_force_ranges
syn keyword ngxDirective proxy_headers_hash_bucket_size
syn keyword ngxDirective proxy_headers_hash_max_size
syn keyword ngxDirective proxy_hide_header
syn keyword ngxDirective proxy_http_version
syn keyword ngxDirective proxy_ignore_client_abort
syn keyword ngxDirective proxy_ignore_headers
syn keyword ngxDirective proxy_intercept_errors
syn keyword ngxDirective proxy_max_temp_file_size
syn keyword ngxDirective proxy_method
syn keyword ngxDirective proxy_next_upstream
syn keyword ngxDirective proxy_next_upstream_timeout
syn keyword ngxDirective proxy_next_upstream_tries
syn keyword ngxDirective proxy_no_cache
syn keyword ngxDirective proxy_pass_error_message
syn keyword ngxDirective proxy_pass_header
syn keyword ngxDirective proxy_pass_request_body
syn keyword ngxDirective proxy_pass_request_headers
syn keyword ngxDirective proxy_read_timeout
syn keyword ngxDirective proxy_redirect
syn keyword ngxDirective proxy_send_lowat
syn keyword ngxDirective proxy_send_timeout
syn keyword ngxDirective proxy_set_body
syn keyword ngxDirective proxy_set_header
syn keyword ngxDirective proxy_ssl_ciphers
syn keyword ngxDirective proxy_ssl_crl
syn keyword ngxDirective proxy_ssl_name
syn keyword ngxDirective proxy_ssl_protocols
syn keyword ngxDirective proxy_ssl_server_name
syn keyword ngxDirective proxy_ssl_session_reuse
syn keyword ngxDirective proxy_ssl_trusted_certificate
syn keyword ngxDirective proxy_ssl_verify
syn keyword ngxDirective proxy_ssl_verify_depth
syn keyword ngxDirective proxy_store
syn keyword ngxDirective proxy_store_access
syn keyword ngxDirective proxy_temp_file_write_size
syn keyword ngxDirective proxy_temp_path
syn keyword ngxDirective proxy_timeout
syn keyword ngxDirective random_index
syn keyword ngxDirective read_ahead
syn keyword ngxDirective real_ip_header
syn keyword ngxDirective real_ip_recursive
syn keyword ngxDirective recursive_error_pages
syn keyword ngxDirective referer_hash_bucket_size
syn keyword ngxDirective referer_hash_max_size
syn keyword ngxDirective request_pool_size
syn keyword ngxDirective reset_timedout_connection
syn keyword ngxDirective resolver
syn keyword ngxDirective resolver_timeout
syn keyword ngxDirective rewrite_log
syn keyword ngxDirective rtsig_overflow_events
syn keyword ngxDirective rtsig_overflow_test
syn keyword ngxDirective rtsig_overflow_threshold
syn keyword ngxDirective rtsig_signo
syn keyword ngxDirective satisfy
syn keyword ngxDirective scgi_bind
syn keyword ngxDirective scgi_buffer_size
syn keyword ngxDirective scgi_buffering
syn keyword ngxDirective scgi_buffers
syn keyword ngxDirective scgi_busy_buffers_size
syn keyword ngxDirective scgi_cache
syn keyword ngxDirective scgi_cache_bypass
syn keyword ngxDirective scgi_cache_key
syn keyword ngxDirective scgi_cache_lock
syn keyword ngxDirective scgi_cache_lock_timeout
syn keyword ngxDirective scgi_cache_methods
syn keyword ngxDirective scgi_cache_min_uses
syn keyword ngxDirective scgi_cache_path
syn keyword ngxDirective scgi_cache_revalidate
syn keyword ngxDirective scgi_cache_use_stale
syn keyword ngxDirective scgi_cache_valid
syn keyword ngxDirective scgi_connect_timeout
syn keyword ngxDirective scgi_force_ranges
syn keyword ngxDirective scgi_hide_header
syn keyword ngxDirective scgi_ignore_client_abort
syn keyword ngxDirective scgi_ignore_headers
syn keyword ngxDirective scgi_intercept_errors
syn keyword ngxDirective scgi_max_temp_file_size
syn keyword ngxDirective scgi_next_upstream
syn keyword ngxDirective scgi_next_upstream_timeout
syn keyword ngxDirective scgi_next_upstream_tries
syn keyword ngxDirective scgi_no_cache
syn keyword ngxDirective scgi_param
syn keyword ngxDirective scgi_pass_header
syn keyword ngxDirective scgi_pass_request_body
syn keyword ngxDirective scgi_pass_request_headers
syn keyword ngxDirective scgi_read_timeout
syn keyword ngxDirective scgi_send_timeout
syn keyword ngxDirective scgi_store
syn keyword ngxDirective scgi_store_access
syn keyword ngxDirective scgi_temp_file_write_size
syn keyword ngxDirective scgi_temp_path
syn keyword ngxDirective secure_link
syn keyword ngxDirective secure_link_md5
syn keyword ngxDirective secure_link_secret
syn keyword ngxDirective send_lowat
syn keyword ngxDirective send_timeout
syn keyword ngxDirective sendfile
syn keyword ngxDirective sendfile_max_chunk
syn keyword ngxDirective server_name_in_redirect
syn keyword ngxDirective server_names_hash_bucket_size
syn keyword ngxDirective server_names_hash_max_size
syn keyword ngxDirective server_tokens
syn keyword ngxDirective set_real_ip_from
syn keyword ngxDirective smtp_auth
syn keyword ngxDirective smtp_capabilities
syn keyword ngxDirective smtp_client_buffer
syn keyword ngxDirective smtp_greeting_delay
syn keyword ngxDirective source_charset
syn keyword ngxDirective spdy_chunk_size
syn keyword ngxDirective spdy_headers_comp
syn keyword ngxDirective spdy_keepalive_timeout
syn keyword ngxDirective spdy_max_concurrent_streams
syn keyword ngxDirective spdy_pool_size
syn keyword ngxDirective spdy_recv_buffer_size
syn keyword ngxDirective spdy_recv_timeout
syn keyword ngxDirective spdy_streams_index_size
syn keyword ngxDirective ssi
syn keyword ngxDirective ssi_ignore_recycled_buffers
syn keyword ngxDirective ssi_last_modified
syn keyword ngxDirective ssi_min_file_chunk
syn keyword ngxDirective ssi_silent_errors
syn keyword ngxDirective ssi_types
syn keyword ngxDirective ssi_value_length
syn keyword ngxDirective ssl
syn keyword ngxDirective ssl_buffer_size
syn keyword ngxDirective ssl_certificate
syn keyword ngxDirective ssl_certificate_key
syn keyword ngxDirective ssl_ciphers
syn keyword ngxDirective ssl_client_certificate
syn keyword ngxDirective ssl_crl
syn keyword ngxDirective ssl_dhparam
syn keyword ngxDirective ssl_ecdh_curve
syn keyword ngxDirective ssl_engine
syn keyword ngxDirective ssl_password_file
syn keyword ngxDirective ssl_prefer_server_ciphers
syn keyword ngxDirective ssl_protocols
syn keyword ngxDirective ssl_session_cache
syn keyword ngxDirective ssl_session_ticket_key
syn keyword ngxDirective ssl_session_tickets
syn keyword ngxDirective ssl_session_timeout
syn keyword ngxDirective ssl_stapling
syn keyword ngxDirective ssl_stapling_file
syn keyword ngxDirective ssl_stapling_responder
syn keyword ngxDirective ssl_stapling_verify
syn keyword ngxDirective ssl_trusted_certificate
syn keyword ngxDirective ssl_verify_client
syn keyword ngxDirective ssl_verify_depth
syn keyword ngxDirective starttls
syn keyword ngxDirective stub_status
syn keyword ngxDirective sub_filter
syn keyword ngxDirective sub_filter_last_modified
syn keyword ngxDirective sub_filter_once
syn keyword ngxDirective sub_filter_types
syn keyword ngxDirective tcp_nodelay
syn keyword ngxDirective tcp_nopush
syn keyword ngxDirective thread_stack_size
syn keyword ngxDirective timeout
syn keyword ngxDirective timer_resolution
syn keyword ngxDirective types_hash_bucket_size
syn keyword ngxDirective types_hash_max_size
syn keyword ngxDirective underscores_in_headers
syn keyword ngxDirective uninitialized_variable_warn
syn keyword ngxDirective use
syn keyword ngxDirective user
syn keyword ngxDirective userid
syn keyword ngxDirective userid_domain
syn keyword ngxDirective userid_expires
syn keyword ngxDirective userid_mark
syn keyword ngxDirective userid_name
syn keyword ngxDirective userid_p3p
syn keyword ngxDirective userid_path
syn keyword ngxDirective userid_service
syn keyword ngxDirective uwsgi_bind
syn keyword ngxDirective uwsgi_buffer_size
syn keyword ngxDirective uwsgi_buffering
syn keyword ngxDirective uwsgi_buffers
syn keyword ngxDirective uwsgi_busy_buffers_size
syn keyword ngxDirective uwsgi_cache
syn keyword ngxDirective uwsgi_cache_bypass
syn keyword ngxDirective uwsgi_cache_key
syn keyword ngxDirective uwsgi_cache_lock
syn keyword ngxDirective uwsgi_cache_lock_timeout
syn keyword ngxDirective uwsgi_cache_methods
syn keyword ngxDirective uwsgi_cache_min_uses
syn keyword ngxDirective uwsgi_cache_path
syn keyword ngxDirective uwsgi_cache_revalidate
syn keyword ngxDirective uwsgi_cache_use_stale
syn keyword ngxDirective uwsgi_cache_valid
syn keyword ngxDirective uwsgi_connect_timeout
syn keyword ngxDirective uwsgi_force_ranges
syn keyword ngxDirective uwsgi_hide_header
syn keyword ngxDirective uwsgi_ignore_client_abort
syn keyword ngxDirective uwsgi_ignore_headers
syn keyword ngxDirective uwsgi_intercept_errors
syn keyword ngxDirective uwsgi_max_temp_file_size
syn keyword ngxDirective uwsgi_modifier1
syn keyword ngxDirective uwsgi_modifier2
syn keyword ngxDirective uwsgi_next_upstream
syn keyword ngxDirective uwsgi_next_upstream_timeout
syn keyword ngxDirective uwsgi_next_upstream_tries
syn keyword ngxDirective uwsgi_no_cache
syn keyword ngxDirective uwsgi_param
syn keyword ngxDirective uwsgi_pass_header
syn keyword ngxDirective uwsgi_pass_request_body
syn keyword ngxDirective uwsgi_pass_request_headers
syn keyword ngxDirective uwsgi_read_timeout
syn keyword ngxDirective uwsgi_send_timeout
syn keyword ngxDirective uwsgi_ssl_ciphers
syn keyword ngxDirective uwsgi_ssl_crl
syn keyword ngxDirective uwsgi_ssl_name
syn keyword ngxDirective uwsgi_ssl_protocols
syn keyword ngxDirective uwsgi_ssl_server_name
syn keyword ngxDirective uwsgi_ssl_session_reuse
syn keyword ngxDirective uwsgi_ssl_trusted_certificate
syn keyword ngxDirective uwsgi_ssl_verify
syn keyword ngxDirective uwsgi_ssl_verify_depth
syn keyword ngxDirective uwsgi_store
syn keyword ngxDirective uwsgi_store_access
syn keyword ngxDirective uwsgi_string
syn keyword ngxDirective uwsgi_temp_file_write_size
syn keyword ngxDirective uwsgi_temp_path
syn keyword ngxDirective valid_referers
syn keyword ngxDirective variables_hash_bucket_size
syn keyword ngxDirective variables_hash_max_size
syn keyword ngxDirective worker_aio_requests
syn keyword ngxDirective worker_connections
syn keyword ngxDirective worker_cpu_affinity
syn keyword ngxDirective worker_priority
syn keyword ngxDirective worker_processes
syn keyword ngxDirective worker_rlimit_core
syn keyword ngxDirective worker_rlimit_nofile
syn keyword ngxDirective worker_rlimit_sigpending
syn keyword ngxDirective worker_threads
syn keyword ngxDirective working_directory
syn keyword ngxDirective xclient
syn keyword ngxDirective xml_entities
syn keyword ngxDirective xslt_last_modified
syn keyword ngxDirective xslt_param
syn keyword ngxDirective xslt_string_param
syn keyword ngxDirective xslt_stylesheet
syn keyword ngxDirective xslt_types

" 3rd party module list:
" http://wiki.nginx.org/Nginx3rdPartyModules

" Accept Language Module <http://wiki.nginx.org/NginxAcceptLanguageModule>
" Parses the Accept-Language header and gives the most suitable locale from a list of supported locales.
syn keyword ngxDirectiveThirdParty set_from_accept_language

" Access Key Module <http://wiki.nginx.org/NginxHttpAccessKeyModule>
" Denies access unless the request URL contains an access key.
syn keyword ngxDirectiveThirdParty accesskey
syn keyword ngxDirectiveThirdParty accesskey_arg
syn keyword ngxDirectiveThirdParty accesskey_hashmethod
syn keyword ngxDirectiveThirdParty accesskey_signature

" Auth PAM Module <http://web.iti.upv.es/~sto/nginx/>
" HTTP Basic Authentication using PAM.
syn keyword ngxDirectiveThirdParty auth_pam
syn keyword ngxDirectiveThirdParty auth_pam_service_name

" Cache Purge Module <http://labs.frickle.com/nginx_ngx_cache_purge/>
" Module adding ability to purge content from FastCGI and proxy caches.
syn keyword ngxDirectiveThirdParty fastcgi_cache_purge
syn keyword ngxDirectiveThirdParty proxy_cache_purge

" Chunkin Module <http://wiki.nginx.org/NginxHttpChunkinModule>
" HTTP 1.1 chunked-encoding request body support for Nginx.
syn keyword ngxDirectiveThirdParty chunkin
syn keyword ngxDirectiveThirdParty chunkin_keepalive
syn keyword ngxDirectiveThirdParty chunkin_max_chunks_per_buf
syn keyword ngxDirectiveThirdParty chunkin_resume

" Circle GIF Module <http://wiki.nginx.org/NginxHttpCircleGifModule>
" Generates simple circle images with the colors and size specified in the URL.
syn keyword ngxDirectiveThirdParty circle_gif
syn keyword ngxDirectiveThirdParty circle_gif_max_radius
syn keyword ngxDirectiveThirdParty circle_gif_min_radius
syn keyword ngxDirectiveThirdParty circle_gif_step_radius

" Drizzle Module <http://github.com/chaoslawful/drizzle-nginx-module>
" Make nginx talk directly to mysql, drizzle, and sqlite3 by libdrizzle.
syn keyword ngxDirectiveThirdParty drizzle_connect_timeout
syn keyword ngxDirectiveThirdParty drizzle_dbname
syn keyword ngxDirectiveThirdParty drizzle_keepalive
syn keyword ngxDirectiveThirdParty drizzle_module_header
syn keyword ngxDirectiveThirdParty drizzle_pass
syn keyword ngxDirectiveThirdParty drizzle_query
syn keyword ngxDirectiveThirdParty drizzle_recv_cols_timeout
syn keyword ngxDirectiveThirdParty drizzle_recv_rows_timeout
syn keyword ngxDirectiveThirdParty drizzle_send_query_timeout
syn keyword ngxDirectiveThirdParty drizzle_server

" Echo Module <http://wiki.nginx.org/NginxHttpEchoModule>
" Brings 'echo', 'sleep', 'time', 'exec' and more shell-style goodies to Nginx config file.
syn keyword ngxDirectiveThirdParty echo
syn keyword ngxDirectiveThirdParty echo_after_body
syn keyword ngxDirectiveThirdParty echo_before_body
syn keyword ngxDirectiveThirdParty echo_blocking_sleep
syn keyword ngxDirectiveThirdParty echo_duplicate
syn keyword ngxDirectiveThirdParty echo_end
syn keyword ngxDirectiveThirdParty echo_exec
syn keyword ngxDirectiveThirdParty echo_flush
syn keyword ngxDirectiveThirdParty echo_foreach_split
syn keyword ngxDirectiveThirdParty echo_location
syn keyword ngxDirectiveThirdParty echo_location_async
syn keyword ngxDirectiveThirdParty echo_read_request_body
syn keyword ngxDirectiveThirdParty echo_request_body
syn keyword ngxDirectiveThirdParty echo_reset_timer
syn keyword ngxDirectiveThirdParty echo_sleep
syn keyword ngxDirectiveThirdParty echo_subrequest
syn keyword ngxDirectiveThirdParty echo_subrequest_async

" Events Module <http://docs.dutov.org/nginx_modules_events_en.html>
" Privides options for start/stop events.
syn keyword ngxDirectiveThirdParty on_start
syn keyword ngxDirectiveThirdParty on_stop

" EY Balancer Module <http://github.com/ry/nginx-ey-balancer>
" Adds a request queue to Nginx that allows the limiting of concurrent requests passed to the upstream.
syn keyword ngxDirectiveThirdParty max_connections
syn keyword ngxDirectiveThirdParty max_connections_max_queue_length
syn keyword ngxDirectiveThirdParty max_connections_queue_timeout

" Fancy Indexes Module <https://connectical.com/projects/ngx-fancyindex/wiki>
" Like the built-in autoindex module, but fancier.
syn keyword ngxDirectiveThirdParty fancyindex
syn keyword ngxDirectiveThirdParty fancyindex_exact_size
syn keyword ngxDirectiveThirdParty fancyindex_footer
syn keyword ngxDirectiveThirdParty fancyindex_header
syn keyword ngxDirectiveThirdParty fancyindex_localtime
syn keyword ngxDirectiveThirdParty fancyindex_readme
syn keyword ngxDirectiveThirdParty fancyindex_readme_mode

" GeoIP Module (DEPRECATED) <http://wiki.nginx.org/NginxHttp3rdPartyGeoIPModule>
" Country code lookups via the MaxMind GeoIP API.
syn keyword ngxDirectiveThirdParty geoip_country_file

" Headers More Module <http://wiki.nginx.org/NginxHttpHeadersMoreModule>
" Set and clear input and output headers...more than "add"!
syn keyword ngxDirectiveThirdParty more_clear_headers
syn keyword ngxDirectiveThirdParty more_clear_input_headers
syn keyword ngxDirectiveThirdParty more_set_headers
syn keyword ngxDirectiveThirdParty more_set_input_headers

" HTTP Push Module <http://pushmodule.slact.net/>
" Turn Nginx into an adept long-polling HTTP Push (Comet) server.
syn keyword ngxDirectiveThirdParty push_buffer_size
syn keyword ngxDirectiveThirdParty push_listener
syn keyword ngxDirectiveThirdParty push_message_timeout
syn keyword ngxDirectiveThirdParty push_queue_messages
syn keyword ngxDirectiveThirdParty push_sender

" HTTP Redis Module <http://people.FreeBSD.ORG/~osa/ngx_http_redis-0.3.1.tar.gz>>
" Redis <http://code.google.com/p/redis/> support.>
syn keyword ngxDirectiveThirdParty redis_bind
syn keyword ngxDirectiveThirdParty redis_buffer_size
syn keyword ngxDirectiveThirdParty redis_connect_timeout
syn keyword ngxDirectiveThirdParty redis_next_upstream
syn keyword ngxDirectiveThirdParty redis_pass
syn keyword ngxDirectiveThirdParty redis_read_timeout
syn keyword ngxDirectiveThirdParty redis_send_timeout

" HTTP JavaScript Module <http://wiki.github.com/kung-fu-tzu/ngx_http_js_module>
" Embedding SpiderMonkey. Nearly full port on Perl module.
syn keyword ngxDirectiveThirdParty js
syn keyword ngxDirectiveThirdParty js_filter
syn keyword ngxDirectiveThirdParty js_filter_types
syn keyword ngxDirectiveThirdParty js_load
syn keyword ngxDirectiveThirdParty js_maxmem
syn keyword ngxDirectiveThirdParty js_require
syn keyword ngxDirectiveThirdParty js_set
syn keyword ngxDirectiveThirdParty js_utf8

" Log Request Speed <http://wiki.nginx.org/NginxHttpLogRequestSpeed>
" Log the time it took to process each request.
syn keyword ngxDirectiveThirdParty log_request_speed_filter
syn keyword ngxDirectiveThirdParty log_request_speed_filter_timeout

" Memc Module <http://wiki.nginx.org/NginxHttpMemcModule>
" An extended version of the standard memcached module that supports set, add, delete, and many more memcached commands.
syn keyword ngxDirectiveThirdParty memc_buffer_size
syn keyword ngxDirectiveThirdParty memc_cmds_allowed
syn keyword ngxDirectiveThirdParty memc_connect_timeout
syn keyword ngxDirectiveThirdParty memc_flags_to_last_modified
syn keyword ngxDirectiveThirdParty memc_next_upstream
syn keyword ngxDirectiveThirdParty memc_pass
syn keyword ngxDirectiveThirdParty memc_read_timeout
syn keyword ngxDirectiveThirdParty memc_send_timeout
syn keyword ngxDirectiveThirdParty memc_upstream_fail_timeout
syn keyword ngxDirectiveThirdParty memc_upstream_max_fails

" Mogilefs Module <http://www.grid.net.ru/nginx/mogilefs.en.html>
" Implements a MogileFS client, provides a replace to the Perlbal reverse proxy of the original MogileFS.
syn keyword ngxDirectiveThirdParty mogilefs_connect_timeout
syn keyword ngxDirectiveThirdParty mogilefs_domain
syn keyword ngxDirectiveThirdParty mogilefs_methods
syn keyword ngxDirectiveThirdParty mogilefs_noverify
syn keyword ngxDirectiveThirdParty mogilefs_pass
syn keyword ngxDirectiveThirdParty mogilefs_read_timeout
syn keyword ngxDirectiveThirdParty mogilefs_send_timeout
syn keyword ngxDirectiveThirdParty mogilefs_tracker

" MP4 Streaming Lite Module <http://wiki.nginx.org/NginxMP4StreamingLite>
" Will seek to a certain time within H.264/MP4 files when provided with a 'start' parameter in the URL.
syn keyword ngxDirectiveThirdParty mp4

" Nginx Notice Module <http://xph.us/software/nginx-notice/>
" Serve static file to POST requests.
syn keyword ngxDirectiveThirdParty notice
syn keyword ngxDirectiveThirdParty notice_type

" Phusion Passenger <http://www.modrails.com/documentation.html>
" Easy and robust deployment of Ruby on Rails application on Apache and Nginx webservers.
syn keyword ngxDirectiveThirdParty passenger_base_uri
syn keyword ngxDirectiveThirdParty passenger_default_user
syn keyword ngxDirectiveThirdParty passenger_enabled
syn keyword ngxDirectiveThirdParty passenger_log_level
syn keyword ngxDirectiveThirdParty passenger_max_instances_per_app
syn keyword ngxDirectiveThirdParty passenger_max_pool_size
syn keyword ngxDirectiveThirdParty passenger_pool_idle_time
syn keyword ngxDirectiveThirdParty passenger_root
syn keyword ngxDirectiveThirdParty passenger_ruby
syn keyword ngxDirectiveThirdParty passenger_use_global_queue
syn keyword ngxDirectiveThirdParty passenger_user_switching
syn keyword ngxDirectiveThirdParty rack_env
syn keyword ngxDirectiveThirdParty rails_app_spawner_idle_time
syn keyword ngxDirectiveThirdParty rails_env
syn keyword ngxDirectiveThirdParty rails_framework_spawner_idle_time
syn keyword ngxDirectiveThirdParty rails_spawn_method

" RDS JSON Module <http://github.com/agentzh/rds-json-nginx-module>
" Help ngx_drizzle and other DBD modules emit JSON data.
syn keyword ngxDirectiveThirdParty rds_json
syn keyword ngxDirectiveThirdParty rds_json_content_type
syn keyword ngxDirectiveThirdParty rds_json_format
syn keyword ngxDirectiveThirdParty rds_json_ret

" RRD Graph Module <http://wiki.nginx.org/NginxNgx_rrd_graph>
" This module provides an HTTP interface to RRDtool's graphing facilities.
syn keyword ngxDirectiveThirdParty rrd_graph
syn keyword ngxDirectiveThirdParty rrd_graph_root

" Secure Download <http://wiki.nginx.org/NginxHttpSecureDownload>
" Create expiring links.
syn keyword ngxDirectiveThirdParty secure_download
syn keyword ngxDirectiveThirdParty secure_download_fail_location
syn keyword ngxDirectiveThirdParty secure_download_path_mode
syn keyword ngxDirectiveThirdParty secure_download_secret

" SlowFS Cache Module <http://labs.frickle.com/nginx_ngx_slowfs_cache/>
" Module adding ability to cache static files.
syn keyword ngxDirectiveThirdParty slowfs_big_file_size
syn keyword ngxDirectiveThirdParty slowfs_cache
syn keyword ngxDirectiveThirdParty slowfs_cache_key
syn keyword ngxDirectiveThirdParty slowfs_cache_min_uses
syn keyword ngxDirectiveThirdParty slowfs_cache_path
syn keyword ngxDirectiveThirdParty slowfs_cache_purge
syn keyword ngxDirectiveThirdParty slowfs_cache_valid
syn keyword ngxDirectiveThirdParty slowfs_temp_path

" Strip Module <http://wiki.nginx.org/NginxHttpStripModule>
" Whitespace remover.
syn keyword ngxDirectiveThirdParty strip

" Substitutions Module <http://wiki.nginx.org/NginxHttpSubsModule>
" A filter module which can do both regular expression and fixed string substitutions on response bodies.
syn keyword ngxDirectiveThirdParty subs_filter
syn keyword ngxDirectiveThirdParty subs_filter_types

" Supervisord Module <http://labs.frickle.com/nginx_ngx_supervisord/>
" Module providing nginx with API to communicate with supervisord and manage (start/stop) backends on-demand.
syn keyword ngxDirectiveThirdParty supervisord
syn keyword ngxDirectiveThirdParty supervisord_inherit_backend_status
syn keyword ngxDirectiveThirdParty supervisord_name
syn keyword ngxDirectiveThirdParty supervisord_start
syn keyword ngxDirectiveThirdParty supervisord_stop

" Upload Module <http://www.grid.net.ru/nginx/upload.en.html>
" Parses multipart/form-data allowing arbitrary handling of uploaded files.
syn keyword ngxDirectiveThirdParty upload_aggregate_form_field
syn keyword ngxDirectiveThirdParty upload_buffer_size
syn keyword ngxDirectiveThirdParty upload_cleanup
syn keyword ngxDirectiveThirdParty upload_limit_rate
syn keyword ngxDirectiveThirdParty upload_max_file_size
syn keyword ngxDirectiveThirdParty upload_max_output_body_len
syn keyword ngxDirectiveThirdParty upload_max_part_header_len
syn keyword ngxDirectiveThirdParty upload_pass
syn keyword ngxDirectiveThirdParty upload_pass_args
syn keyword ngxDirectiveThirdParty upload_pass_form_field
syn keyword ngxDirectiveThirdParty upload_set_form_field
syn keyword ngxDirectiveThirdParty upload_store
syn keyword ngxDirectiveThirdParty upload_store_access

" Upload Progress Module <http://wiki.nginx.org/NginxHttpUploadProgressModule>
" Tracks and reports upload progress.
syn keyword ngxDirectiveThirdParty report_uploads
syn keyword ngxDirectiveThirdParty track_uploads
syn keyword ngxDirectiveThirdParty upload_progress
syn keyword ngxDirectiveThirdParty upload_progress_content_type
syn keyword ngxDirectiveThirdParty upload_progress_header
syn keyword ngxDirectiveThirdParty upload_progress_json_output
syn keyword ngxDirectiveThirdParty upload_progress_template

" Upstream Fair Balancer <http://wiki.nginx.org/NginxHttpUpstreamFairModule>
" Sends an incoming request to the least-busy backend server, rather than distributing requests round-robin.
syn keyword ngxDirectiveThirdParty fair
syn keyword ngxDirectiveThirdParty upstream_fair_shm_size

" Upstream Consistent Hash <http://wiki.nginx.org/NginxHttpUpstreamConsistentHash>
" Select backend based on Consistent hash ring.
syn keyword ngxDirectiveThirdParty consistent_hash

" Upstream Hash Module <http://wiki.nginx.org/NginxHttpUpstreamRequestHashModule>
" Provides simple upstream load distribution by hashing a configurable variable.
syn keyword ngxDirectiveThirdParty hash
syn keyword ngxDirectiveThirdParty hash_again

" XSS Module <http://github.com/agentzh/xss-nginx-module>
" Native support for cross-site scripting (XSS) in an nginx.
syn keyword ngxDirectiveThirdParty xss_callback_arg
syn keyword ngxDirectiveThirdParty xss_get
syn keyword ngxDirectiveThirdParty xss_input_types
syn keyword ngxDirectiveThirdParty xss_output_type

" highlight

hi link ngxComment Comment
hi link ngxVariable Identifier
hi link ngxVariableBlock Identifier
hi link ngxVariableString PreProc
hi link ngxBlock Normal
hi link ngxString String

hi link ngxBoolean Boolean
hi link ngxDirectiveBlock Statement
hi link ngxDirectiveImportant Type
hi link ngxDirectiveControl Keyword
hi link ngxDirectiveError Constant
hi link ngxDirectiveDeprecated Error
hi link ngxDirective Identifier
hi link ngxDirectiveThirdParty Special

let b:current_syntax = "nginx"
