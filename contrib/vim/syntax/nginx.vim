" Vim syntax file
" Language: nginx.conf

if exists("b:current_syntax")
  finish
end

" general syntax

if has("patch-7.4.1142")
    " except control characters, ";", "{", and "}"
    syn iskeyword 33-58,60-122,124,126-255
endif

syn match ngxName '\([^;{} \t\\]\|\\.\)\+'
    \ contains=@ngxDirectives
    \ nextgroup=@ngxParams skipwhite skipempty
syn match ngxParam '\([^;{ \t\\]\|\\.\)\+'
    \ contained
    \ contains=ngxVariable
    \ nextgroup=@ngxParams skipwhite skipempty
syn region ngxString start=+\z(["']\)+ end=+\z1+ skip=+\\\\\|\\\z1+
    \ contains=ngxVariableString
    \ nextgroup=@ngxParams skipwhite skipempty
syn match ngxParamComment '#.*$'
    \ nextgroup=@ngxParams skipwhite skipempty
syn match ngxSemicolon ';' contained
syn region ngxBlock start=+{+ end=+}+ contained
    \ contains=@ngxTopLevel
syn match ngxComment '#.*$'

syn match ngxVariable '\$\w\+' contained
syn match ngxVariableString '\$\(\w\+\|{\w\+}\)' contained

syn cluster ngxTopLevel
    \ contains=ngxName,ngxString,ngxComment
syn cluster ngxDirectives
    \ contains=ngxDirective,ngxDirectiveBlock,ngxDirectiveImportant
    \ add=ngxDirectiveControl,ngxDirectiveError,ngxDirectiveDeprecated
    \ add=ngxDirectiveThirdParty
syn cluster ngxParams
    \ contains=ngxParam,ngxString,ngxParamComment,ngxSemicolon,ngxBlock

" boolean parameters

syn keyword ngxBoolean contained on off
    \ nextgroup=@ngxParams skipwhite skipempty
syn cluster ngxParams add=ngxBoolean

" listen directive

syn cluster ngxTopLevel add=ngxDirectiveListen
syn keyword ngxDirectiveListen listen
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn match ngxListenParam '\([^;{ \t\\]\|\\.\)\+'
    \ contained
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn region ngxListenString start=+\z(["']\)+ end=+\z1+ skip=+\\\\\|\\\z1+
    \ contained
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn match ngxListenComment '#.*$'
    \ contained
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn keyword ngxListenOptions contained
    \ default_server ssl http2 spdy proxy_protocol
    \ setfib fastopen backlog rcvbuf sndbuf accept_filter deferred bind
    \ ipv6only reuseport so_keepalive keepidle
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn cluster ngxListenParams
    \ contains=ngxListenParam,ngxListenString,ngxListenComment
    \ add=ngxListenOptions

syn keyword ngxDirectiveBlock contained http
syn keyword ngxDirectiveBlock contained mail
syn keyword ngxDirectiveBlock contained events
syn keyword ngxDirectiveBlock contained server
syn keyword ngxDirectiveBlock contained types
syn keyword ngxDirectiveBlock contained location
syn keyword ngxDirectiveBlock contained upstream
syn keyword ngxDirectiveBlock contained charset_map
syn keyword ngxDirectiveBlock contained limit_except
syn keyword ngxDirectiveBlock contained if
syn keyword ngxDirectiveBlock contained geo
syn keyword ngxDirectiveBlock contained map
syn keyword ngxDirectiveBlock contained split_clients

syn keyword ngxDirectiveImportant contained include
syn keyword ngxDirectiveImportant contained root
"syn keyword ngxDirectiveImportant contained server
syn keyword ngxDirectiveImportant contained server_name
"syn keyword ngxDirectiveImportant contained listen
syn keyword ngxDirectiveImportant contained internal
syn keyword ngxDirectiveImportant contained proxy_pass
syn keyword ngxDirectiveImportant contained memcached_pass
syn keyword ngxDirectiveImportant contained fastcgi_pass
syn keyword ngxDirectiveImportant contained scgi_pass
syn keyword ngxDirectiveImportant contained uwsgi_pass
syn keyword ngxDirectiveImportant contained try_files

syn keyword ngxDirectiveControl contained break
syn keyword ngxDirectiveControl contained return
syn keyword ngxDirectiveControl contained rewrite
syn keyword ngxDirectiveControl contained set

syn keyword ngxDirectiveError contained error_page
syn keyword ngxDirectiveError contained post_action

syn keyword ngxDirectiveDeprecated contained connections
syn keyword ngxDirectiveDeprecated contained imap
syn keyword ngxDirectiveDeprecated contained limit_zone
syn keyword ngxDirectiveDeprecated contained mysql_test
syn keyword ngxDirectiveDeprecated contained open_file_cache_retest
syn keyword ngxDirectiveDeprecated contained optimize_server_names
syn keyword ngxDirectiveDeprecated contained satisfy_any
syn keyword ngxDirectiveDeprecated contained so_keepalive

syn keyword ngxDirective contained absolute_redirect
syn keyword ngxDirective contained accept_mutex
syn keyword ngxDirective contained accept_mutex_delay
syn keyword ngxDirective contained acceptex_read
syn keyword ngxDirective contained access_log
syn keyword ngxDirective contained add_after_body
syn keyword ngxDirective contained add_before_body
syn keyword ngxDirective contained add_header
syn keyword ngxDirective contained addition_types
syn keyword ngxDirective contained aio
syn keyword ngxDirective contained aio_write
syn keyword ngxDirective contained alias
syn keyword ngxDirective contained allow
syn keyword ngxDirective contained ancient_browser
syn keyword ngxDirective contained ancient_browser_value
syn keyword ngxDirective contained auth_basic
syn keyword ngxDirective contained auth_basic_user_file
syn keyword ngxDirective contained auth_http
syn keyword ngxDirective contained auth_http_header
syn keyword ngxDirective contained auth_http_pass_client_cert
syn keyword ngxDirective contained auth_http_timeout
syn keyword ngxDirective contained auth_jwt
syn keyword ngxDirective contained auth_jwt_key_file
syn keyword ngxDirective contained auth_request
syn keyword ngxDirective contained auth_request_set
syn keyword ngxDirective contained autoindex
syn keyword ngxDirective contained autoindex_exact_size
syn keyword ngxDirective contained autoindex_format
syn keyword ngxDirective contained autoindex_localtime
syn keyword ngxDirective contained charset
syn keyword ngxDirective contained charset_map
syn keyword ngxDirective contained charset_types
syn keyword ngxDirective contained chunked_transfer_encoding
syn keyword ngxDirective contained client_body_buffer_size
syn keyword ngxDirective contained client_body_in_file_only
syn keyword ngxDirective contained client_body_in_single_buffer
syn keyword ngxDirective contained client_body_temp_path
syn keyword ngxDirective contained client_body_timeout
syn keyword ngxDirective contained client_header_buffer_size
syn keyword ngxDirective contained client_header_timeout
syn keyword ngxDirective contained client_max_body_size
syn keyword ngxDirective contained connection_pool_size
syn keyword ngxDirective contained create_full_put_path
syn keyword ngxDirective contained daemon
syn keyword ngxDirective contained dav_access
syn keyword ngxDirective contained dav_methods
syn keyword ngxDirective contained debug_connection
syn keyword ngxDirective contained debug_points
syn keyword ngxDirective contained default_type
syn keyword ngxDirective contained degradation
syn keyword ngxDirective contained degrade
syn keyword ngxDirective contained deny
syn keyword ngxDirective contained devpoll_changes
syn keyword ngxDirective contained devpoll_events
syn keyword ngxDirective contained directio
syn keyword ngxDirective contained directio_alignment
syn keyword ngxDirective contained disable_symlinks
syn keyword ngxDirective contained empty_gif
syn keyword ngxDirective contained env
syn keyword ngxDirective contained epoll_events
syn keyword ngxDirective contained error_log
syn keyword ngxDirective contained etag
syn keyword ngxDirective contained eventport_events
syn keyword ngxDirective contained expires
syn keyword ngxDirective contained f4f
syn keyword ngxDirective contained f4f_buffer_size
syn keyword ngxDirective contained fastcgi_bind
syn keyword ngxDirective contained fastcgi_buffer_size
syn keyword ngxDirective contained fastcgi_buffering
syn keyword ngxDirective contained fastcgi_buffers
syn keyword ngxDirective contained fastcgi_busy_buffers_size
syn keyword ngxDirective contained fastcgi_cache
syn keyword ngxDirective contained fastcgi_cache_bypass
syn keyword ngxDirective contained fastcgi_cache_key
syn keyword ngxDirective contained fastcgi_cache_lock
syn keyword ngxDirective contained fastcgi_cache_lock_age
syn keyword ngxDirective contained fastcgi_cache_lock_timeout
syn keyword ngxDirective contained fastcgi_cache_max_range_offset
syn keyword ngxDirective contained fastcgi_cache_methods
syn keyword ngxDirective contained fastcgi_cache_min_uses
syn keyword ngxDirective contained fastcgi_cache_path
syn keyword ngxDirective contained fastcgi_cache_purge
syn keyword ngxDirective contained fastcgi_cache_revalidate
syn keyword ngxDirective contained fastcgi_cache_use_stale
syn keyword ngxDirective contained fastcgi_cache_valid
syn keyword ngxDirective contained fastcgi_catch_stderr
syn keyword ngxDirective contained fastcgi_connect_timeout
syn keyword ngxDirective contained fastcgi_force_ranges
syn keyword ngxDirective contained fastcgi_hide_header
syn keyword ngxDirective contained fastcgi_ignore_client_abort
syn keyword ngxDirective contained fastcgi_ignore_headers
syn keyword ngxDirective contained fastcgi_index
syn keyword ngxDirective contained fastcgi_intercept_errors
syn keyword ngxDirective contained fastcgi_keep_conn
syn keyword ngxDirective contained fastcgi_limit_rate
syn keyword ngxDirective contained fastcgi_max_temp_file_size
syn keyword ngxDirective contained fastcgi_next_upstream
syn keyword ngxDirective contained fastcgi_next_upstream_timeout
syn keyword ngxDirective contained fastcgi_next_upstream_tries
syn keyword ngxDirective contained fastcgi_no_cache
syn keyword ngxDirective contained fastcgi_param
syn keyword ngxDirective contained fastcgi_pass_header
syn keyword ngxDirective contained fastcgi_pass_request_body
syn keyword ngxDirective contained fastcgi_pass_request_headers
syn keyword ngxDirective contained fastcgi_read_timeout
syn keyword ngxDirective contained fastcgi_request_buffering
syn keyword ngxDirective contained fastcgi_send_lowat
syn keyword ngxDirective contained fastcgi_send_timeout
syn keyword ngxDirective contained fastcgi_split_path_info
syn keyword ngxDirective contained fastcgi_store
syn keyword ngxDirective contained fastcgi_store_access
syn keyword ngxDirective contained fastcgi_temp_file_write_size
syn keyword ngxDirective contained fastcgi_temp_path
syn keyword ngxDirective contained flv
syn keyword ngxDirective contained geoip_city
syn keyword ngxDirective contained geoip_country
syn keyword ngxDirective contained geoip_org
syn keyword ngxDirective contained geoip_proxy
syn keyword ngxDirective contained geoip_proxy_recursive
syn keyword ngxDirective contained google_perftools_profiles
syn keyword ngxDirective contained gunzip
syn keyword ngxDirective contained gunzip_buffers
syn keyword ngxDirective contained gzip
syn keyword ngxDirective contained gzip_buffers
syn keyword ngxDirective contained gzip_comp_level
syn keyword ngxDirective contained gzip_disable
syn keyword ngxDirective contained gzip_hash
syn keyword ngxDirective contained gzip_http_version
syn keyword ngxDirective contained gzip_min_length
syn keyword ngxDirective contained gzip_no_buffer
syn keyword ngxDirective contained gzip_proxied
syn keyword ngxDirective contained gzip_static
syn keyword ngxDirective contained gzip_types
syn keyword ngxDirective contained gzip_vary
syn keyword ngxDirective contained gzip_window
syn keyword ngxDirective contained hash
syn keyword ngxDirective contained health_check
syn keyword ngxDirective contained health_check_timeout
syn keyword ngxDirective contained hls
syn keyword ngxDirective contained hls_buffers
syn keyword ngxDirective contained hls_forward_args
syn keyword ngxDirective contained hls_fragment
syn keyword ngxDirective contained hls_mp4_buffer_size
syn keyword ngxDirective contained hls_mp4_max_buffer_size
syn keyword ngxDirective contained http2_chunk_size
syn keyword ngxDirective contained http2_body_preread_size
syn keyword ngxDirective contained http2_idle_timeout
syn keyword ngxDirective contained http2_max_concurrent_streams
syn keyword ngxDirective contained http2_max_field_size
syn keyword ngxDirective contained http2_max_header_size
syn keyword ngxDirective contained http2_max_requests
syn keyword ngxDirective contained http2_recv_buffer_size
syn keyword ngxDirective contained http2_recv_timeout
syn keyword ngxDirective contained if_modified_since
syn keyword ngxDirective contained ignore_invalid_headers
syn keyword ngxDirective contained image_filter
syn keyword ngxDirective contained image_filter_buffer
syn keyword ngxDirective contained image_filter_interlace
syn keyword ngxDirective contained image_filter_jpeg_quality
syn keyword ngxDirective contained image_filter_sharpen
syn keyword ngxDirective contained image_filter_transparency
syn keyword ngxDirective contained image_filter_webp_quality
syn keyword ngxDirective contained imap_auth
syn keyword ngxDirective contained imap_capabilities
syn keyword ngxDirective contained imap_client_buffer
syn keyword ngxDirective contained index
syn keyword ngxDirective contained iocp_threads
syn keyword ngxDirective contained ip_hash
syn keyword ngxDirective contained js_access
syn keyword ngxDirective contained js_content
syn keyword ngxDirective contained js_filter
syn keyword ngxDirective contained js_include
syn keyword ngxDirective contained js_preread
syn keyword ngxDirective contained js_set
syn keyword ngxDirective contained keepalive
syn keyword ngxDirective contained keepalive_disable
syn keyword ngxDirective contained keepalive_requests
syn keyword ngxDirective contained keepalive_timeout
syn keyword ngxDirective contained kqueue_changes
syn keyword ngxDirective contained kqueue_events
syn keyword ngxDirective contained large_client_header_buffers
syn keyword ngxDirective contained least_conn
syn keyword ngxDirective contained least_time
syn keyword ngxDirective contained limit_conn
syn keyword ngxDirective contained limit_conn_log_level
syn keyword ngxDirective contained limit_conn_status
syn keyword ngxDirective contained limit_conn_zone
syn keyword ngxDirective contained limit_rate
syn keyword ngxDirective contained limit_rate_after
syn keyword ngxDirective contained limit_req
syn keyword ngxDirective contained limit_req_log_level
syn keyword ngxDirective contained limit_req_status
syn keyword ngxDirective contained limit_req_zone
syn keyword ngxDirective contained lingering_close
syn keyword ngxDirective contained lingering_time
syn keyword ngxDirective contained lingering_timeout
syn keyword ngxDirective contained load_module
syn keyword ngxDirective contained lock_file
syn keyword ngxDirective contained log_format
syn keyword ngxDirective contained log_not_found
syn keyword ngxDirective contained log_subrequest
syn keyword ngxDirective contained map_hash_bucket_size
syn keyword ngxDirective contained map_hash_max_size
syn keyword ngxDirective contained match
syn keyword ngxDirective contained master_process
syn keyword ngxDirective contained max_ranges
syn keyword ngxDirective contained memcached_bind
syn keyword ngxDirective contained memcached_buffer_size
syn keyword ngxDirective contained memcached_connect_timeout
syn keyword ngxDirective contained memcached_force_ranges
syn keyword ngxDirective contained memcached_gzip_flag
syn keyword ngxDirective contained memcached_next_upstream
syn keyword ngxDirective contained memcached_next_upstream_timeout
syn keyword ngxDirective contained memcached_next_upstream_tries
syn keyword ngxDirective contained memcached_read_timeout
syn keyword ngxDirective contained memcached_send_timeout
syn keyword ngxDirective contained merge_slashes
syn keyword ngxDirective contained min_delete_depth
syn keyword ngxDirective contained modern_browser
syn keyword ngxDirective contained modern_browser_value
syn keyword ngxDirective contained mp4
syn keyword ngxDirective contained mp4_buffer_size
syn keyword ngxDirective contained mp4_max_buffer_size
syn keyword ngxDirective contained mp4_limit_rate
syn keyword ngxDirective contained mp4_limit_rate_after
syn keyword ngxDirective contained msie_padding
syn keyword ngxDirective contained msie_refresh
syn keyword ngxDirective contained multi_accept
syn keyword ngxDirective contained ntlm
syn keyword ngxDirective contained open_file_cache
syn keyword ngxDirective contained open_file_cache_errors
syn keyword ngxDirective contained open_file_cache_events
syn keyword ngxDirective contained open_file_cache_min_uses
syn keyword ngxDirective contained open_file_cache_valid
syn keyword ngxDirective contained open_log_file_cache
syn keyword ngxDirective contained output_buffers
syn keyword ngxDirective contained override_charset
syn keyword ngxDirective contained pcre_jit
syn keyword ngxDirective contained perl
syn keyword ngxDirective contained perl_modules
syn keyword ngxDirective contained perl_require
syn keyword ngxDirective contained perl_set
syn keyword ngxDirective contained pid
syn keyword ngxDirective contained pop3_auth
syn keyword ngxDirective contained pop3_capabilities
syn keyword ngxDirective contained port_in_redirect
syn keyword ngxDirective contained post_acceptex
syn keyword ngxDirective contained postpone_gzipping
syn keyword ngxDirective contained postpone_output
syn keyword ngxDirective contained preread_buffer_size
syn keyword ngxDirective contained preread_timeout
syn keyword ngxDirective contained protocol
syn keyword ngxDirective contained proxy
syn keyword ngxDirective contained proxy_bind
syn keyword ngxDirective contained proxy_buffer
syn keyword ngxDirective contained proxy_buffer_size
syn keyword ngxDirective contained proxy_buffering
syn keyword ngxDirective contained proxy_buffers
syn keyword ngxDirective contained proxy_busy_buffers_size
syn keyword ngxDirective contained proxy_cache
syn keyword ngxDirective contained proxy_cache_bypass
syn keyword ngxDirective contained proxy_cache_convert_head
syn keyword ngxDirective contained proxy_cache_key
syn keyword ngxDirective contained proxy_cache_lock
syn keyword ngxDirective contained proxy_cache_lock_age
syn keyword ngxDirective contained proxy_cache_lock_timeout
syn keyword ngxDirective contained proxy_cache_max_range_offset
syn keyword ngxDirective contained proxy_cache_methods
syn keyword ngxDirective contained proxy_cache_min_uses
syn keyword ngxDirective contained proxy_cache_path
syn keyword ngxDirective contained proxy_cache_purge
syn keyword ngxDirective contained proxy_cache_revalidate
syn keyword ngxDirective contained proxy_cache_use_stale
syn keyword ngxDirective contained proxy_cache_valid
syn keyword ngxDirective contained proxy_connect_timeout
syn keyword ngxDirective contained proxy_cookie_domain
syn keyword ngxDirective contained proxy_cookie_path
syn keyword ngxDirective contained proxy_download_rate
syn keyword ngxDirective contained proxy_force_ranges
syn keyword ngxDirective contained proxy_headers_hash_bucket_size
syn keyword ngxDirective contained proxy_headers_hash_max_size
syn keyword ngxDirective contained proxy_hide_header
syn keyword ngxDirective contained proxy_http_version
syn keyword ngxDirective contained proxy_ignore_client_abort
syn keyword ngxDirective contained proxy_ignore_headers
syn keyword ngxDirective contained proxy_intercept_errors
syn keyword ngxDirective contained proxy_limit_rate
syn keyword ngxDirective contained proxy_max_temp_file_size
syn keyword ngxDirective contained proxy_method
syn keyword ngxDirective contained proxy_next_upstream
syn keyword ngxDirective contained proxy_next_upstream_timeout
syn keyword ngxDirective contained proxy_next_upstream_tries
syn keyword ngxDirective contained proxy_no_cache
syn keyword ngxDirective contained proxy_pass_error_message
syn keyword ngxDirective contained proxy_pass_header
syn keyword ngxDirective contained proxy_pass_request_body
syn keyword ngxDirective contained proxy_pass_request_headers
syn keyword ngxDirective contained proxy_protocol
syn keyword ngxDirective contained proxy_protocol_timeout
syn keyword ngxDirective contained proxy_read_timeout
syn keyword ngxDirective contained proxy_redirect
syn keyword ngxDirective contained proxy_request_buffering
syn keyword ngxDirective contained proxy_responses
syn keyword ngxDirective contained proxy_send_lowat
syn keyword ngxDirective contained proxy_send_timeout
syn keyword ngxDirective contained proxy_set_body
syn keyword ngxDirective contained proxy_set_header
syn keyword ngxDirective contained proxy_ssl_certificate
syn keyword ngxDirective contained proxy_ssl_certificate_key
syn keyword ngxDirective contained proxy_ssl_ciphers
syn keyword ngxDirective contained proxy_ssl_crl
syn keyword ngxDirective contained proxy_ssl_name
syn keyword ngxDirective contained proxy_ssl_password_file
syn keyword ngxDirective contained proxy_ssl_protocols
syn keyword ngxDirective contained proxy_ssl_server_name
syn keyword ngxDirective contained proxy_ssl_session_reuse
syn keyword ngxDirective contained proxy_ssl_trusted_certificate
syn keyword ngxDirective contained proxy_ssl_verify
syn keyword ngxDirective contained proxy_ssl_verify_depth
syn keyword ngxDirective contained proxy_store
syn keyword ngxDirective contained proxy_store_access
syn keyword ngxDirective contained proxy_temp_file_write_size
syn keyword ngxDirective contained proxy_temp_path
syn keyword ngxDirective contained proxy_timeout
syn keyword ngxDirective contained proxy_upload_rate
syn keyword ngxDirective contained queue
syn keyword ngxDirective contained random_index
syn keyword ngxDirective contained read_ahead
syn keyword ngxDirective contained real_ip_header
syn keyword ngxDirective contained real_ip_recursive
syn keyword ngxDirective contained recursive_error_pages
syn keyword ngxDirective contained referer_hash_bucket_size
syn keyword ngxDirective contained referer_hash_max_size
syn keyword ngxDirective contained request_pool_size
syn keyword ngxDirective contained reset_timedout_connection
syn keyword ngxDirective contained resolver
syn keyword ngxDirective contained resolver_timeout
syn keyword ngxDirective contained rewrite_log
syn keyword ngxDirective contained rtsig_overflow_events
syn keyword ngxDirective contained rtsig_overflow_test
syn keyword ngxDirective contained rtsig_overflow_threshold
syn keyword ngxDirective contained rtsig_signo
syn keyword ngxDirective contained satisfy
syn keyword ngxDirective contained scgi_bind
syn keyword ngxDirective contained scgi_buffer_size
syn keyword ngxDirective contained scgi_buffering
syn keyword ngxDirective contained scgi_buffers
syn keyword ngxDirective contained scgi_busy_buffers_size
syn keyword ngxDirective contained scgi_cache
syn keyword ngxDirective contained scgi_cache_bypass
syn keyword ngxDirective contained scgi_cache_key
syn keyword ngxDirective contained scgi_cache_lock
syn keyword ngxDirective contained scgi_cache_lock_age
syn keyword ngxDirective contained scgi_cache_lock_timeout
syn keyword ngxDirective contained scgi_cache_max_range_offset
syn keyword ngxDirective contained scgi_cache_methods
syn keyword ngxDirective contained scgi_cache_min_uses
syn keyword ngxDirective contained scgi_cache_path
syn keyword ngxDirective contained scgi_cache_purge
syn keyword ngxDirective contained scgi_cache_revalidate
syn keyword ngxDirective contained scgi_cache_use_stale
syn keyword ngxDirective contained scgi_cache_valid
syn keyword ngxDirective contained scgi_connect_timeout
syn keyword ngxDirective contained scgi_force_ranges
syn keyword ngxDirective contained scgi_hide_header
syn keyword ngxDirective contained scgi_ignore_client_abort
syn keyword ngxDirective contained scgi_ignore_headers
syn keyword ngxDirective contained scgi_intercept_errors
syn keyword ngxDirective contained scgi_limit_rate
syn keyword ngxDirective contained scgi_max_temp_file_size
syn keyword ngxDirective contained scgi_next_upstream
syn keyword ngxDirective contained scgi_next_upstream_timeout
syn keyword ngxDirective contained scgi_next_upstream_tries
syn keyword ngxDirective contained scgi_no_cache
syn keyword ngxDirective contained scgi_param
syn keyword ngxDirective contained scgi_pass_header
syn keyword ngxDirective contained scgi_pass_request_body
syn keyword ngxDirective contained scgi_pass_request_headers
syn keyword ngxDirective contained scgi_read_timeout
syn keyword ngxDirective contained scgi_request_buffering
syn keyword ngxDirective contained scgi_send_timeout
syn keyword ngxDirective contained scgi_store
syn keyword ngxDirective contained scgi_store_access
syn keyword ngxDirective contained scgi_temp_file_write_size
syn keyword ngxDirective contained scgi_temp_path
syn keyword ngxDirective contained secure_link
syn keyword ngxDirective contained secure_link_md5
syn keyword ngxDirective contained secure_link_secret
syn keyword ngxDirective contained send_lowat
syn keyword ngxDirective contained send_timeout
syn keyword ngxDirective contained sendfile
syn keyword ngxDirective contained sendfile_max_chunk
syn keyword ngxDirective contained server_name_in_redirect
syn keyword ngxDirective contained server_names_hash_bucket_size
syn keyword ngxDirective contained server_names_hash_max_size
syn keyword ngxDirective contained server_tokens
syn keyword ngxDirective contained session_log
syn keyword ngxDirective contained session_log_format
syn keyword ngxDirective contained session_log_zone
syn keyword ngxDirective contained set_real_ip_from
syn keyword ngxDirective contained slice
syn keyword ngxDirective contained smtp_auth
syn keyword ngxDirective contained smtp_capabilities
syn keyword ngxDirective contained smtp_client_buffer
syn keyword ngxDirective contained smtp_greeting_delay
syn keyword ngxDirective contained source_charset
syn keyword ngxDirective contained spdy_chunk_size
syn keyword ngxDirective contained spdy_headers_comp
syn keyword ngxDirective contained spdy_keepalive_timeout
syn keyword ngxDirective contained spdy_max_concurrent_streams
syn keyword ngxDirective contained spdy_pool_size
syn keyword ngxDirective contained spdy_recv_buffer_size
syn keyword ngxDirective contained spdy_recv_timeout
syn keyword ngxDirective contained spdy_streams_index_size
syn keyword ngxDirective contained ssi
syn keyword ngxDirective contained ssi_ignore_recycled_buffers
syn keyword ngxDirective contained ssi_last_modified
syn keyword ngxDirective contained ssi_min_file_chunk
syn keyword ngxDirective contained ssi_silent_errors
syn keyword ngxDirective contained ssi_types
syn keyword ngxDirective contained ssi_value_length
syn keyword ngxDirective contained ssl
syn keyword ngxDirective contained ssl_buffer_size
syn keyword ngxDirective contained ssl_certificate
syn keyword ngxDirective contained ssl_certificate_key
syn keyword ngxDirective contained ssl_ciphers
syn keyword ngxDirective contained ssl_client_certificate
syn keyword ngxDirective contained ssl_crl
syn keyword ngxDirective contained ssl_dhparam
syn keyword ngxDirective contained ssl_ecdh_curve
syn keyword ngxDirective contained ssl_engine
syn keyword ngxDirective contained ssl_handshake_timeout
syn keyword ngxDirective contained ssl_password_file
syn keyword ngxDirective contained ssl_prefer_server_ciphers
syn keyword ngxDirective contained ssl_preread
syn keyword ngxDirective contained ssl_protocols
syn keyword ngxDirective contained ssl_session_cache
syn keyword ngxDirective contained ssl_session_ticket_key
syn keyword ngxDirective contained ssl_session_tickets
syn keyword ngxDirective contained ssl_session_timeout
syn keyword ngxDirective contained ssl_stapling
syn keyword ngxDirective contained ssl_stapling_file
syn keyword ngxDirective contained ssl_stapling_responder
syn keyword ngxDirective contained ssl_stapling_verify
syn keyword ngxDirective contained ssl_trusted_certificate
syn keyword ngxDirective contained ssl_verify_client
syn keyword ngxDirective contained ssl_verify_depth
syn keyword ngxDirective contained starttls
syn keyword ngxDirective contained state
syn keyword ngxDirective contained status
syn keyword ngxDirective contained status_format
syn keyword ngxDirective contained status_zone
syn keyword ngxDirective contained sticky
syn keyword ngxDirective contained sticky_cookie_insert
syn keyword ngxDirective contained stub_status
syn keyword ngxDirective contained sub_filter
syn keyword ngxDirective contained sub_filter_last_modified
syn keyword ngxDirective contained sub_filter_once
syn keyword ngxDirective contained sub_filter_types
syn keyword ngxDirective contained tcp_nodelay
syn keyword ngxDirective contained tcp_nopush
syn keyword ngxDirective contained thread_pool
syn keyword ngxDirective contained thread_stack_size
syn keyword ngxDirective contained timeout
syn keyword ngxDirective contained timer_resolution
syn keyword ngxDirective contained types_hash_bucket_size
syn keyword ngxDirective contained types_hash_max_size
syn keyword ngxDirective contained underscores_in_headers
syn keyword ngxDirective contained uninitialized_variable_warn
syn keyword ngxDirective contained upstream_conf
syn keyword ngxDirective contained use
syn keyword ngxDirective contained user
syn keyword ngxDirective contained userid
syn keyword ngxDirective contained userid_domain
syn keyword ngxDirective contained userid_expires
syn keyword ngxDirective contained userid_mark
syn keyword ngxDirective contained userid_name
syn keyword ngxDirective contained userid_p3p
syn keyword ngxDirective contained userid_path
syn keyword ngxDirective contained userid_service
syn keyword ngxDirective contained uwsgi_bind
syn keyword ngxDirective contained uwsgi_buffer_size
syn keyword ngxDirective contained uwsgi_buffering
syn keyword ngxDirective contained uwsgi_buffers
syn keyword ngxDirective contained uwsgi_busy_buffers_size
syn keyword ngxDirective contained uwsgi_cache
syn keyword ngxDirective contained uwsgi_cache_bypass
syn keyword ngxDirective contained uwsgi_cache_key
syn keyword ngxDirective contained uwsgi_cache_lock
syn keyword ngxDirective contained uwsgi_cache_lock_age
syn keyword ngxDirective contained uwsgi_cache_lock_timeout
syn keyword ngxDirective contained uwsgi_cache_methods
syn keyword ngxDirective contained uwsgi_cache_min_uses
syn keyword ngxDirective contained uwsgi_cache_path
syn keyword ngxDirective contained uwsgi_cache_purge
syn keyword ngxDirective contained uwsgi_cache_revalidate
syn keyword ngxDirective contained uwsgi_cache_use_stale
syn keyword ngxDirective contained uwsgi_cache_valid
syn keyword ngxDirective contained uwsgi_connect_timeout
syn keyword ngxDirective contained uwsgi_force_ranges
syn keyword ngxDirective contained uwsgi_hide_header
syn keyword ngxDirective contained uwsgi_ignore_client_abort
syn keyword ngxDirective contained uwsgi_ignore_headers
syn keyword ngxDirective contained uwsgi_intercept_errors
syn keyword ngxDirective contained uwsgi_limit_rate
syn keyword ngxDirective contained uwsgi_max_temp_file_size
syn keyword ngxDirective contained uwsgi_modifier1
syn keyword ngxDirective contained uwsgi_modifier2
syn keyword ngxDirective contained uwsgi_next_upstream
syn keyword ngxDirective contained uwsgi_next_upstream_timeout
syn keyword ngxDirective contained uwsgi_next_upstream_tries
syn keyword ngxDirective contained uwsgi_no_cache
syn keyword ngxDirective contained uwsgi_param
syn keyword ngxDirective contained uwsgi_pass
syn keyword ngxDirective contained uwsgi_pass_header
syn keyword ngxDirective contained uwsgi_pass_request_body
syn keyword ngxDirective contained uwsgi_pass_request_headers
syn keyword ngxDirective contained uwsgi_read_timeout
syn keyword ngxDirective contained uwsgi_request_buffering
syn keyword ngxDirective contained uwsgi_send_timeout
syn keyword ngxDirective contained uwsgi_ssl_certificate
syn keyword ngxDirective contained uwsgi_ssl_certificate_key
syn keyword ngxDirective contained uwsgi_ssl_ciphers
syn keyword ngxDirective contained uwsgi_ssl_crl
syn keyword ngxDirective contained uwsgi_ssl_name
syn keyword ngxDirective contained uwsgi_ssl_password_file
syn keyword ngxDirective contained uwsgi_ssl_protocols
syn keyword ngxDirective contained uwsgi_ssl_server_name
syn keyword ngxDirective contained uwsgi_ssl_session_reuse
syn keyword ngxDirective contained uwsgi_ssl_trusted_certificate
syn keyword ngxDirective contained uwsgi_ssl_verify
syn keyword ngxDirective contained uwsgi_ssl_verify_depth
syn keyword ngxDirective contained uwsgi_store
syn keyword ngxDirective contained uwsgi_store_access
syn keyword ngxDirective contained uwsgi_string
syn keyword ngxDirective contained uwsgi_temp_file_write_size
syn keyword ngxDirective contained uwsgi_temp_path
syn keyword ngxDirective contained valid_referers
syn keyword ngxDirective contained variables_hash_bucket_size
syn keyword ngxDirective contained variables_hash_max_size
syn keyword ngxDirective contained worker_aio_requests
syn keyword ngxDirective contained worker_connections
syn keyword ngxDirective contained worker_cpu_affinity
syn keyword ngxDirective contained worker_priority
syn keyword ngxDirective contained worker_processes
syn keyword ngxDirective contained worker_rlimit_core
syn keyword ngxDirective contained worker_rlimit_nofile
syn keyword ngxDirective contained worker_rlimit_sigpending
syn keyword ngxDirective contained worker_threads
syn keyword ngxDirective contained working_directory
syn keyword ngxDirective contained xclient
syn keyword ngxDirective contained xml_entities
syn keyword ngxDirective contained xslt_last_modified
syn keyword ngxDirective contained xslt_param
syn keyword ngxDirective contained xslt_string_param
syn keyword ngxDirective contained xslt_stylesheet
syn keyword ngxDirective contained xslt_types
syn keyword ngxDirective contained zone

" 3rd party module list:
" https://www.nginx.com/resources/wiki/modules/

" Accept Language Module <https://www.nginx.com/resources/wiki/modules/accept_language/>
" Parses the Accept-Language header and gives the most suitable locale from a list of supported locales.
syn keyword ngxDirectiveThirdParty contained set_from_accept_language

" Access Key Module (DEPRECATED) <http://wiki.nginx.org/NginxHttpAccessKeyModule>
" Denies access unless the request URL contains an access key.
syn keyword ngxDirectiveDeprecated contained accesskey
syn keyword ngxDirectiveDeprecated contained accesskey_arg
syn keyword ngxDirectiveDeprecated contained accesskey_hashmethod
syn keyword ngxDirectiveDeprecated contained accesskey_signature

" Asynchronous FastCGI Module <https://github.com/rsms/afcgi>
" Primarily a modified version of the Nginx FastCGI module which implements multiplexing of connections, allowing a single FastCGI server to handle many concurrent requests.
" syn keyword ngxDirectiveThirdParty contained fastcgi_bind
" syn keyword ngxDirectiveThirdParty contained fastcgi_buffer_size
" syn keyword ngxDirectiveThirdParty contained fastcgi_buffers
" syn keyword ngxDirectiveThirdParty contained fastcgi_busy_buffers_size
" syn keyword ngxDirectiveThirdParty contained fastcgi_cache
" syn keyword ngxDirectiveThirdParty contained fastcgi_cache_key
" syn keyword ngxDirectiveThirdParty contained fastcgi_cache_methods
" syn keyword ngxDirectiveThirdParty contained fastcgi_cache_min_uses
" syn keyword ngxDirectiveThirdParty contained fastcgi_cache_path
" syn keyword ngxDirectiveThirdParty contained fastcgi_cache_use_stale
" syn keyword ngxDirectiveThirdParty contained fastcgi_cache_valid
" syn keyword ngxDirectiveThirdParty contained fastcgi_catch_stderr
" syn keyword ngxDirectiveThirdParty contained fastcgi_connect_timeout
" syn keyword ngxDirectiveThirdParty contained fastcgi_hide_header
" syn keyword ngxDirectiveThirdParty contained fastcgi_ignore_client_abort
" syn keyword ngxDirectiveThirdParty contained fastcgi_ignore_headers
" syn keyword ngxDirectiveThirdParty contained fastcgi_index
" syn keyword ngxDirectiveThirdParty contained fastcgi_intercept_errors
" syn keyword ngxDirectiveThirdParty contained fastcgi_max_temp_file_size
" syn keyword ngxDirectiveThirdParty contained fastcgi_next_upstream
" syn keyword ngxDirectiveThirdParty contained fastcgi_param
" syn keyword ngxDirectiveThirdParty contained fastcgi_pass
" syn keyword ngxDirectiveThirdParty contained fastcgi_pass_header
" syn keyword ngxDirectiveThirdParty contained fastcgi_pass_request_body
" syn keyword ngxDirectiveThirdParty contained fastcgi_pass_request_headers
" syn keyword ngxDirectiveThirdParty contained fastcgi_read_timeout
" syn keyword ngxDirectiveThirdParty contained fastcgi_send_lowat
" syn keyword ngxDirectiveThirdParty contained fastcgi_send_timeout
" syn keyword ngxDirectiveThirdParty contained fastcgi_split_path_info
" syn keyword ngxDirectiveThirdParty contained fastcgi_store
" syn keyword ngxDirectiveThirdParty contained fastcgi_store_access
" syn keyword ngxDirectiveThirdParty contained fastcgi_temp_file_write_size
" syn keyword ngxDirectiveThirdParty contained fastcgi_temp_path
syn keyword ngxDirectiveDeprecated contained fastcgi_upstream_fail_timeout
syn keyword ngxDirectiveDeprecated contained fastcgi_upstream_max_fails

" Akamai G2O Module <https://github.com/kaltura/nginx_mod_akamai_g2o>
" Nginx Module for Authenticating Akamai G2O requests
syn keyword ngxDirectiveThirdParty contained g2o
syn keyword ngxDirectiveThirdParty contained g2o_nonce
syn keyword ngxDirectiveThirdParty contained g2o_key

" Lua Module <https://github.com/alacner/nginx_lua_module>
" You can be very simple to execute lua code for nginx
syn keyword ngxDirectiveThirdParty contained lua_file

" Array Variable Module <https://github.com/openresty/array-var-nginx-module>
" Add support for array-typed variables to nginx config files
syn keyword ngxDirectiveThirdParty contained array_split
syn keyword ngxDirectiveThirdParty contained array_join
syn keyword ngxDirectiveThirdParty contained array_map
syn keyword ngxDirectiveThirdParty contained array_map_op

" Nginx Audio Track for HTTP Live Streaming <https://github.com/flavioribeiro/nginx-audio-track-for-hls-module>
" This nginx module generates audio track for hls streams on the fly.
syn keyword ngxDirectiveThirdParty contained ngx_hls_audio_track
syn keyword ngxDirectiveThirdParty contained ngx_hls_audio_track_rootpath
syn keyword ngxDirectiveThirdParty contained ngx_hls_audio_track_output_format
syn keyword ngxDirectiveThirdParty contained ngx_hls_audio_track_output_header

" AWS Proxy Module <https://github.com/anomalizer/ngx_aws_auth>
" Nginx module to proxy to authenticated AWS services
syn keyword ngxDirectiveThirdParty contained aws_access_key
syn keyword ngxDirectiveThirdParty contained aws_key_scope
syn keyword ngxDirectiveThirdParty contained aws_signing_key
syn keyword ngxDirectiveThirdParty contained aws_endpoint
syn keyword ngxDirectiveThirdParty contained aws_s3_bucket
syn keyword ngxDirectiveThirdParty contained aws_sign

" Backtrace module <https://github.com/alibaba/nginx-backtrace>
" A Nginx module to dump backtrace when a worker process exits abnormally
syn keyword ngxDirectiveThirdParty contained backtrace_log
syn keyword ngxDirectiveThirdParty contained backtrace_max_stack_size

" Brotli Module <https://github.com/google/ngx_brotli>
" Nginx module for Brotli compression
syn keyword ngxDirectiveThirdParty contained brotli_static
syn keyword ngxDirectiveThirdParty contained brotli
syn keyword ngxDirectiveThirdParty contained brotli_types
syn keyword ngxDirectiveThirdParty contained brotli_buffers
syn keyword ngxDirectiveThirdParty contained brotli_comp_level
syn keyword ngxDirectiveThirdParty contained brotli_window
syn keyword ngxDirectiveThirdParty contained brotli_min_length

" Cache Purge Module <https://github.com/FRiCKLE/ngx_cache_purge>
" Adds ability to purge content from FastCGI, proxy, SCGI and uWSGI caches.
syn keyword ngxDirectiveThirdParty contained fastcgi_cache_purge
syn keyword ngxDirectiveThirdParty contained proxy_cache_purge
" syn keyword ngxDirectiveThirdParty contained scgi_cache_purge
" syn keyword ngxDirectiveThirdParty contained uwsgi_cache_purge

" Chunkin Module (DEPRECATED) <http://wiki.nginx.org/NginxHttpChunkinModule>
" HTTP 1.1 chunked-encoding request body support for Nginx.
syn keyword ngxDirectiveDeprecated contained chunkin
syn keyword ngxDirectiveDeprecated contained chunkin_keepalive
syn keyword ngxDirectiveDeprecated contained chunkin_max_chunks_per_buf
syn keyword ngxDirectiveDeprecated contained chunkin_resume

" Circle GIF Module <https://github.com/evanmiller/nginx_circle_gif>
" Generates simple circle images with the colors and size specified in the URL.
syn keyword ngxDirectiveThirdParty contained circle_gif
syn keyword ngxDirectiveThirdParty contained circle_gif_max_radius
syn keyword ngxDirectiveThirdParty contained circle_gif_min_radius
syn keyword ngxDirectiveThirdParty contained circle_gif_step_radius

" Nginx-Clojure Module <http://nginx-clojure.github.io/index.html>
" Parses the Accept-Language header and gives the most suitable locale from a list of supported locales.
syn keyword ngxDirectiveThirdParty contained jvm_path
syn keyword ngxDirectiveThirdParty contained jvm_var
syn keyword ngxDirectiveThirdParty contained jvm_classpath
syn keyword ngxDirectiveThirdParty contained jvm_classpath_check
syn keyword ngxDirectiveThirdParty contained jvm_workers
syn keyword ngxDirectiveThirdParty contained jvm_options
syn keyword ngxDirectiveThirdParty contained jvm_handler_type
syn keyword ngxDirectiveThirdParty contained jvm_init_handler_name
syn keyword ngxDirectiveThirdParty contained jvm_init_handler_code
syn keyword ngxDirectiveThirdParty contained jvm_exit_handler_name
syn keyword ngxDirectiveThirdParty contained jvm_exit_handler_code
syn keyword ngxDirectiveThirdParty contained handlers_lazy_init
syn keyword ngxDirectiveThirdParty contained auto_upgrade_ws
syn keyword ngxDirectiveThirdParty contained content_handler_type
syn keyword ngxDirectiveThirdParty contained content_handler_name
syn keyword ngxDirectiveThirdParty contained content_handler_code
syn keyword ngxDirectiveThirdParty contained rewrite_handler_type
syn keyword ngxDirectiveThirdParty contained rewrite_handler_name
syn keyword ngxDirectiveThirdParty contained rewrite_handler_code
syn keyword ngxDirectiveThirdParty contained access_handler_type
syn keyword ngxDirectiveThirdParty contained access_handler_name
syn keyword ngxDirectiveThirdParty contained access_handler_code
syn keyword ngxDirectiveThirdParty contained header_filter_type
syn keyword ngxDirectiveThirdParty contained header_filter_name
syn keyword ngxDirectiveThirdParty contained header_filter_code
syn keyword ngxDirectiveThirdParty contained content_handler_property
syn keyword ngxDirectiveThirdParty contained rewrite_handler_property
syn keyword ngxDirectiveThirdParty contained access_handler_property
syn keyword ngxDirectiveThirdParty contained header_filter_property
syn keyword ngxDirectiveThirdParty contained always_read_body
syn keyword ngxDirectiveThirdParty contained shared_map
syn keyword ngxDirectiveThirdParty contained write_page_size

" Upstream Consistent Hash <https://www.nginx.com/resources/wiki/modules/consistent_hash/>
" A load balancer that uses an internal consistent hash ring to select the right backend node.
syn keyword ngxDirectiveThirdParty contained consistent_hash

" Nginx Development Kit <https://github.com/simpl/ngx_devel_kit>
" The NDK is an Nginx module that is designed to extend the core functionality of the excellent Nginx webserver in a way that can be used as a basis of other Nginx modules.
" NDK_UPSTREAM_LIST
" This submodule provides a directive that creates a list of upstreams, with optional weighting. This list can then be used by other modules to hash over the upstreams however they choose.
syn keyword ngxDirectiveThirdParty contained upstream_list

" Drizzle Module <https://www.nginx.com/resources/wiki/modules/drizzle/>
" Upstream module for talking to MySQL and Drizzle directly
syn keyword ngxDirectiveThirdParty contained drizzle_server
syn keyword ngxDirectiveThirdParty contained drizzle_keepalive
syn keyword ngxDirectiveThirdParty contained drizzle_query
syn keyword ngxDirectiveThirdParty contained drizzle_pass
syn keyword ngxDirectiveThirdParty contained drizzle_connect_timeout
syn keyword ngxDirectiveThirdParty contained drizzle_send_query_timeout
syn keyword ngxDirectiveThirdParty contained drizzle_recv_cols_timeout
syn keyword ngxDirectiveThirdParty contained drizzle_recv_rows_timeout
syn keyword ngxDirectiveThirdParty contained drizzle_buffer_size
syn keyword ngxDirectiveThirdParty contained drizzle_module_header
syn keyword ngxDirectiveThirdParty contained drizzle_status

" Dynamic ETags Module <https://github.com/kali/nginx-dynamic-etags>
" Attempt at handling ETag / If-None-Match on proxied content.
syn keyword ngxDirectiveThirdParty contained dynamic_etags

" Echo Module <https://www.nginx.com/resources/wiki/modules/echo/>
" Bringing the power of "echo", "sleep", "time" and more to Nginx's config file
syn keyword ngxDirectiveThirdParty contained echo
syn keyword ngxDirectiveThirdParty contained echo_duplicate
syn keyword ngxDirectiveThirdParty contained echo_flush
syn keyword ngxDirectiveThirdParty contained echo_sleep
syn keyword ngxDirectiveThirdParty contained echo_blocking_sleep
syn keyword ngxDirectiveThirdParty contained echo_reset_timer
syn keyword ngxDirectiveThirdParty contained echo_read_request_body
syn keyword ngxDirectiveThirdParty contained echo_location_async
syn keyword ngxDirectiveThirdParty contained echo_location
syn keyword ngxDirectiveThirdParty contained echo_subrequest_async
syn keyword ngxDirectiveThirdParty contained echo_subrequest
syn keyword ngxDirectiveThirdParty contained echo_foreach_split
syn keyword ngxDirectiveThirdParty contained echo_end
syn keyword ngxDirectiveThirdParty contained echo_request_body
syn keyword ngxDirectiveThirdParty contained echo_exec
syn keyword ngxDirectiveThirdParty contained echo_status
syn keyword ngxDirectiveThirdParty contained echo_before_body
syn keyword ngxDirectiveThirdParty contained echo_after_body

" Encrypted Session Module <https://github.com/openresty/encrypted-session-nginx-module>
" Encrypt and decrypt nginx variable values
syn keyword ngxDirectiveThirdParty contained encrypted_session_key
syn keyword ngxDirectiveThirdParty contained encrypted_session_iv
syn keyword ngxDirectiveThirdParty contained encrypted_session_expires
syn keyword ngxDirectiveThirdParty contained set_encrypt_session
syn keyword ngxDirectiveThirdParty contained set_decrypt_session

" Enhanced Memcached Module <https://github.com/bpaquet/ngx_http_enhanced_memcached_module>
" This module is based on the standard Nginx Memcached module, with some additonal features
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_pass
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_hash_keys_with_md5
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_allow_put
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_allow_delete
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_stats
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_flush
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_flush_namespace
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_bind
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_connect_timeout
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_send_timeout
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_buffer_size
syn keyword ngxDirectiveThirdParty contained enhanced_memcached_read_timeout

" Events Module (DEPRECATED) <http://docs.dutov.org/nginx_modules_events_en.html>
" Provides options for start/stop events.
syn keyword ngxDirectiveDeprecated contained on_start
syn keyword ngxDirectiveDeprecated contained on_stop

" EY Balancer Module <https://github.com/ezmobius/nginx-ey-balancer>
" Adds a request queue to Nginx that allows the limiting of concurrent requests passed to the upstream.
syn keyword ngxDirectiveThirdParty contained max_connections
syn keyword ngxDirectiveThirdParty contained max_connections_max_queue_length
syn keyword ngxDirectiveThirdParty contained max_connections_queue_timeout

" Upstream Fair Balancer <https://www.nginx.com/resources/wiki/modules/fair_balancer/>
" Sends an incoming request to the least-busy backend server, rather than distributing requests round-robin.
syn keyword ngxDirectiveThirdParty contained fair
syn keyword ngxDirectiveThirdParty contained upstream_fair_shm_size

" Fancy Indexes Module <https://github.com/aperezdc/ngx-fancyindex>
" Like the built-in autoindex module, but fancier.
syn keyword ngxDirectiveThirdParty contained fancyindex
syn keyword ngxDirectiveThirdParty contained fancyindex_default_sort
syn keyword ngxDirectiveThirdParty contained fancyindex_directories_first
syn keyword ngxDirectiveThirdParty contained fancyindex_css_href
syn keyword ngxDirectiveThirdParty contained fancyindex_exact_size
syn keyword ngxDirectiveThirdParty contained fancyindex_name_length
syn keyword ngxDirectiveThirdParty contained fancyindex_footer
syn keyword ngxDirectiveThirdParty contained fancyindex_header
syn keyword ngxDirectiveThirdParty contained fancyindex_show_path
syn keyword ngxDirectiveThirdParty contained fancyindex_ignore
syn keyword ngxDirectiveThirdParty contained fancyindex_hide_symlinks
syn keyword ngxDirectiveThirdParty contained fancyindex_localtime
syn keyword ngxDirectiveThirdParty contained fancyindex_time_format

" Form Auth Module <https://github.com/veruu/ngx_form_auth>
" Provides authentication and authorization with credentials submitted via POST request
syn keyword ngxDirectiveThirdParty contained form_auth
syn keyword ngxDirectiveThirdParty contained form_auth_pam_service
syn keyword ngxDirectiveThirdParty contained form_auth_login
syn keyword ngxDirectiveThirdParty contained form_auth_password
syn keyword ngxDirectiveThirdParty contained form_auth_remote_user

" Form Input Module <https://github.com/calio/form-input-nginx-module>
" Reads HTTP POST and PUT request body encoded in "application/x-www-form-urlencoded" and parses the arguments into nginx variables.
syn keyword ngxDirectiveThirdParty contained set_form_input
syn keyword ngxDirectiveThirdParty contained set_form_input_multi

" GeoIP Module (DEPRECATED) <http://wiki.nginx.org/NginxHttp3rdPartyGeoIPModule>
" Country code lookups via the MaxMind GeoIP API.
syn keyword ngxDirectiveDeprecated contained geoip_country_file

" GeoIP 2 Module <https://github.com/leev/ngx_http_geoip2_module>
" Creates variables with values from the maxmind geoip2 databases based on the client IP
syn keyword ngxDirectiveThirdParty contained geoip2

" GridFS Module <https://github.com/mdirolf/nginx-gridfs>
" Nginx module for serving files from MongoDB's GridFS
syn keyword ngxDirectiveThirdParty contained gridfs

" Headers More Module <https://github.com/openresty/headers-more-nginx-module>
" Set and clear input and output headers...more than "add"!
syn keyword ngxDirectiveThirdParty contained more_clear_headers
syn keyword ngxDirectiveThirdParty contained more_clear_input_headers
syn keyword ngxDirectiveThirdParty contained more_set_headers
syn keyword ngxDirectiveThirdParty contained more_set_input_headers

" Health Checks Upstreams Module <https://www.nginx.com/resources/wiki/modules/healthcheck/>
" Polls backends and if they respond with HTTP 200 + an optional request body, they are marked good. Otherwise, they are marked bad.
syn keyword ngxDirectiveThirdParty contained healthcheck_enabled
syn keyword ngxDirectiveThirdParty contained healthcheck_delay
syn keyword ngxDirectiveThirdParty contained healthcheck_timeout
syn keyword ngxDirectiveThirdParty contained healthcheck_failcount
syn keyword ngxDirectiveThirdParty contained healthcheck_send
syn keyword ngxDirectiveThirdParty contained healthcheck_expected
syn keyword ngxDirectiveThirdParty contained healthcheck_buffer
syn keyword ngxDirectiveThirdParty contained healthcheck_status

" HTTP Accounting Module <https://github.com/Lax/ngx_http_accounting_module>
" Add traffic stat function to nginx. Useful for http accounting based on nginx configuration logic
syn keyword ngxDirectiveThirdParty contained http_accounting
syn keyword ngxDirectiveThirdParty contained http_accounting_log
syn keyword ngxDirectiveThirdParty contained http_accounting_id
syn keyword ngxDirectiveThirdParty contained http_accounting_interval
syn keyword ngxDirectiveThirdParty contained http_accounting_perturb

" Nginx Digest Authentication module <https://github.com/atomx/nginx-http-auth-digest>
" Digest Authentication for Nginx
syn keyword ngxDirectiveThirdParty contained auth_digest
syn keyword ngxDirectiveThirdParty contained auth_digest_user_file
syn keyword ngxDirectiveThirdParty contained auth_digest_timeout
syn keyword ngxDirectiveThirdParty contained auth_digest_expires
syn keyword ngxDirectiveThirdParty contained auth_digest_replays
syn keyword ngxDirectiveThirdParty contained auth_digest_shm_size

" Auth PAM Module <https://github.com/sto/ngx_http_auth_pam_module>
" HTTP Basic Authentication using PAM.
syn keyword ngxDirectiveThirdParty contained auth_pam
syn keyword ngxDirectiveThirdParty contained auth_pam_service_name

" HTTP Auth Request Module <http://nginx.org/en/docs/http/ngx_http_auth_request_module.html>
" Implements client authorization based on the result of a subrequest
" syn keyword ngxDirectiveThirdParty contained auth_request
" syn keyword ngxDirectiveThirdParty contained auth_request_set

" HTTP Concatenation module for Nginx <https://github.com/alibaba/nginx-http-concat>
" A Nginx module for concatenating files in a given context: CSS and JS files usually
syn keyword ngxDirectiveThirdParty contained concat
syn keyword ngxDirectiveThirdParty contained concat_types
syn keyword ngxDirectiveThirdParty contained concat_unique
syn keyword ngxDirectiveThirdParty contained concat_max_files
syn keyword ngxDirectiveThirdParty contained concat_delimiter
syn keyword ngxDirectiveThirdParty contained concat_ignore_file_error

" HTTP Dynamic Upstream Module <https://github.com/yzprofile/ngx_http_dyups_module>
" Update upstreams' config by restful interface
syn keyword ngxDirectiveThirdParty contained dyups_interface
syn keyword ngxDirectiveThirdParty contained dyups_read_msg_timeout
syn keyword ngxDirectiveThirdParty contained dyups_shm_zone_size
syn keyword ngxDirectiveThirdParty contained dyups_upstream_conf
syn keyword ngxDirectiveThirdParty contained dyups_trylock

" HTTP Footer If Filter Module <https://github.com/flygoast/ngx_http_footer_if_filter>
" The ngx_http_footer_if_filter_module is used to add given content to the end of the response according to the condition specified.
syn keyword ngxDirectiveThirdParty contained footer_if

" HTTP Footer Filter Module <https://github.com/alibaba/nginx-http-footer-filter>
" This module implements a body filter that adds a given string to the page footer.
syn keyword ngxDirectiveThirdParty contained footer
syn keyword ngxDirectiveThirdParty contained footer_types

" HTTP Internal Redirect Module <https://github.com/flygoast/ngx_http_internal_redirect>
" Make an internal redirect to the uri specified according to the condition specified.
syn keyword ngxDirectiveThirdParty contained internal_redirect_if
syn keyword ngxDirectiveThirdParty contained internal_redirect_if_no_postponed

" HTTP JavaScript Module <https://github.com/peter-leonov/ngx_http_js_module>
" Embedding SpiderMonkey. Nearly full port on Perl module.
syn keyword ngxDirectiveThirdParty contained js
syn keyword ngxDirectiveThirdParty contained js_filter
syn keyword ngxDirectiveThirdParty contained js_filter_types
syn keyword ngxDirectiveThirdParty contained js_load
syn keyword ngxDirectiveThirdParty contained js_maxmem
syn keyword ngxDirectiveThirdParty contained js_require
syn keyword ngxDirectiveThirdParty contained js_set
syn keyword ngxDirectiveThirdParty contained js_utf8

" HTTP Push Module (DEPRECATED) <http://pushmodule.slact.net/>
" Turn Nginx into an adept long-polling HTTP Push (Comet) server.
syn keyword ngxDirectiveDeprecated contained push_buffer_size
syn keyword ngxDirectiveDeprecated contained push_listener
syn keyword ngxDirectiveDeprecated contained push_message_timeout
syn keyword ngxDirectiveDeprecated contained push_queue_messages
syn keyword ngxDirectiveDeprecated contained push_sender

" HTTP Redis Module <https://www.nginx.com/resources/wiki/modules/redis/>
" Redis <http://code.google.com/p/redis/> support.
syn keyword ngxDirectiveThirdParty contained redis_bind
syn keyword ngxDirectiveThirdParty contained redis_buffer_size
syn keyword ngxDirectiveThirdParty contained redis_connect_timeout
syn keyword ngxDirectiveThirdParty contained redis_next_upstream
syn keyword ngxDirectiveThirdParty contained redis_pass
syn keyword ngxDirectiveThirdParty contained redis_read_timeout
syn keyword ngxDirectiveThirdParty contained redis_send_timeout

" Iconv Module <https://github.com/calio/iconv-nginx-module>
" A character conversion nginx module using libiconv
syn keyword ngxDirectiveThirdParty contained set_iconv
syn keyword ngxDirectiveThirdParty contained iconv_buffer_size
syn keyword ngxDirectiveThirdParty contained iconv_filter

" IP Blocker Module <https://github.com/tmthrgd/nginx-ip-blocker>
" An efficient shared memory IP blocking system for nginx.
syn keyword ngxDirectiveThirdParty contained ip_blocker

" IP2Location Module <https://github.com/chrislim2888/ip2location-nginx>
" Allows user to lookup for geolocation information using IP2Location database
syn keyword ngxDirectiveThirdParty contained ip2location_database

" JS Module <https://github.com/peter-leonov/ngx_http_js_module>
" Reflect the nginx functionality in JS
syn keyword ngxDirectiveThirdParty contained js
syn keyword ngxDirectiveThirdParty contained js_access
syn keyword ngxDirectiveThirdParty contained js_load
syn keyword ngxDirectiveThirdParty contained js_set

" Limit Upload Rate Module <https://github.com/cfsego/limit_upload_rate>
" Limit client-upload rate when they are sending request bodies to you
syn keyword ngxDirectiveThirdParty contained limit_upload_rate
syn keyword ngxDirectiveThirdParty contained limit_upload_rate_after

" Limit Upstream Module <https://github.com/cfsego/nginx-limit-upstream>
" Limit the number of connections to upstream for NGINX
syn keyword ngxDirectiveThirdParty contained limit_upstream_zone
syn keyword ngxDirectiveThirdParty contained limit_upstream_conn
syn keyword ngxDirectiveThirdParty contained limit_upstream_log_level

" Log If Module <https://github.com/cfsego/ngx_log_if>
" Conditional accesslog for nginx
syn keyword ngxDirectiveThirdParty contained access_log_bypass_if

" Log Request Speed (DEPRECATED) <http://wiki.nginx.org/NginxHttpLogRequestSpeed>
" Log the time it took to process each request.
syn keyword ngxDirectiveDeprecated contained log_request_speed_filter
syn keyword ngxDirectiveDeprecated contained log_request_speed_filter_timeout

" Log ZeroMQ Module <https://github.com/alticelabs/nginx-log-zmq>
" ZeroMQ logger module for nginx
syn keyword ngxDirectiveThirdParty contained log_zmq_server
syn keyword ngxDirectiveThirdParty contained log_zmq_endpoint
syn keyword ngxDirectiveThirdParty contained log_zmq_format
syn keyword ngxDirectiveThirdParty contained log_zmq_off

" Lower/UpperCase Module <https://github.com/replay/ngx_http_lower_upper_case>
" This module simply uppercases or lowercases a string and saves it into a new variable.
syn keyword ngxDirectiveThirdParty contained lower
syn keyword ngxDirectiveThirdParty contained upper

" Lua Upstream Module <https://github.com/openresty/lua-upstream-nginx-module>
" Nginx C module to expose Lua API to ngx_lua for Nginx upstreams

" Lua Module <https://github.com/openresty/lua-nginx-module>
" Embed the Power of Lua into NGINX HTTP servers
syn keyword ngxDirectiveThirdParty contained lua_use_default_type
syn keyword ngxDirectiveThirdParty contained lua_malloc_trim
syn keyword ngxDirectiveThirdParty contained lua_code_cache
syn keyword ngxDirectiveThirdParty contained lua_regex_cache_max_entries
syn keyword ngxDirectiveThirdParty contained lua_regex_match_limit
syn keyword ngxDirectiveThirdParty contained lua_package_path
syn keyword ngxDirectiveThirdParty contained lua_package_cpath
syn keyword ngxDirectiveThirdParty contained init_by_lua
syn keyword ngxDirectiveThirdParty contained init_by_lua_block
syn keyword ngxDirectiveThirdParty contained init_by_lua_file
syn keyword ngxDirectiveThirdParty contained init_worker_by_lua
syn keyword ngxDirectiveThirdParty contained init_worker_by_lua_block
syn keyword ngxDirectiveThirdParty contained init_worker_by_lua_file
syn keyword ngxDirectiveThirdParty contained set_by_lua
syn keyword ngxDirectiveThirdParty contained set_by_lua_block
syn keyword ngxDirectiveThirdParty contained set_by_lua_file
syn keyword ngxDirectiveThirdParty contained content_by_lua
syn keyword ngxDirectiveThirdParty contained content_by_lua_block
syn keyword ngxDirectiveThirdParty contained content_by_lua_file
syn keyword ngxDirectiveThirdParty contained rewrite_by_lua
syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_block
syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_file
syn keyword ngxDirectiveThirdParty contained access_by_lua
syn keyword ngxDirectiveThirdParty contained access_by_lua_block
syn keyword ngxDirectiveThirdParty contained access_by_lua_file
syn keyword ngxDirectiveThirdParty contained header_filter_by_lua
syn keyword ngxDirectiveThirdParty contained header_filter_by_lua_block
syn keyword ngxDirectiveThirdParty contained header_filter_by_lua_file
syn keyword ngxDirectiveThirdParty contained body_filter_by_lua
syn keyword ngxDirectiveThirdParty contained body_filter_by_lua_block
syn keyword ngxDirectiveThirdParty contained body_filter_by_lua_file
syn keyword ngxDirectiveThirdParty contained log_by_lua
syn keyword ngxDirectiveThirdParty contained log_by_lua_block
syn keyword ngxDirectiveThirdParty contained log_by_lua_file
syn keyword ngxDirectiveThirdParty contained balancer_by_lua_block
syn keyword ngxDirectiveThirdParty contained balancer_by_lua_file
syn keyword ngxDirectiveThirdParty contained lua_need_request_body
syn keyword ngxDirectiveThirdParty contained ssl_certificate_by_lua_block
syn keyword ngxDirectiveThirdParty contained ssl_certificate_by_lua_file
syn keyword ngxDirectiveThirdParty contained ssl_session_fetch_by_lua_block
syn keyword ngxDirectiveThirdParty contained ssl_session_fetch_by_lua_file
syn keyword ngxDirectiveThirdParty contained ssl_session_store_by_lua_block
syn keyword ngxDirectiveThirdParty contained ssl_session_store_by_lua_file
syn keyword ngxDirectiveThirdParty contained lua_shared_dict
syn keyword ngxDirectiveThirdParty contained lua_socket_connect_timeout
syn keyword ngxDirectiveThirdParty contained lua_socket_send_timeout
syn keyword ngxDirectiveThirdParty contained lua_socket_send_lowat
syn keyword ngxDirectiveThirdParty contained lua_socket_read_timeout
syn keyword ngxDirectiveThirdParty contained lua_socket_buffer_size
syn keyword ngxDirectiveThirdParty contained lua_socket_pool_size
syn keyword ngxDirectiveThirdParty contained lua_socket_keepalive_timeout
syn keyword ngxDirectiveThirdParty contained lua_socket_log_errors
syn keyword ngxDirectiveThirdParty contained lua_ssl_ciphers
syn keyword ngxDirectiveThirdParty contained lua_ssl_crl
syn keyword ngxDirectiveThirdParty contained lua_ssl_protocols
syn keyword ngxDirectiveThirdParty contained lua_ssl_trusted_certificate
syn keyword ngxDirectiveThirdParty contained lua_ssl_verify_depth
syn keyword ngxDirectiveThirdParty contained lua_http10_buffering
syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_no_postpone
syn keyword ngxDirectiveThirdParty contained access_by_lua_no_postpone
syn keyword ngxDirectiveThirdParty contained lua_transform_underscores_in_response_headers
syn keyword ngxDirectiveThirdParty contained lua_check_client_abort
syn keyword ngxDirectiveThirdParty contained lua_max_pending_timers
syn keyword ngxDirectiveThirdParty contained lua_max_running_timers

" MD5 Filter Module <https://github.com/kainswor/nginx_md5_filter>
" A content filter for nginx, which returns the md5 hash of the content otherwise returned.
syn keyword ngxDirectiveThirdParty contained md5_filter

" Memc Module <https://github.com/openresty/memc-nginx-module>
" An extended version of the standard memcached module that supports set, add, delete, and many more memcached commands.
syn keyword ngxDirectiveThirdParty contained memc_buffer_size
syn keyword ngxDirectiveThirdParty contained memc_cmds_allowed
syn keyword ngxDirectiveThirdParty contained memc_connect_timeout
syn keyword ngxDirectiveThirdParty contained memc_flags_to_last_modified
syn keyword ngxDirectiveThirdParty contained memc_next_upstream
syn keyword ngxDirectiveThirdParty contained memc_pass
syn keyword ngxDirectiveThirdParty contained memc_read_timeout
syn keyword ngxDirectiveThirdParty contained memc_send_timeout
syn keyword ngxDirectiveThirdParty contained memc_upstream_fail_timeout
syn keyword ngxDirectiveThirdParty contained memc_upstream_max_fails

" Mod Security Module <https://github.com/SpiderLabs/ModSecurity>
" ModSecurity is an open source, cross platform web application firewall (WAF) engine
syn keyword ngxDirectiveThirdParty contained ModSecurityConfig
syn keyword ngxDirectiveThirdParty contained ModSecurityEnabled
syn keyword ngxDirectiveThirdParty contained pool_context
syn keyword ngxDirectiveThirdParty contained pool_context_hash_size

" Mogilefs Module <http://www.grid.net.ru/nginx/mogilefs.en.html>
" MogileFS client for nginx web server.
syn keyword ngxDirectiveThirdParty contained mogilefs_pass
syn keyword ngxDirectiveThirdParty contained mogilefs_methods
syn keyword ngxDirectiveThirdParty contained mogilefs_domain
syn keyword ngxDirectiveThirdParty contained mogilefs_class
syn keyword ngxDirectiveThirdParty contained mogilefs_tracker
syn keyword ngxDirectiveThirdParty contained mogilefs_noverify
syn keyword ngxDirectiveThirdParty contained mogilefs_connect_timeout
syn keyword ngxDirectiveThirdParty contained mogilefs_send_timeout
syn keyword ngxDirectiveThirdParty contained mogilefs_read_timeout

" Mongo Module <https://github.com/simpl/ngx_mongo>
" Upstream module that allows nginx to communicate directly with MongoDB database.
syn keyword ngxDirectiveThirdParty contained mongo_auth
syn keyword ngxDirectiveThirdParty contained mongo_pass
syn keyword ngxDirectiveThirdParty contained mongo_query
syn keyword ngxDirectiveThirdParty contained mongo_json
syn keyword ngxDirectiveThirdParty contained mongo_bind
syn keyword ngxDirectiveThirdParty contained mongo_connect_timeout
syn keyword ngxDirectiveThirdParty contained mongo_send_timeout
syn keyword ngxDirectiveThirdParty contained mongo_read_timeout
syn keyword ngxDirectiveThirdParty contained mongo_buffering
syn keyword ngxDirectiveThirdParty contained mongo_buffer_size
syn keyword ngxDirectiveThirdParty contained mongo_buffers
syn keyword ngxDirectiveThirdParty contained mongo_busy_buffers_size
syn keyword ngxDirectiveThirdParty contained mongo_next_upstream

" MP4 Streaming Lite Module <https://www.nginx.com/resources/wiki/modules/mp4_streaming/>
" Will seek to a certain time within H.264/MP4 files when provided with a 'start' parameter in the URL.
" syn keyword ngxDirectiveThirdParty contained mp4

" NAXSI Module <https://github.com/nbs-system/naxsi>
" NAXSI is an open-source, high performance, low rules maintenance WAF for NGINX
syn keyword ngxDirectiveThirdParty contained DeniedUrl denied_url
syn keyword ngxDirectiveThirdParty contained LearningMode learning_mode
syn keyword ngxDirectiveThirdParty contained SecRulesEnabled rules_enabled
syn keyword ngxDirectiveThirdParty contained SecRulesDisabled rules_disabled
syn keyword ngxDirectiveThirdParty contained CheckRule check_rule
syn keyword ngxDirectiveThirdParty contained BasicRule basic_rule
syn keyword ngxDirectiveThirdParty contained MainRule main_rule
syn keyword ngxDirectiveThirdParty contained LibInjectionSql libinjection_sql
syn keyword ngxDirectiveThirdParty contained LibInjectionXss libinjection_xss

" Nchan Module <https://nchan.slact.net/>
" Fast, horizontally scalable, multiprocess pub/sub queuing server and proxy for HTTP, long-polling, Websockets and EventSource (SSE)
syn keyword ngxDirectiveThirdParty contained nchan_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_channel_id_split_delimiter
syn keyword ngxDirectiveThirdParty contained nchan_eventsource_event
syn keyword ngxDirectiveThirdParty contained nchan_longpoll_multipart_response
syn keyword ngxDirectiveThirdParty contained nchan_publisher
syn keyword ngxDirectiveThirdParty contained nchan_publisher_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_publisher_upstream_request
syn keyword ngxDirectiveThirdParty contained nchan_pubsub
syn keyword ngxDirectiveThirdParty contained nchan_subscribe_request
syn keyword ngxDirectiveThirdParty contained nchan_subscriber
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_compound_etag_message_id
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_first_message
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_http_raw_stream_separator
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_last_message_id
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_message_id_custom_etag_header
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_timeout
syn keyword ngxDirectiveThirdParty contained nchan_unsubscribe_request
syn keyword ngxDirectiveThirdParty contained nchan_websocket_ping_interval
syn keyword ngxDirectiveThirdParty contained nchan_authorize_request
syn keyword ngxDirectiveThirdParty contained nchan_max_reserved_memory
syn keyword ngxDirectiveThirdParty contained nchan_message_buffer_length
syn keyword ngxDirectiveThirdParty contained nchan_message_timeout
syn keyword ngxDirectiveThirdParty contained nchan_redis_idle_channel_cache_timeout
syn keyword ngxDirectiveThirdParty contained nchan_redis_namespace
syn keyword ngxDirectiveThirdParty contained nchan_redis_pass
syn keyword ngxDirectiveThirdParty contained nchan_redis_ping_interval
syn keyword ngxDirectiveThirdParty contained nchan_redis_server
syn keyword ngxDirectiveThirdParty contained nchan_redis_storage_mode
syn keyword ngxDirectiveThirdParty contained nchan_redis_url
syn keyword ngxDirectiveThirdParty contained nchan_store_messages
syn keyword ngxDirectiveThirdParty contained nchan_use_redis
syn keyword ngxDirectiveThirdParty contained nchan_access_control_allow_origin
syn keyword ngxDirectiveThirdParty contained nchan_channel_group
syn keyword ngxDirectiveThirdParty contained nchan_channel_group_accounting
syn keyword ngxDirectiveThirdParty contained nchan_group_location
syn keyword ngxDirectiveThirdParty contained nchan_group_max_channels
syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages
syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages_disk
syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages_memory
syn keyword ngxDirectiveThirdParty contained nchan_group_max_subscribers
syn keyword ngxDirectiveThirdParty contained nchan_subscribe_existing_channels_only
syn keyword ngxDirectiveThirdParty contained nchan_channel_event_string
syn keyword ngxDirectiveThirdParty contained nchan_channel_events_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_stub_status
syn keyword ngxDirectiveThirdParty contained nchan_max_channel_id_length
syn keyword ngxDirectiveThirdParty contained nchan_max_channel_subscribers
syn keyword ngxDirectiveThirdParty contained nchan_channel_timeout
syn keyword ngxDirectiveThirdParty contained nchan_storage_engine

" Nginx Notice Module <https://github.com/kr/nginx-notice>
" Serve static file to POST requests.
syn keyword ngxDirectiveThirdParty contained notice
syn keyword ngxDirectiveThirdParty contained notice_type

" OCSP Proxy Module <https://github.com/kyprizel/nginx_ocsp_proxy-module>
" Nginx OCSP processing module designed for response caching
syn keyword ngxDirectiveThirdParty contained ocsp_proxy
syn keyword ngxDirectiveThirdParty contained ocsp_cache_timeout

" Eval Module <https://github.com/openresty/nginx-eval-module>
" Module for nginx web server evaluates response of proxy or memcached module into variables.
syn keyword ngxDirectiveThirdParty contained eval
syn keyword ngxDirectiveThirdParty contained eval_escalate
syn keyword ngxDirectiveThirdParty contained eval_buffer_size
syn keyword ngxDirectiveThirdParty contained eval_override_content_type
syn keyword ngxDirectiveThirdParty contained eval_subrequest_in_memory

" OpenSSL Version Module <https://github.com/apcera/nginx-openssl-version>
" Nginx OpenSSL version check at startup
syn keyword ngxDirectiveThirdParty contained openssl_version_minimum
syn keyword ngxDirectiveThirdParty contained openssl_builddate_minimum

" Owner Match Module <https://www.nginx.com/resources/wiki/modules/owner_match/>
" Control access for specific owners and groups of files
syn keyword ngxDirectiveThirdParty contained omallow
syn keyword ngxDirectiveThirdParty contained omdeny

" Accept Language Module <https://www.nginx.com/resources/wiki/modules/accept_language/>
" Parses the Accept-Language header and gives the most suitable locale from a list of supported locales.
syn keyword ngxDirectiveThirdParty contained pagespeed

" PHP Memcache Standard Balancer Module <https://github.com/replay/ngx_http_php_memcache_standard_balancer>
" Loadbalancer that is compatible to the standard loadbalancer in the php-memcache module
syn keyword ngxDirectiveThirdParty contained hash_key

" PHP Session Module <https://github.com/replay/ngx_http_php_session>
" Nginx module to parse php sessions
syn keyword ngxDirectiveThirdParty contained php_session_parse
syn keyword ngxDirectiveThirdParty contained php_session_strip_formatting

" Phusion Passenger Module <https://www.phusionpassenger.com/library/config/nginx/>
" Passenger is an open source web application server.
syn keyword ngxDirectiveThirdParty contained passenger_root
syn keyword ngxDirectiveThirdParty contained passenger_enabled
syn keyword ngxDirectiveThirdParty contained passenger_base_uri
syn keyword ngxDirectiveThirdParty contained passenger_document_root
syn keyword ngxDirectiveThirdParty contained passenger_ruby
syn keyword ngxDirectiveThirdParty contained passenger_python
syn keyword ngxDirectiveThirdParty contained passenger_nodejs
syn keyword ngxDirectiveThirdParty contained passenger_meteor_app_settings
syn keyword ngxDirectiveThirdParty contained passenger_app_env
syn keyword ngxDirectiveThirdParty contained passenger_app_root
syn keyword ngxDirectiveThirdParty contained passenger_app_group_name
syn keyword ngxDirectiveThirdParty contained passenger_app_type
syn keyword ngxDirectiveThirdParty contained passenger_startup_file
syn keyword ngxDirectiveThirdParty contained passenger_restart_dir
syn keyword ngxDirectiveThirdParty contained passenger_spawn_method
syn keyword ngxDirectiveThirdParty contained passenger_env_var
syn keyword ngxDirectiveThirdParty contained passenger_load_shell_envvars
syn keyword ngxDirectiveThirdParty contained passenger_rolling_restarts
syn keyword ngxDirectiveThirdParty contained passenger_resist_deployment_errors
syn keyword ngxDirectiveThirdParty contained passenger_user_switching
syn keyword ngxDirectiveThirdParty contained passenger_user
syn keyword ngxDirectiveThirdParty contained passenger_group
syn keyword ngxDirectiveThirdParty contained passenger_default_user
syn keyword ngxDirectiveThirdParty contained passenger_default_group
syn keyword ngxDirectiveThirdParty contained passenger_show_version_in_header
syn keyword ngxDirectiveThirdParty contained passenger_friendly_error_pages
syn keyword ngxDirectiveThirdParty contained passenger_disable_security_update_check
syn keyword ngxDirectiveThirdParty contained passenger_security_update_check_proxy
syn keyword ngxDirectiveThirdParty contained passenger_max_pool_size
syn keyword ngxDirectiveThirdParty contained passenger_min_instances
syn keyword ngxDirectiveThirdParty contained passenger_max_instances
syn keyword ngxDirectiveThirdParty contained passenger_max_instances_per_app
syn keyword ngxDirectiveThirdParty contained passenger_pool_idle_time
syn keyword ngxDirectiveThirdParty contained passenger_max_preloader_idle_time
syn keyword ngxDirectiveThirdParty contained passenger_force_max_concurrent_requests_per_process
syn keyword ngxDirectiveThirdParty contained passenger_start_timeout
syn keyword ngxDirectiveThirdParty contained passenger_concurrency_model
syn keyword ngxDirectiveThirdParty contained passenger_thread_count
syn keyword ngxDirectiveThirdParty contained passenger_max_requests
syn keyword ngxDirectiveThirdParty contained passenger_max_request_time
syn keyword ngxDirectiveThirdParty contained passenger_memory_limit
syn keyword ngxDirectiveThirdParty contained passenger_stat_throttle_rate
syn keyword ngxDirectiveThirdParty contained passenger_core_file_descriptor_ulimit
syn keyword ngxDirectiveThirdParty contained passenger_app_file_descriptor_ulimit
syn keyword ngxDirectiveThirdParty contained passenger_pre_start
syn keyword ngxDirectiveThirdParty contained passenger_set_header
syn keyword ngxDirectiveThirdParty contained passenger_max_request_queue_size
syn keyword ngxDirectiveThirdParty contained passenger_request_queue_overflow_status_code
syn keyword ngxDirectiveThirdParty contained passenger_sticky_sessions
syn keyword ngxDirectiveThirdParty contained passenger_sticky_sessions_cookie_name
syn keyword ngxDirectiveThirdParty contained passenger_abort_websockets_on_process_shutdown
syn keyword ngxDirectiveThirdParty contained passenger_ignore_client_abort
syn keyword ngxDirectiveThirdParty contained passenger_intercept_errors
syn keyword ngxDirectiveThirdParty contained passenger_pass_header
syn keyword ngxDirectiveThirdParty contained passenger_ignore_headers
syn keyword ngxDirectiveThirdParty contained passenger_headers_hash_bucket_size
syn keyword ngxDirectiveThirdParty contained passenger_headers_hash_max_size
syn keyword ngxDirectiveThirdParty contained passenger_buffer_response
syn keyword ngxDirectiveThirdParty contained passenger_response_buffer_high_watermark
syn keyword ngxDirectiveThirdParty contained passenger_buffer_size, passenger_buffers, passenger_busy_buffers_size
syn keyword ngxDirectiveThirdParty contained passenger_socket_backlog
syn keyword ngxDirectiveThirdParty contained passenger_log_level
syn keyword ngxDirectiveThirdParty contained passenger_log_file
syn keyword ngxDirectiveThirdParty contained passenger_file_descriptor_log_file
syn keyword ngxDirectiveThirdParty contained passenger_debugger
syn keyword ngxDirectiveThirdParty contained passenger_instance_registry_dir
syn keyword ngxDirectiveThirdParty contained passenger_data_buffer_dir
syn keyword ngxDirectiveThirdParty contained passenger_fly_with
syn keyword ngxDirectiveThirdParty contained union_station_support
syn keyword ngxDirectiveThirdParty contained union_station_key
syn keyword ngxDirectiveThirdParty contained union_station_proxy_address
syn keyword ngxDirectiveThirdParty contained union_station_filter
syn keyword ngxDirectiveThirdParty contained union_station_gateway_address
syn keyword ngxDirectiveThirdParty contained union_station_gateway_port
syn keyword ngxDirectiveThirdParty contained union_station_gateway_cert
syn keyword ngxDirectiveDeprecated contained rails_spawn_method
syn keyword ngxDirectiveDeprecated contained passenger_debug_log_file

" Postgres Module <http://labs.frickle.com/nginx_ngx_postgres/>
" Upstream module that allows nginx to communicate directly with PostgreSQL database.
syn keyword ngxDirectiveThirdParty contained postgres_server
syn keyword ngxDirectiveThirdParty contained postgres_keepalive
syn keyword ngxDirectiveThirdParty contained postgres_pass
syn keyword ngxDirectiveThirdParty contained postgres_query
syn keyword ngxDirectiveThirdParty contained postgres_rewrite
syn keyword ngxDirectiveThirdParty contained postgres_output
syn keyword ngxDirectiveThirdParty contained postgres_set
syn keyword ngxDirectiveThirdParty contained postgres_escape
syn keyword ngxDirectiveThirdParty contained postgres_connect_timeout
syn keyword ngxDirectiveThirdParty contained postgres_result_timeout

" Pubcookie Module <https://www.vanko.me/book/page/pubcookie-module-nginx>
" Authorizes users using encrypted cookies
syn keyword ngxDirectiveThirdParty contained pubcookie_inactive_expire
syn keyword ngxDirectiveThirdParty contained pubcookie_hard_expire
syn keyword ngxDirectiveThirdParty contained pubcookie_app_id
syn keyword ngxDirectiveThirdParty contained pubcookie_dir_depth
syn keyword ngxDirectiveThirdParty contained pubcookie_catenate_app_ids
syn keyword ngxDirectiveThirdParty contained pubcookie_app_srv_id
syn keyword ngxDirectiveThirdParty contained pubcookie_login
syn keyword ngxDirectiveThirdParty contained pubcookie_login_method
syn keyword ngxDirectiveThirdParty contained pubcookie_post
syn keyword ngxDirectiveThirdParty contained pubcookie_domain
syn keyword ngxDirectiveThirdParty contained pubcookie_granting_cert_file
syn keyword ngxDirectiveThirdParty contained pubcookie_session_key_file
syn keyword ngxDirectiveThirdParty contained pubcookie_session_cert_file
syn keyword ngxDirectiveThirdParty contained pubcookie_crypt_key_file
syn keyword ngxDirectiveThirdParty contained pubcookie_end_session
syn keyword ngxDirectiveThirdParty contained pubcookie_encryption
syn keyword ngxDirectiveThirdParty contained pubcookie_session_reauth
syn keyword ngxDirectiveThirdParty contained pubcookie_auth_type_names
syn keyword ngxDirectiveThirdParty contained pubcookie_no_prompt
syn keyword ngxDirectiveThirdParty contained pubcookie_on_demand
syn keyword ngxDirectiveThirdParty contained pubcookie_addl_request
syn keyword ngxDirectiveThirdParty contained pubcookie_no_obscure_cookies
syn keyword ngxDirectiveThirdParty contained pubcookie_no_clean_creds
syn keyword ngxDirectiveThirdParty contained pubcookie_egd_device
syn keyword ngxDirectiveThirdParty contained pubcookie_no_blank
syn keyword ngxDirectiveThirdParty contained pubcookie_super_debug
syn keyword ngxDirectiveThirdParty contained pubcookie_set_remote_user

" Push Stream Module <https://github.com/wandenberg/nginx-push-stream-module>
" A pure stream http push technology for your Nginx setup
syn keyword ngxDirectiveThirdParty contained push_stream_channels_statistics
syn keyword ngxDirectiveThirdParty contained push_stream_publisher
syn keyword ngxDirectiveThirdParty contained push_stream_subscriber
syn keyword ngxDirectiveThirdParty contained push_stream_shared_memory_size
syn keyword ngxDirectiveThirdParty contained push_stream_channel_deleted_message_text
syn keyword ngxDirectiveThirdParty contained push_stream_channel_inactivity_time
syn keyword ngxDirectiveThirdParty contained push_stream_ping_message_text
syn keyword ngxDirectiveThirdParty contained push_stream_timeout_with_body
syn keyword ngxDirectiveThirdParty contained push_stream_message_ttl
syn keyword ngxDirectiveThirdParty contained push_stream_max_subscribers_per_channel
syn keyword ngxDirectiveThirdParty contained push_stream_max_messages_stored_per_channel
syn keyword ngxDirectiveThirdParty contained push_stream_max_channel_id_length
syn keyword ngxDirectiveThirdParty contained push_stream_max_number_of_channels
syn keyword ngxDirectiveThirdParty contained push_stream_max_number_of_wildcard_channels
syn keyword ngxDirectiveThirdParty contained push_stream_wildcard_channel_prefix
syn keyword ngxDirectiveThirdParty contained push_stream_events_channel_id
syn keyword ngxDirectiveThirdParty contained push_stream_channels_path
syn keyword ngxDirectiveThirdParty contained push_stream_store_messages
syn keyword ngxDirectiveThirdParty contained push_stream_channel_info_on_publish
syn keyword ngxDirectiveThirdParty contained push_stream_authorized_channels_only
syn keyword ngxDirectiveThirdParty contained push_stream_header_template_file
syn keyword ngxDirectiveThirdParty contained push_stream_header_template
syn keyword ngxDirectiveThirdParty contained push_stream_message_template
syn keyword ngxDirectiveThirdParty contained push_stream_footer_template
syn keyword ngxDirectiveThirdParty contained push_stream_wildcard_channel_max_qtd
syn keyword ngxDirectiveThirdParty contained push_stream_ping_message_interval
syn keyword ngxDirectiveThirdParty contained push_stream_subscriber_connection_ttl
syn keyword ngxDirectiveThirdParty contained push_stream_longpolling_connection_ttl
syn keyword ngxDirectiveThirdParty contained push_stream_websocket_allow_publish
syn keyword ngxDirectiveThirdParty contained push_stream_last_received_message_time
syn keyword ngxDirectiveThirdParty contained push_stream_last_received_message_tag
syn keyword ngxDirectiveThirdParty contained push_stream_last_event_id
syn keyword ngxDirectiveThirdParty contained push_stream_user_agent
syn keyword ngxDirectiveThirdParty contained push_stream_padding_by_user_agent
syn keyword ngxDirectiveThirdParty contained push_stream_allowed_origins
syn keyword ngxDirectiveThirdParty contained push_stream_allow_connections_to_events_channel

" rDNS Module <https://github.com/flant/nginx-http-rdns>
" Make a reverse DNS (rDNS) lookup for incoming connection and provides simple access control of incoming hostname by allow/deny rules
syn keyword ngxDirectiveThirdParty contained rdns
syn keyword ngxDirectiveThirdParty contained rdns_allow
syn keyword ngxDirectiveThirdParty contained rdns_deny

" RDS CSV Module <https://github.com/openresty/rds-csv-nginx-module>
" Nginx output filter module to convert Resty-DBD-Streams (RDS) to Comma-Separated Values (CSV)
syn keyword ngxDirectiveThirdParty contained rds_csv
syn keyword ngxDirectiveThirdParty contained rds_csv_row_terminator
syn keyword ngxDirectiveThirdParty contained rds_csv_field_separator
syn keyword ngxDirectiveThirdParty contained rds_csv_field_name_header
syn keyword ngxDirectiveThirdParty contained rds_csv_content_type
syn keyword ngxDirectiveThirdParty contained rds_csv_buffer_size

" RDS JSON Module <https://github.com/openresty/rds-json-nginx-module>
" An output filter that formats Resty DBD Streams generated by ngx_drizzle and others to JSON
syn keyword ngxDirectiveThirdParty contained rds_json
syn keyword ngxDirectiveThirdParty contained rds_json_buffer_size
syn keyword ngxDirectiveThirdParty contained rds_json_format
syn keyword ngxDirectiveThirdParty contained rds_json_root
syn keyword ngxDirectiveThirdParty contained rds_json_success_property
syn keyword ngxDirectiveThirdParty contained rds_json_user_property
syn keyword ngxDirectiveThirdParty contained rds_json_errcode_key
syn keyword ngxDirectiveThirdParty contained rds_json_errstr_key
syn keyword ngxDirectiveThirdParty contained rds_json_ret
syn keyword ngxDirectiveThirdParty contained rds_json_content_type

" Redis Module <https://www.nginx.com/resources/wiki/modules/redis/>
" Use this module to perform simple caching
syn keyword ngxDirectiveThirdParty contained redis_pass
syn keyword ngxDirectiveThirdParty contained redis_bind
syn keyword ngxDirectiveThirdParty contained redis_connect_timeout
syn keyword ngxDirectiveThirdParty contained redis_read_timeout
syn keyword ngxDirectiveThirdParty contained redis_send_timeout
syn keyword ngxDirectiveThirdParty contained redis_buffer_size
syn keyword ngxDirectiveThirdParty contained redis_next_upstream
syn keyword ngxDirectiveThirdParty contained redis_gzip_flag

" Redis 2 Module <https://github.com/openresty/redis2-nginx-module>
" Nginx upstream module for the Redis 2.0 protocol
syn keyword ngxDirectiveThirdParty contained redis2_query
syn keyword ngxDirectiveThirdParty contained redis2_raw_query
syn keyword ngxDirectiveThirdParty contained redis2_raw_queries
syn keyword ngxDirectiveThirdParty contained redis2_literal_raw_query
syn keyword ngxDirectiveThirdParty contained redis2_pass
syn keyword ngxDirectiveThirdParty contained redis2_connect_timeout
syn keyword ngxDirectiveThirdParty contained redis2_send_timeout
syn keyword ngxDirectiveThirdParty contained redis2_read_timeout
syn keyword ngxDirectiveThirdParty contained redis2_buffer_size
syn keyword ngxDirectiveThirdParty contained redis2_next_upstream

" Replace Filter Module <https://github.com/openresty/replace-filter-nginx-module>
" Streaming regular expression replacement in response bodies
syn keyword ngxDirectiveThirdParty contained replace_filter
syn keyword ngxDirectiveThirdParty contained replace_filter_types
syn keyword ngxDirectiveThirdParty contained replace_filter_max_buffered_size
syn keyword ngxDirectiveThirdParty contained replace_filter_last_modified
syn keyword ngxDirectiveThirdParty contained replace_filter_skip

" Roboo Module <https://github.com/yuri-gushin/Roboo>
" HTTP Robot Mitigator

" RRD Graph Module <https://www.nginx.com/resources/wiki/modules/rrd_graph/>
" This module provides an HTTP interface to RRDtool's graphing facilities.
syn keyword ngxDirectiveThirdParty contained rrd_graph
syn keyword ngxDirectiveThirdParty contained rrd_graph_root

" RTMP Module <https://github.com/arut/nginx-rtmp-module>
" NGINX-based Media Streaming Server
syn keyword ngxDirectiveThirdParty contained rtmp
" syn keyword ngxDirectiveThirdParty contained server
" syn keyword ngxDirectiveThirdParty contained listen
syn keyword ngxDirectiveThirdParty contained application
" syn keyword ngxDirectiveThirdParty contained timeout
syn keyword ngxDirectiveThirdParty contained ping
syn keyword ngxDirectiveThirdParty contained ping_timeout
syn keyword ngxDirectiveThirdParty contained max_streams
syn keyword ngxDirectiveThirdParty contained ack_window
syn keyword ngxDirectiveThirdParty contained chunk_size
syn keyword ngxDirectiveThirdParty contained max_queue
syn keyword ngxDirectiveThirdParty contained max_message
syn keyword ngxDirectiveThirdParty contained out_queue
syn keyword ngxDirectiveThirdParty contained out_cork
" syn keyword ngxDirectiveThirdParty contained allow
" syn keyword ngxDirectiveThirdParty contained deny
syn keyword ngxDirectiveThirdParty contained exec_push
syn keyword ngxDirectiveThirdParty contained exec_pull
syn keyword ngxDirectiveThirdParty contained exec
syn keyword ngxDirectiveThirdParty contained exec_options
syn keyword ngxDirectiveThirdParty contained exec_static
syn keyword ngxDirectiveThirdParty contained exec_kill_signal
syn keyword ngxDirectiveThirdParty contained respawn
syn keyword ngxDirectiveThirdParty contained respawn_timeout
syn keyword ngxDirectiveThirdParty contained exec_publish
syn keyword ngxDirectiveThirdParty contained exec_play
syn keyword ngxDirectiveThirdParty contained exec_play_done
syn keyword ngxDirectiveThirdParty contained exec_publish_done
syn keyword ngxDirectiveThirdParty contained exec_record_done
syn keyword ngxDirectiveThirdParty contained live
syn keyword ngxDirectiveThirdParty contained meta
syn keyword ngxDirectiveThirdParty contained interleave
syn keyword ngxDirectiveThirdParty contained wait_key
syn keyword ngxDirectiveThirdParty contained wait_video
syn keyword ngxDirectiveThirdParty contained publish_notify
syn keyword ngxDirectiveThirdParty contained drop_idle_publisher
syn keyword ngxDirectiveThirdParty contained sync
syn keyword ngxDirectiveThirdParty contained play_restart
syn keyword ngxDirectiveThirdParty contained idle_streams
syn keyword ngxDirectiveThirdParty contained record
syn keyword ngxDirectiveThirdParty contained record_path
syn keyword ngxDirectiveThirdParty contained record_suffix
syn keyword ngxDirectiveThirdParty contained record_unique
syn keyword ngxDirectiveThirdParty contained record_append
syn keyword ngxDirectiveThirdParty contained record_lock
syn keyword ngxDirectiveThirdParty contained record_max_size
syn keyword ngxDirectiveThirdParty contained record_max_frames
syn keyword ngxDirectiveThirdParty contained record_interval
syn keyword ngxDirectiveThirdParty contained recorder
syn keyword ngxDirectiveThirdParty contained record_notify
syn keyword ngxDirectiveThirdParty contained play
syn keyword ngxDirectiveThirdParty contained play_temp_path
syn keyword ngxDirectiveThirdParty contained play_local_path
syn keyword ngxDirectiveThirdParty contained pull
syn keyword ngxDirectiveThirdParty contained push
syn keyword ngxDirectiveThirdParty contained push_reconnect
syn keyword ngxDirectiveThirdParty contained session_relay
syn keyword ngxDirectiveThirdParty contained on_connect
syn keyword ngxDirectiveThirdParty contained on_play
syn keyword ngxDirectiveThirdParty contained on_publish
syn keyword ngxDirectiveThirdParty contained on_done
syn keyword ngxDirectiveThirdParty contained on_play_done
syn keyword ngxDirectiveThirdParty contained on_publish_done
syn keyword ngxDirectiveThirdParty contained on_record_done
syn keyword ngxDirectiveThirdParty contained on_update
syn keyword ngxDirectiveThirdParty contained notify_update_timeout
syn keyword ngxDirectiveThirdParty contained notify_update_strict
syn keyword ngxDirectiveThirdParty contained notify_relay_redirect
syn keyword ngxDirectiveThirdParty contained notify_method
syn keyword ngxDirectiveThirdParty contained hls
syn keyword ngxDirectiveThirdParty contained hls_path
syn keyword ngxDirectiveThirdParty contained hls_fragment
syn keyword ngxDirectiveThirdParty contained hls_playlist_length
syn keyword ngxDirectiveThirdParty contained hls_sync
syn keyword ngxDirectiveThirdParty contained hls_continuous
syn keyword ngxDirectiveThirdParty contained hls_nested
syn keyword ngxDirectiveThirdParty contained hls_base_url
syn keyword ngxDirectiveThirdParty contained hls_cleanup
syn keyword ngxDirectiveThirdParty contained hls_fragment_naming
syn keyword ngxDirectiveThirdParty contained hls_fragment_slicing
syn keyword ngxDirectiveThirdParty contained hls_variant
syn keyword ngxDirectiveThirdParty contained hls_type
syn keyword ngxDirectiveThirdParty contained hls_keys
syn keyword ngxDirectiveThirdParty contained hls_key_path
syn keyword ngxDirectiveThirdParty contained hls_key_url
syn keyword ngxDirectiveThirdParty contained hls_fragments_per_key
syn keyword ngxDirectiveThirdParty contained dash
syn keyword ngxDirectiveThirdParty contained dash_path
syn keyword ngxDirectiveThirdParty contained dash_fragment
syn keyword ngxDirectiveThirdParty contained dash_playlist_length
syn keyword ngxDirectiveThirdParty contained dash_nested
syn keyword ngxDirectiveThirdParty contained dash_cleanup
" syn keyword ngxDirectiveThirdParty contained access_log
" syn keyword ngxDirectiveThirdParty contained log_format
syn keyword ngxDirectiveThirdParty contained max_connections
syn keyword ngxDirectiveThirdParty contained rtmp_stat
syn keyword ngxDirectiveThirdParty contained rtmp_stat_stylesheet
syn keyword ngxDirectiveThirdParty contained rtmp_auto_push
syn keyword ngxDirectiveThirdParty contained rtmp_auto_push_reconnect
syn keyword ngxDirectiveThirdParty contained rtmp_socket_dir
syn keyword ngxDirectiveThirdParty contained rtmp_control

" RTMPT Module <https://github.com/kwojtek/nginx-rtmpt-proxy-module>
" Module for nginx to proxy rtmp using http protocol
syn keyword ngxDirectiveThirdParty contained rtmpt_proxy_target
syn keyword ngxDirectiveThirdParty contained rtmpt_proxy_rtmp_timeout
syn keyword ngxDirectiveThirdParty contained rtmpt_proxy_http_timeout
syn keyword ngxDirectiveThirdParty contained rtmpt_proxy
syn keyword ngxDirectiveThirdParty contained rtmpt_proxy_stat
syn keyword ngxDirectiveThirdParty contained rtmpt_proxy_stylesheet

" Syntactically Awesome Module <https://github.com/mneudert/sass-nginx-module>
" Providing on-the-fly compiling of Sass files as an NGINX module.
syn keyword ngxDirectiveThirdParty contained sass_compile
syn keyword ngxDirectiveThirdParty contained sass_error_log
syn keyword ngxDirectiveThirdParty contained sass_include_path
syn keyword ngxDirectiveThirdParty contained sass_indent
syn keyword ngxDirectiveThirdParty contained sass_is_indented_syntax
syn keyword ngxDirectiveThirdParty contained sass_linefeed
syn keyword ngxDirectiveThirdParty contained sass_precision
syn keyword ngxDirectiveThirdParty contained sass_output_style
syn keyword ngxDirectiveThirdParty contained sass_source_comments
syn keyword ngxDirectiveThirdParty contained sass_source_map_embed

" Secure Download Module <https://www.nginx.com/resources/wiki/modules/secure_download/>
" Enables you to create links which are only valid until a certain datetime is reached
syn keyword ngxDirectiveThirdParty contained secure_download
syn keyword ngxDirectiveThirdParty contained secure_download_secret
syn keyword ngxDirectiveThirdParty contained secure_download_path_mode

" Selective Cache Purge Module <https://github.com/wandenberg/nginx-selective-cache-purge-module>
" A module to purge cache by GLOB patterns. The supported patterns are the same as supported by Redis.
syn keyword ngxDirectiveThirdParty contained selective_cache_purge_redis_unix_socket
syn keyword ngxDirectiveThirdParty contained selective_cache_purge_redis_host
syn keyword ngxDirectiveThirdParty contained selective_cache_purge_redis_port
syn keyword ngxDirectiveThirdParty contained selective_cache_purge_redis_database
syn keyword ngxDirectiveThirdParty contained selective_cache_purge_query

" Set cconv Module <https://github.com/liseen/set-cconv-nginx-module>
" Cconv rewrite set commands
syn keyword ngxDirectiveThirdParty contained set_cconv_to_simp
syn keyword ngxDirectiveThirdParty contained set_cconv_to_trad
syn keyword ngxDirectiveThirdParty contained set_pinyin_to_normal

" Set Hash Module <https://github.com/simpl/ngx_http_set_hash>
" Nginx module that allows the setting of variables to the value of a variety of hashes
syn keyword ngxDirectiveThirdParty contained set_md5
syn keyword ngxDirectiveThirdParty contained set_md5_upper
syn keyword ngxDirectiveThirdParty contained set_murmur2
syn keyword ngxDirectiveThirdParty contained set_murmur2_upper
syn keyword ngxDirectiveThirdParty contained set_sha1
syn keyword ngxDirectiveThirdParty contained set_sha1_upper

" Set Lang Module <https://github.com/simpl/ngx_http_set_lang>
" Provides a variety of ways for setting a variable denoting the langauge that content should be returned in.
syn keyword ngxDirectiveThirdParty contained set_lang
syn keyword ngxDirectiveThirdParty contained set_lang_method
syn keyword ngxDirectiveThirdParty contained lang_cookie
syn keyword ngxDirectiveThirdParty contained lang_get_var
syn keyword ngxDirectiveThirdParty contained lang_list
syn keyword ngxDirectiveThirdParty contained lang_post_var
syn keyword ngxDirectiveThirdParty contained lang_host
syn keyword ngxDirectiveThirdParty contained lang_referer

" Set Misc Module <https://github.com/openresty/set-misc-nginx-module>
" Various set_xxx directives added to nginx's rewrite module
syn keyword ngxDirectiveThirdParty contained set_if_empty
syn keyword ngxDirectiveThirdParty contained set_quote_sql_str
syn keyword ngxDirectiveThirdParty contained set_quote_pgsql_str
syn keyword ngxDirectiveThirdParty contained set_quote_json_str
syn keyword ngxDirectiveThirdParty contained set_unescape_uri
syn keyword ngxDirectiveThirdParty contained set_escape_uri
syn keyword ngxDirectiveThirdParty contained set_hashed_upstream
syn keyword ngxDirectiveThirdParty contained set_encode_base32
syn keyword ngxDirectiveThirdParty contained set_base32_padding
syn keyword ngxDirectiveThirdParty contained set_misc_base32_padding
syn keyword ngxDirectiveThirdParty contained set_base32_alphabet
syn keyword ngxDirectiveThirdParty contained set_decode_base32
syn keyword ngxDirectiveThirdParty contained set_encode_base64
syn keyword ngxDirectiveThirdParty contained set_decode_base64
syn keyword ngxDirectiveThirdParty contained set_encode_hex
syn keyword ngxDirectiveThirdParty contained set_decode_hex
syn keyword ngxDirectiveThirdParty contained set_sha1
syn keyword ngxDirectiveThirdParty contained set_md5
syn keyword ngxDirectiveThirdParty contained set_hmac_sha1
syn keyword ngxDirectiveThirdParty contained set_random
syn keyword ngxDirectiveThirdParty contained set_secure_random_alphanum
syn keyword ngxDirectiveThirdParty contained set_secure_random_lcalpha
syn keyword ngxDirectiveThirdParty contained set_rotate
syn keyword ngxDirectiveThirdParty contained set_local_today
syn keyword ngxDirectiveThirdParty contained set_formatted_gmt_time
syn keyword ngxDirectiveThirdParty contained set_formatted_local_time

" SFlow Module <https://github.com/sflow/nginx-sflow-module>
" A binary, random-sampling nginx module designed for: lightweight, centralized, continuous, real-time monitoring of very large and very busy web farms.
syn keyword ngxDirectiveThirdParty contained sflow

" Shibboleth Module <https://github.com/nginx-shib/nginx-http-shibboleth>
" Shibboleth auth request module for nginx
syn keyword ngxDirectiveThirdParty contained shib_request
syn keyword ngxDirectiveThirdParty contained shib_request_set
syn keyword ngxDirectiveThirdParty contained shib_request_use_headers

" Slice Module <https://github.com/alibaba/nginx-http-slice>
" Nginx module for serving a file in slices (reverse byte-range)
" syn keyword ngxDirectiveThirdParty contained slice
syn keyword ngxDirectiveThirdParty contained slice_arg_begin
syn keyword ngxDirectiveThirdParty contained slice_arg_end
syn keyword ngxDirectiveThirdParty contained slice_header
syn keyword ngxDirectiveThirdParty contained slice_footer
syn keyword ngxDirectiveThirdParty contained slice_header_first
syn keyword ngxDirectiveThirdParty contained slice_footer_last

" SlowFS Cache Module <https://github.com/FRiCKLE/ngx_slowfs_cache/>
" Module adding ability to cache static files.
syn keyword ngxDirectiveThirdParty contained slowfs_big_file_size
syn keyword ngxDirectiveThirdParty contained slowfs_cache
syn keyword ngxDirectiveThirdParty contained slowfs_cache_key
syn keyword ngxDirectiveThirdParty contained slowfs_cache_min_uses
syn keyword ngxDirectiveThirdParty contained slowfs_cache_path
syn keyword ngxDirectiveThirdParty contained slowfs_cache_purge
syn keyword ngxDirectiveThirdParty contained slowfs_cache_valid
syn keyword ngxDirectiveThirdParty contained slowfs_temp_path

" Small Light Module <https://github.com/cubicdaiya/ngx_small_light>
" Dynamic Image Transformation Module For nginx.
syn keyword ngxDirectiveThirdParty contained small_light
syn keyword ngxDirectiveThirdParty contained small_light_getparam_mode
syn keyword ngxDirectiveThirdParty contained small_light_material_dir
syn keyword ngxDirectiveThirdParty contained small_light_pattern_define
syn keyword ngxDirectiveThirdParty contained small_light_radius_max
syn keyword ngxDirectiveThirdParty contained small_light_sigma_max
syn keyword ngxDirectiveThirdParty contained small_light_imlib2_temp_dir
syn keyword ngxDirectiveThirdParty contained small_light_buffer

" Sorted Querystring Filter Module <https://github.com/wandenberg/nginx-sorted-querystring-module>
" Nginx module to expose querystring parameters sorted in a variable to be used on cache_key as example
syn keyword ngxDirectiveThirdParty contained sorted_querystring_filter_parameter

" Sphinx2 Module <https://github.com/reeteshranjan/sphinx2-nginx-module>
" Nginx upstream module for Sphinx 2.x
syn keyword ngxDirectiveThirdParty contained sphinx2_pass
syn keyword ngxDirectiveThirdParty contained sphinx2_bind
syn keyword ngxDirectiveThirdParty contained sphinx2_connect_timeout
syn keyword ngxDirectiveThirdParty contained sphinx2_send_timeout
syn keyword ngxDirectiveThirdParty contained sphinx2_buffer_size
syn keyword ngxDirectiveThirdParty contained sphinx2_read_timeout
syn keyword ngxDirectiveThirdParty contained sphinx2_next_upstream

" HTTP SPNEGO auth Module <https://github.com/stnoonan/spnego-http-auth-nginx-module>
" This module implements adds SPNEGO support to nginx(http://nginx.org). It currently supports only Kerberos authentication via GSSAPI
syn keyword ngxDirectiveThirdParty contained auth_gss
syn keyword ngxDirectiveThirdParty contained auth_gss_keytab
syn keyword ngxDirectiveThirdParty contained auth_gss_realm
syn keyword ngxDirectiveThirdParty contained auth_gss_service_name
syn keyword ngxDirectiveThirdParty contained auth_gss_authorized_principal
syn keyword ngxDirectiveThirdParty contained auth_gss_allow_basic_fallback

" SR Cache Module <https://github.com/openresty/srcache-nginx-module>
" Transparent subrequest-based caching layout for arbitrary nginx locations
syn keyword ngxDirectiveThirdParty contained srcache_fetch
syn keyword ngxDirectiveThirdParty contained srcache_fetch_skip
syn keyword ngxDirectiveThirdParty contained srcache_store
syn keyword ngxDirectiveThirdParty contained srcache_store_max_size
syn keyword ngxDirectiveThirdParty contained srcache_store_skip
syn keyword ngxDirectiveThirdParty contained srcache_store_statuses
syn keyword ngxDirectiveThirdParty contained srcache_store_ranges
syn keyword ngxDirectiveThirdParty contained srcache_header_buffer_size
syn keyword ngxDirectiveThirdParty contained srcache_store_hide_header
syn keyword ngxDirectiveThirdParty contained srcache_store_pass_header
syn keyword ngxDirectiveThirdParty contained srcache_methods
syn keyword ngxDirectiveThirdParty contained srcache_ignore_content_encoding
syn keyword ngxDirectiveThirdParty contained srcache_request_cache_control
syn keyword ngxDirectiveThirdParty contained srcache_response_cache_control
syn keyword ngxDirectiveThirdParty contained srcache_store_no_store
syn keyword ngxDirectiveThirdParty contained srcache_store_no_cache
syn keyword ngxDirectiveThirdParty contained srcache_store_private
syn keyword ngxDirectiveThirdParty contained srcache_default_expire
syn keyword ngxDirectiveThirdParty contained srcache_max_expire

" SSSD Info Module <https://github.com/veruu/ngx_sssd_info>
" Retrives additional attributes from SSSD for current authentizated user
syn keyword ngxDirectiveThirdParty contained sssd_info
syn keyword ngxDirectiveThirdParty contained sssd_info_output_to
syn keyword ngxDirectiveThirdParty contained sssd_info_groups
syn keyword ngxDirectiveThirdParty contained sssd_info_group
syn keyword ngxDirectiveThirdParty contained sssd_info_group_separator
syn keyword ngxDirectiveThirdParty contained sssd_info_attributes
syn keyword ngxDirectiveThirdParty contained sssd_info_attribute
syn keyword ngxDirectiveThirdParty contained sssd_info_attribute_separator

" Static Etags Module <https://github.com/mikewest/nginx-static-etags>
" Generate etags for static content
syn keyword ngxDirectiveThirdParty contained FileETag

" Statsd Module <https://github.com/zebrafishlabs/nginx-statsd>
" An nginx module for sending statistics to statsd
syn keyword ngxDirectiveThirdParty contained statsd_server
syn keyword ngxDirectiveThirdParty contained statsd_sample_rate
syn keyword ngxDirectiveThirdParty contained statsd_count
syn keyword ngxDirectiveThirdParty contained statsd_timing

" Sticky Module <https://bitbucket.org/nginx-goodies/nginx-sticky-module-ng>
" Add a sticky cookie to be always forwarded to the same upstream server
" syn keyword ngxDirectiveThirdParty contained sticky

" Stream Echo Module <https://github.com/openresty/stream-echo-nginx-module>
" TCP/stream echo module for NGINX (a port of ngx_http_echo_module)
syn keyword ngxDirectiveThirdParty contained echo
syn keyword ngxDirectiveThirdParty contained echo_duplicate
syn keyword ngxDirectiveThirdParty contained echo_flush_wait
syn keyword ngxDirectiveThirdParty contained echo_sleep
syn keyword ngxDirectiveThirdParty contained echo_send_timeout
syn keyword ngxDirectiveThirdParty contained echo_read_bytes
syn keyword ngxDirectiveThirdParty contained echo_read_line
syn keyword ngxDirectiveThirdParty contained echo_request_data
syn keyword ngxDirectiveThirdParty contained echo_discard_request
syn keyword ngxDirectiveThirdParty contained echo_read_buffer_size
syn keyword ngxDirectiveThirdParty contained echo_read_timeout
syn keyword ngxDirectiveThirdParty contained echo_client_error_log_level
syn keyword ngxDirectiveThirdParty contained echo_lingering_close
syn keyword ngxDirectiveThirdParty contained echo_lingering_time
syn keyword ngxDirectiveThirdParty contained echo_lingering_timeout

" Stream Lua Module <https://github.com/openresty/stream-lua-nginx-module>
" Embed the power of Lua into Nginx stream/TCP Servers.
syn keyword ngxDirectiveThirdParty contained lua_resolver
syn keyword ngxDirectiveThirdParty contained lua_resolver_timeout
syn keyword ngxDirectiveThirdParty contained lua_lingering_close
syn keyword ngxDirectiveThirdParty contained lua_lingering_time
syn keyword ngxDirectiveThirdParty contained lua_lingering_timeout

" Stream Upsync Module <https://github.com/xiaokai-wang/nginx-stream-upsync-module>
" Sync upstreams from consul or others, dynamiclly modify backend-servers attribute(weight, max_fails,...), needn't reload nginx.
syn keyword ngxDirectiveThirdParty contained upsync
syn keyword ngxDirectiveThirdParty contained upsync_dump_path
syn keyword ngxDirectiveThirdParty contained upsync_lb
syn keyword ngxDirectiveThirdParty contained upsync_show

" Strip Module <https://github.com/evanmiller/mod_strip>
" Whitespace remover.
syn keyword ngxDirectiveThirdParty contained strip

" Subrange Module <https://github.com/Qihoo360/ngx_http_subrange_module>
" Split one big HTTP/Range request to multiple subrange requesets
syn keyword ngxDirectiveThirdParty contained subrange

" Substitutions Module <https://www.nginx.com/resources/wiki/modules/substitutions/>
" A filter module which can do both regular expression and fixed string substitutions on response bodies.
syn keyword ngxDirectiveThirdParty contained subs_filter
syn keyword ngxDirectiveThirdParty contained subs_filter_types

" Summarizer Module <https://github.com/reeteshranjan/summarizer-nginx-module>
" Upstream nginx module to get summaries of documents using the summarizer daemon service
syn keyword ngxDirectiveThirdParty contained smrzr_filename
syn keyword ngxDirectiveThirdParty contained smrzr_ratio

" Supervisord Module <https://github.com/FRiCKLE/ngx_supervisord/>
" Module providing nginx with API to communicate with supervisord and manage (start/stop) backends on-demand.
syn keyword ngxDirectiveThirdParty contained supervisord
syn keyword ngxDirectiveThirdParty contained supervisord_inherit_backend_status
syn keyword ngxDirectiveThirdParty contained supervisord_name
syn keyword ngxDirectiveThirdParty contained supervisord_start
syn keyword ngxDirectiveThirdParty contained supervisord_stop

" Tarantool Upstream Module <https://github.com/tarantool/nginx_upstream_module>
" Tarantool NginX upstream module (REST, JSON API, websockets, load balancing)
syn keyword ngxDirectiveThirdParty contained tnt_pass
syn keyword ngxDirectiveThirdParty contained tnt_http_methods
syn keyword ngxDirectiveThirdParty contained tnt_http_rest_methods
syn keyword ngxDirectiveThirdParty contained tnt_pass_http_request
syn keyword ngxDirectiveThirdParty contained tnt_pass_http_request_buffer_size
syn keyword ngxDirectiveThirdParty contained tnt_method
syn keyword ngxDirectiveThirdParty contained tnt_http_allowed_methods - experemental
syn keyword ngxDirectiveThirdParty contained tnt_send_timeout
syn keyword ngxDirectiveThirdParty contained tnt_read_timeout
syn keyword ngxDirectiveThirdParty contained tnt_buffer_size
syn keyword ngxDirectiveThirdParty contained tnt_next_upstream
syn keyword ngxDirectiveThirdParty contained tnt_connect_timeout
syn keyword ngxDirectiveThirdParty contained tnt_next_upstream
syn keyword ngxDirectiveThirdParty contained tnt_next_upstream_tries
syn keyword ngxDirectiveThirdParty contained tnt_next_upstream_timeout

" TCP Proxy Module <http://yaoweibin.github.io/nginx_tcp_proxy_module/>
" Add the feature of tcp proxy with nginx, with health check and status monitor
syn keyword ngxDirectiveBlock contained tcp
" syn keyword ngxDirectiveThirdParty contained server
" syn keyword ngxDirectiveThirdParty contained listen
" syn keyword ngxDirectiveThirdParty contained allow
" syn keyword ngxDirectiveThirdParty contained deny
" syn keyword ngxDirectiveThirdParty contained so_keepalive
" syn keyword ngxDirectiveThirdParty contained tcp_nodelay
" syn keyword ngxDirectiveThirdParty contained timeout
" syn keyword ngxDirectiveThirdParty contained server_name
" syn keyword ngxDirectiveThirdParty contained resolver
" syn keyword ngxDirectiveThirdParty contained resolver_timeout
" syn keyword ngxDirectiveThirdParty contained upstream
syn keyword ngxDirectiveThirdParty contained check
syn keyword ngxDirectiveThirdParty contained check_http_send
syn keyword ngxDirectiveThirdParty contained check_http_expect_alive
syn keyword ngxDirectiveThirdParty contained check_smtp_send
syn keyword ngxDirectiveThirdParty contained check_smtp_expect_alive
syn keyword ngxDirectiveThirdParty contained check_shm_size
syn keyword ngxDirectiveThirdParty contained check_status
" syn keyword ngxDirectiveThirdParty contained ip_hash
" syn keyword ngxDirectiveThirdParty contained proxy_pass
" syn keyword ngxDirectiveThirdParty contained proxy_buffer
" syn keyword ngxDirectiveThirdParty contained proxy_connect_timeout
" syn keyword ngxDirectiveThirdParty contained proxy_read_timeout
syn keyword ngxDirectiveThirdParty contained proxy_write_timeout

" Testcookie Module <https://github.com/kyprizel/testcookie-nginx-module>
" NGINX module for L7 DDoS attack mitigation
syn keyword ngxDirectiveThirdParty contained testcookie
syn keyword ngxDirectiveThirdParty contained testcookie_name
syn keyword ngxDirectiveThirdParty contained testcookie_domain
syn keyword ngxDirectiveThirdParty contained testcookie_expires
syn keyword ngxDirectiveThirdParty contained testcookie_path
syn keyword ngxDirectiveThirdParty contained testcookie_secret
syn keyword ngxDirectiveThirdParty contained testcookie_session
syn keyword ngxDirectiveThirdParty contained testcookie_arg
syn keyword ngxDirectiveThirdParty contained testcookie_max_attempts
syn keyword ngxDirectiveThirdParty contained testcookie_p3p
syn keyword ngxDirectiveThirdParty contained testcookie_fallback
syn keyword ngxDirectiveThirdParty contained testcookie_whitelist
syn keyword ngxDirectiveThirdParty contained testcookie_pass
syn keyword ngxDirectiveThirdParty contained testcookie_redirect_via_refresh
syn keyword ngxDirectiveThirdParty contained testcookie_refresh_template
syn keyword ngxDirectiveThirdParty contained testcookie_refresh_status
syn keyword ngxDirectiveThirdParty contained testcookie_deny_keepalive
syn keyword ngxDirectiveThirdParty contained testcookie_get_only
syn keyword ngxDirectiveThirdParty contained testcookie_https_location
syn keyword ngxDirectiveThirdParty contained testcookie_refresh_encrypt_cookie
syn keyword ngxDirectiveThirdParty contained testcookie_refresh_encrypt_cookie_key
syn keyword ngxDirectiveThirdParty contained testcookie_refresh_encrypt_iv
syn keyword ngxDirectiveThirdParty contained testcookie_internal
syn keyword ngxDirectiveThirdParty contained testcookie_httponly_flag
syn keyword ngxDirectiveThirdParty contained testcookie_secure_flag

" Types Filter Module <https://github.com/flygoast/ngx_http_types_filter>
" Change the `Content-Type` output header depending on an extension variable according to a condition specified in the 'if' clause.
syn keyword ngxDirectiveThirdParty contained types_filter
syn keyword ngxDirectiveThirdParty contained types_filter_use_default

" Unzip Module <https://github.com/youzee/nginx-unzip-module>
" Enabling fetching of files that are stored in zipped archives.
syn keyword ngxDirectiveThirdParty contained file_in_unzip_archivefile
syn keyword ngxDirectiveThirdParty contained file_in_unzip_extract
syn keyword ngxDirectiveThirdParty contained file_in_unzip

" Upload Progress Module <https://www.nginx.com/resources/wiki/modules/upload_progress/>
" An upload progress system, that monitors RFC1867 POST upload as they are transmitted to upstream servers
syn keyword ngxDirectiveThirdParty contained upload_progress
syn keyword ngxDirectiveThirdParty contained track_uploads
syn keyword ngxDirectiveThirdParty contained report_uploads
syn keyword ngxDirectiveThirdParty contained upload_progress_content_type
syn keyword ngxDirectiveThirdParty contained upload_progress_header
syn keyword ngxDirectiveThirdParty contained upload_progress_jsonp_parameter
syn keyword ngxDirectiveThirdParty contained upload_progress_json_output
syn keyword ngxDirectiveThirdParty contained upload_progress_jsonp_output
syn keyword ngxDirectiveThirdParty contained upload_progress_template

" Upload Module <https://www.nginx.com/resources/wiki/modules/upload/>
" Parses request body storing all files being uploaded to a directory specified by upload_store directive
syn keyword ngxDirectiveThirdParty contained upload_pass
syn keyword ngxDirectiveThirdParty contained upload_resumable
syn keyword ngxDirectiveThirdParty contained upload_store
syn keyword ngxDirectiveThirdParty contained upload_state_store
syn keyword ngxDirectiveThirdParty contained upload_store_access
syn keyword ngxDirectiveThirdParty contained upload_set_form_field
syn keyword ngxDirectiveThirdParty contained upload_aggregate_form_field
syn keyword ngxDirectiveThirdParty contained upload_pass_form_field
syn keyword ngxDirectiveThirdParty contained upload_cleanup
syn keyword ngxDirectiveThirdParty contained upload_buffer_size
syn keyword ngxDirectiveThirdParty contained upload_max_part_header_len
syn keyword ngxDirectiveThirdParty contained upload_max_file_size
syn keyword ngxDirectiveThirdParty contained upload_limit_rate
syn keyword ngxDirectiveThirdParty contained upload_max_output_body_len
syn keyword ngxDirectiveThirdParty contained upload_tame_arrays
syn keyword ngxDirectiveThirdParty contained upload_pass_args

" Upstream Fair Module <https://github.com/gnosek/nginx-upstream-fair>
" The fair load balancer module for nginx http://nginx.localdomain.pl
syn keyword ngxDirectiveThirdParty contained fair
syn keyword ngxDirectiveThirdParty contained upstream_fair_shm_size

" Upstream Hash Module (DEPRECATED) <http://wiki.nginx.org/NginxHttpUpstreamRequestHashModule>
" Provides simple upstream load distribution by hashing a configurable variable.
" syn keyword ngxDirectiveDeprecated contained hash
syn keyword ngxDirectiveDeprecated contained hash_again

" Upstream Domain Resolve Module <https://www.nginx.com/resources/wiki/modules/domain_resolve/>
" A load-balancer that resolves an upstream domain name asynchronously.
syn keyword ngxDirectiveThirdParty contained jdomain

" Upsync Module <https://github.com/weibocom/nginx-upsync-module>
" Sync upstreams from consul or others, dynamiclly modify backend-servers attribute(weight, max_fails,...), needn't reload nginx
syn keyword ngxDirectiveThirdParty contained upsync
syn keyword ngxDirectiveThirdParty contained upsync_dump_path
syn keyword ngxDirectiveThirdParty contained upsync_lb
syn keyword ngxDirectiveThirdParty contained upstream_show

" URL Module <https://github.com/vozlt/nginx-module-url>
" Nginx url encoding converting module
syn keyword ngxDirectiveThirdParty contained url_encoding_convert
syn keyword ngxDirectiveThirdParty contained url_encoding_convert_from
syn keyword ngxDirectiveThirdParty contained url_encoding_convert_to

" User Agent Module <https://github.com/alibaba/nginx-http-user-agent>
" Match browsers and crawlers
syn keyword ngxDirectiveThirdParty contained user_agent

" Upstrema Ketama Chash Module <https://github.com/flygoast/ngx_http_upstream_ketama_chash>
" Nginx load-balancer module implementing ketama consistent hashing.
syn keyword ngxDirectiveThirdParty contained ketama_chash

" Video Thumbextractor Module <https://github.com/wandenberg/nginx-video-thumbextractor-module>
" Extract thumbs from a video file
syn keyword ngxDirectiveThirdParty contained video_thumbextractor
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_video_filename
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_video_second
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_image_width
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_image_height
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_only_keyframe
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_next_time
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_rows
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_cols
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_max_rows
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_max_cols
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_sample_interval
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_color
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_margin
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_padding
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_threads
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_processes_per_worker

" Eval Module <http://www.grid.net.ru/nginx/eval.en.html>
" Module for nginx web server evaluates response of proxy or memcached module into variables.
syn keyword ngxDirectiveThirdParty contained eval
syn keyword ngxDirectiveThirdParty contained eval_escalate
syn keyword ngxDirectiveThirdParty contained eval_override_content_type

" VTS Module <https://github.com/vozlt/nginx-module-vts>
" Nginx virtual host traffic status module
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_zone
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display_format
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display_jsonp
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_by_host
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_by_set_key
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_check_duplicate
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_traffic
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_traffic_by_set_key
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_check_duplicate

" XSS Module <https://github.com/openresty/xss-nginx-module>
" Native support for cross-site scripting (XSS) in an nginx.
syn keyword ngxDirectiveThirdParty contained xss_get
syn keyword ngxDirectiveThirdParty contained xss_callback_arg
syn keyword ngxDirectiveThirdParty contained xss_override_status
syn keyword ngxDirectiveThirdParty contained xss_check_status
syn keyword ngxDirectiveThirdParty contained xss_input_types

" ZIP Module <https://www.nginx.com/resources/wiki/modules/zip/>
" ZIP archiver for nginx


" highlight

hi link ngxComment Comment
hi link ngxParamComment Comment
hi link ngxListenComment Comment
hi link ngxVariable Identifier
hi link ngxVariableString PreProc
hi link ngxString String
hi link ngxListenString String

hi link ngxBoolean Boolean
hi link ngxDirectiveBlock Statement
hi link ngxDirectiveImportant Type
hi link ngxDirectiveListen Type
hi link ngxDirectiveControl Keyword
hi link ngxDirectiveError Constant
hi link ngxDirectiveDeprecated Error
hi link ngxDirective Identifier
hi link ngxDirectiveThirdParty Special

hi link ngxListenOptions Keyword

let b:current_syntax = "nginx"
