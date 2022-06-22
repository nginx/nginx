" Vim syntax file
" Language: nginx.conf

if exists("b:current_syntax")
  finish
end

let s:save_cpo = &cpo
set cpo&vim

" general syntax

if has("patch-7.4.1142")
    " except control characters, ";", "{", and "}"
    syn iskeyword 33-58,60-122,124,126-255
endif

syn match ngxName '\([^;{} \t\\]\|\\.\)\+'
    \ contains=@ngxDirectives
    \ nextgroup=@ngxParams skipwhite skipempty
syn match ngxParam '\(\${\|[^;{ \t\\]\|\\.\)\+'
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

syn match ngxVariable '\$\(\w\+\|{\w\+}\)' contained
syn match ngxVariableString '\$\(\w\+\|{\w\+}\)' contained

syn cluster ngxTopLevel
    \ contains=ngxName,ngxString,ngxComment
syn cluster ngxDirectives
    \ contains=ngxDirective,ngxDirectiveBlock,ngxDirectiveImportant
    \ add=ngxDirectiveControl,ngxDirectiveError,ngxDirectiveDeprecated
    \ add=ngxDirectiveThirdParty,ngxDirectiveThirdPartyDeprecated
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
syn match ngxListenParam '\(\${\|[^;{ \t\\]\|\\.\)\+'
    \ contained
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn region ngxListenString start=+\z(["']\)+ end=+\z1+ skip=+\\\\\|\\\z1+
    \ contained
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn match ngxListenComment '#.*$'
    \ contained
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn keyword ngxListenOptions contained
    \ default_server ssl http2 proxy_protocol
    \ setfib fastopen backlog rcvbuf sndbuf accept_filter deferred bind
    \ ipv6only reuseport so_keepalive
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn keyword ngxListenOptionsDeprecated contained
    \ spdy
    \ nextgroup=@ngxListenParams skipwhite skipempty
syn cluster ngxListenParams
    \ contains=ngxListenParam,ngxListenString,ngxListenComment
    \ add=ngxListenOptions,ngxListenOptionsDeprecated

syn keyword ngxDirectiveBlock contained http
syn keyword ngxDirectiveBlock contained stream
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
syn keyword ngxDirectiveBlock contained match

syn keyword ngxDirectiveImportant contained include
syn keyword ngxDirectiveImportant contained root
syn keyword ngxDirectiveImportant contained server_name
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

syn keyword ngxDirectiveDeprecated contained proxy_downstream_buffer
syn keyword ngxDirectiveDeprecated contained proxy_upstream_buffer
syn keyword ngxDirectiveDeprecated contained ssl
syn keyword ngxDirectiveDeprecated contained http2_idle_timeout
syn keyword ngxDirectiveDeprecated contained http2_max_field_size
syn keyword ngxDirectiveDeprecated contained http2_max_header_size
syn keyword ngxDirectiveDeprecated contained http2_max_requests
syn keyword ngxDirectiveDeprecated contained http2_recv_timeout

syn keyword ngxDirective contained absolute_redirect
syn keyword ngxDirective contained accept_mutex
syn keyword ngxDirective contained accept_mutex_delay
syn keyword ngxDirective contained acceptex_read
syn keyword ngxDirective contained access_log
syn keyword ngxDirective contained add_after_body
syn keyword ngxDirective contained add_before_body
syn keyword ngxDirective contained add_header
syn keyword ngxDirective contained add_trailer
syn keyword ngxDirective contained addition_types
syn keyword ngxDirective contained aio
syn keyword ngxDirective contained aio_write
syn keyword ngxDirective contained alias
syn keyword ngxDirective contained allow
syn keyword ngxDirective contained ancient_browser
syn keyword ngxDirective contained ancient_browser_value
syn keyword ngxDirective contained api
syn keyword ngxDirective contained auth_basic
syn keyword ngxDirective contained auth_basic_user_file
syn keyword ngxDirective contained auth_delay
syn keyword ngxDirective contained auth_http
syn keyword ngxDirective contained auth_http_header
syn keyword ngxDirective contained auth_http_pass_client_cert
syn keyword ngxDirective contained auth_http_timeout
syn keyword ngxDirective contained auth_jwt
syn keyword ngxDirective contained auth_jwt_claim_set
syn keyword ngxDirective contained auth_jwt_header_set
syn keyword ngxDirective contained auth_jwt_key_cache
syn keyword ngxDirective contained auth_jwt_key_file
syn keyword ngxDirective contained auth_jwt_key_request
syn keyword ngxDirective contained auth_jwt_leeway
syn keyword ngxDirective contained auth_jwt_require
syn keyword ngxDirective contained auth_jwt_type
syn keyword ngxDirective contained auth_request
syn keyword ngxDirective contained auth_request_set
syn keyword ngxDirective contained autoindex
syn keyword ngxDirective contained autoindex_exact_size
syn keyword ngxDirective contained autoindex_format
syn keyword ngxDirective contained autoindex_localtime
syn keyword ngxDirective contained charset
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
syn keyword ngxDirective contained fastcgi_cache_background_update
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
syn keyword ngxDirective contained fastcgi_socket_keepalive
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
syn keyword ngxDirective contained grpc_bind
syn keyword ngxDirective contained grpc_buffer_size
syn keyword ngxDirective contained grpc_connect_timeout
syn keyword ngxDirective contained grpc_hide_header
syn keyword ngxDirective contained grpc_ignore_headers
syn keyword ngxDirective contained grpc_intercept_errors
syn keyword ngxDirective contained grpc_next_upstream
syn keyword ngxDirective contained grpc_next_upstream_timeout
syn keyword ngxDirective contained grpc_next_upstream_tries
syn keyword ngxDirective contained grpc_pass
syn keyword ngxDirective contained grpc_pass_header
syn keyword ngxDirective contained grpc_read_timeout
syn keyword ngxDirective contained grpc_send_timeout
syn keyword ngxDirective contained grpc_set_header
syn keyword ngxDirective contained grpc_socket_keepalive
syn keyword ngxDirective contained grpc_ssl_certificate
syn keyword ngxDirective contained grpc_ssl_certificate_key
syn keyword ngxDirective contained grpc_ssl_ciphers
syn keyword ngxDirective contained grpc_ssl_conf_command
syn keyword ngxDirective contained grpc_ssl_crl
syn keyword ngxDirective contained grpc_ssl_name
syn keyword ngxDirective contained grpc_ssl_password_file
syn keyword ngxDirective contained grpc_ssl_protocols
syn keyword ngxDirective contained grpc_ssl_server_name
syn keyword ngxDirective contained grpc_ssl_session_reuse
syn keyword ngxDirective contained grpc_ssl_trusted_certificate
syn keyword ngxDirective contained grpc_ssl_verify
syn keyword ngxDirective contained grpc_ssl_verify_depth
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
syn keyword ngxDirective contained http2_body_preread_size
syn keyword ngxDirective contained http2_chunk_size
syn keyword ngxDirective contained http2_max_concurrent_pushes
syn keyword ngxDirective contained http2_max_concurrent_streams
syn keyword ngxDirective contained http2_pool_size
syn keyword ngxDirective contained http2_push
syn keyword ngxDirective contained http2_push_preload
syn keyword ngxDirective contained http2_recv_buffer_size
syn keyword ngxDirective contained http2_streams_index_size
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
syn keyword ngxDirective contained js_body_filter
syn keyword ngxDirective contained js_content
syn keyword ngxDirective contained js_fetch_buffer_size
syn keyword ngxDirective contained js_fetch_ciphers
syn keyword ngxDirective contained js_fetch_max_response_buffer_size
syn keyword ngxDirective contained js_fetch_protocols
syn keyword ngxDirective contained js_fetch_timeout
syn keyword ngxDirective contained js_fetch_trusted_certificate
syn keyword ngxDirective contained js_fetch_verify
syn keyword ngxDirective contained js_fetch_verify_depth
syn keyword ngxDirective contained js_filter
syn keyword ngxDirective contained js_header_filter
syn keyword ngxDirective contained js_import
syn keyword ngxDirective contained js_path
syn keyword ngxDirective contained js_preread
syn keyword ngxDirective contained js_set
syn keyword ngxDirective contained js_var
syn keyword ngxDirective contained keepalive
syn keyword ngxDirective contained keepalive_disable
syn keyword ngxDirective contained keepalive_requests
syn keyword ngxDirective contained keepalive_time
syn keyword ngxDirective contained keepalive_timeout
syn keyword ngxDirective contained keyval
syn keyword ngxDirective contained keyval_zone
syn keyword ngxDirective contained kqueue_changes
syn keyword ngxDirective contained kqueue_events
syn keyword ngxDirective contained large_client_header_buffers
syn keyword ngxDirective contained least_conn
syn keyword ngxDirective contained least_time
syn keyword ngxDirective contained limit_conn
syn keyword ngxDirective contained limit_conn_dry_run
syn keyword ngxDirective contained limit_conn_log_level
syn keyword ngxDirective contained limit_conn_status
syn keyword ngxDirective contained limit_conn_zone
syn keyword ngxDirective contained limit_rate
syn keyword ngxDirective contained limit_rate_after
syn keyword ngxDirective contained limit_req
syn keyword ngxDirective contained limit_req_dry_run
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
syn keyword ngxDirective contained master_process
syn keyword ngxDirective contained max_errors
syn keyword ngxDirective contained max_ranges
syn keyword ngxDirective contained memcached_bind
syn keyword ngxDirective contained memcached_buffer_size
syn keyword ngxDirective contained memcached_connect_timeout
syn keyword ngxDirective contained memcached_gzip_flag
syn keyword ngxDirective contained memcached_next_upstream
syn keyword ngxDirective contained memcached_next_upstream_timeout
syn keyword ngxDirective contained memcached_next_upstream_tries
syn keyword ngxDirective contained memcached_read_timeout
syn keyword ngxDirective contained memcached_send_timeout
syn keyword ngxDirective contained memcached_socket_keepalive
syn keyword ngxDirective contained merge_slashes
syn keyword ngxDirective contained min_delete_depth
syn keyword ngxDirective contained mirror
syn keyword ngxDirective contained mirror_request_body
syn keyword ngxDirective contained modern_browser
syn keyword ngxDirective contained modern_browser_value
syn keyword ngxDirective contained mp4
syn keyword ngxDirective contained mp4_buffer_size
syn keyword ngxDirective contained mp4_limit_rate
syn keyword ngxDirective contained mp4_limit_rate_after
syn keyword ngxDirective contained mp4_max_buffer_size
syn keyword ngxDirective contained mp4_start_key_frame
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
syn keyword ngxDirective contained proxy_cache_background_update
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
syn keyword ngxDirective contained proxy_cookie_flags
syn keyword ngxDirective contained proxy_cookie_path
syn keyword ngxDirective contained proxy_download_rate
syn keyword ngxDirective contained proxy_force_ranges
syn keyword ngxDirective contained proxy_half_close
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
syn keyword ngxDirective contained proxy_requests
syn keyword ngxDirective contained proxy_responses
syn keyword ngxDirective contained proxy_send_lowat
syn keyword ngxDirective contained proxy_send_timeout
syn keyword ngxDirective contained proxy_session_drop
syn keyword ngxDirective contained proxy_set_body
syn keyword ngxDirective contained proxy_set_header
syn keyword ngxDirective contained proxy_smtp_auth
syn keyword ngxDirective contained proxy_socket_keepalive
syn keyword ngxDirective contained proxy_ssl
syn keyword ngxDirective contained proxy_ssl_certificate
syn keyword ngxDirective contained proxy_ssl_certificate_key
syn keyword ngxDirective contained proxy_ssl_ciphers
syn keyword ngxDirective contained proxy_ssl_conf_command
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
syn keyword ngxDirective contained random
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
syn keyword ngxDirective contained satisfy
syn keyword ngxDirective contained scgi_bind
syn keyword ngxDirective contained scgi_buffer_size
syn keyword ngxDirective contained scgi_buffering
syn keyword ngxDirective contained scgi_buffers
syn keyword ngxDirective contained scgi_busy_buffers_size
syn keyword ngxDirective contained scgi_cache
syn keyword ngxDirective contained scgi_cache_background_update
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
syn keyword ngxDirective contained scgi_socket_keepalive
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
syn keyword ngxDirective contained ssi
syn keyword ngxDirective contained ssi_ignore_recycled_buffers
syn keyword ngxDirective contained ssi_last_modified
syn keyword ngxDirective contained ssi_min_file_chunk
syn keyword ngxDirective contained ssi_silent_errors
syn keyword ngxDirective contained ssi_types
syn keyword ngxDirective contained ssi_value_length
syn keyword ngxDirective contained ssl_alpn
syn keyword ngxDirective contained ssl_buffer_size
syn keyword ngxDirective contained ssl_certificate
syn keyword ngxDirective contained ssl_certificate_key
syn keyword ngxDirective contained ssl_ciphers
syn keyword ngxDirective contained ssl_client_certificate
syn keyword ngxDirective contained ssl_conf_command
syn keyword ngxDirective contained ssl_crl
syn keyword ngxDirective contained ssl_dhparam
syn keyword ngxDirective contained ssl_early_data
syn keyword ngxDirective contained ssl_ecdh_curve
syn keyword ngxDirective contained ssl_engine
syn keyword ngxDirective contained ssl_handshake_timeout
syn keyword ngxDirective contained ssl_ocsp
syn keyword ngxDirective contained ssl_ocsp_cache
syn keyword ngxDirective contained ssl_ocsp_responder
syn keyword ngxDirective contained ssl_password_file
syn keyword ngxDirective contained ssl_prefer_server_ciphers
syn keyword ngxDirective contained ssl_preread
syn keyword ngxDirective contained ssl_protocols
syn keyword ngxDirective contained ssl_reject_handshake
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
syn keyword ngxDirective contained stub_status
syn keyword ngxDirective contained sub_filter
syn keyword ngxDirective contained sub_filter_last_modified
syn keyword ngxDirective contained sub_filter_once
syn keyword ngxDirective contained sub_filter_types
syn keyword ngxDirective contained subrequest_output_buffer_size
syn keyword ngxDirective contained tcp_nodelay
syn keyword ngxDirective contained tcp_nopush
syn keyword ngxDirective contained thread_pool
syn keyword ngxDirective contained timeout
syn keyword ngxDirective contained timer_resolution
syn keyword ngxDirective contained types_hash_bucket_size
syn keyword ngxDirective contained types_hash_max_size
syn keyword ngxDirective contained underscores_in_headers
syn keyword ngxDirective contained uninitialized_variable_warn
syn keyword ngxDirective contained use
syn keyword ngxDirective contained user
syn keyword ngxDirective contained userid
syn keyword ngxDirective contained userid_domain
syn keyword ngxDirective contained userid_expires
syn keyword ngxDirective contained userid_flags
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
syn keyword ngxDirective contained uwsgi_cache_background_update
syn keyword ngxDirective contained uwsgi_cache_bypass
syn keyword ngxDirective contained uwsgi_cache_key
syn keyword ngxDirective contained uwsgi_cache_lock
syn keyword ngxDirective contained uwsgi_cache_lock_age
syn keyword ngxDirective contained uwsgi_cache_lock_timeout
syn keyword ngxDirective contained uwsgi_cache_max_range_offset
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
syn keyword ngxDirective contained uwsgi_pass_header
syn keyword ngxDirective contained uwsgi_pass_request_body
syn keyword ngxDirective contained uwsgi_pass_request_headers
syn keyword ngxDirective contained uwsgi_read_timeout
syn keyword ngxDirective contained uwsgi_request_buffering
syn keyword ngxDirective contained uwsgi_send_timeout
syn keyword ngxDirective contained uwsgi_socket_keepalive
syn keyword ngxDirective contained uwsgi_ssl_certificate
syn keyword ngxDirective contained uwsgi_ssl_certificate_key
syn keyword ngxDirective contained uwsgi_ssl_ciphers
syn keyword ngxDirective contained uwsgi_ssl_conf_command
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
syn keyword ngxDirective contained worker_shutdown_timeout
syn keyword ngxDirective contained working_directory
syn keyword ngxDirective contained xclient
syn keyword ngxDirective contained xml_entities
syn keyword ngxDirective contained xslt_last_modified
syn keyword ngxDirective contained xslt_param
syn keyword ngxDirective contained xslt_string_param
syn keyword ngxDirective contained xslt_stylesheet
syn keyword ngxDirective contained xslt_types
syn keyword ngxDirective contained zone
syn keyword ngxDirective contained zone_sync
syn keyword ngxDirective contained zone_sync_buffers
syn keyword ngxDirective contained zone_sync_connect_retry_interval
syn keyword ngxDirective contained zone_sync_connect_timeout
syn keyword ngxDirective contained zone_sync_interval
syn keyword ngxDirective contained zone_sync_recv_buffer_size
syn keyword ngxDirective contained zone_sync_server
syn keyword ngxDirective contained zone_sync_ssl
syn keyword ngxDirective contained zone_sync_ssl_certificate
syn keyword ngxDirective contained zone_sync_ssl_certificate_key
syn keyword ngxDirective contained zone_sync_ssl_ciphers
syn keyword ngxDirective contained zone_sync_ssl_conf_command
syn keyword ngxDirective contained zone_sync_ssl_crl
syn keyword ngxDirective contained zone_sync_ssl_name
syn keyword ngxDirective contained zone_sync_ssl_password_file
syn keyword ngxDirective contained zone_sync_ssl_protocols
syn keyword ngxDirective contained zone_sync_ssl_server_name
syn keyword ngxDirective contained zone_sync_ssl_trusted_certificate
syn keyword ngxDirective contained zone_sync_ssl_verify
syn keyword ngxDirective contained zone_sync_ssl_verify_depth
syn keyword ngxDirective contained zone_sync_timeout


" 3rd party modules list taken from
" https://github.com/freebsd/freebsd-ports/blob/main/www/nginx-devel/Makefile.extmod
" ----------------------------------------------------------------------------------

" https://github.com/msva/nginx_ajp_module
syn keyword ngxDirectiveThirdParty contained ajp_buffer_size
syn keyword ngxDirectiveThirdParty contained ajp_buffers
syn keyword ngxDirectiveThirdParty contained ajp_busy_buffers_size
syn keyword ngxDirectiveThirdParty contained ajp_cache
syn keyword ngxDirectiveThirdParty contained ajp_cache_key
syn keyword ngxDirectiveThirdParty contained ajp_cache_lock
syn keyword ngxDirectiveThirdParty contained ajp_cache_lock_timeout
syn keyword ngxDirectiveThirdParty contained ajp_cache_methods
syn keyword ngxDirectiveThirdParty contained ajp_cache_min_uses
syn keyword ngxDirectiveThirdParty contained ajp_cache_path
syn keyword ngxDirectiveThirdParty contained ajp_cache_use_stale
syn keyword ngxDirectiveThirdParty contained ajp_cache_valid
syn keyword ngxDirectiveThirdParty contained ajp_connect_timeout
syn keyword ngxDirectiveThirdParty contained ajp_header_packet_buffer_size
syn keyword ngxDirectiveThirdParty contained ajp_hide_header
syn keyword ngxDirectiveThirdParty contained ajp_ignore_client_abort
syn keyword ngxDirectiveThirdParty contained ajp_ignore_headers
syn keyword ngxDirectiveThirdParty contained ajp_intercept_errors
syn keyword ngxDirectiveThirdParty contained ajp_keep_conn
syn keyword ngxDirectiveThirdParty contained ajp_max_data_packet_size
syn keyword ngxDirectiveThirdParty contained ajp_max_temp_file_size
syn keyword ngxDirectiveThirdParty contained ajp_next_upstream
syn keyword ngxDirectiveThirdParty contained ajp_param
syn keyword ngxDirectiveThirdParty contained ajp_pass
syn keyword ngxDirectiveThirdParty contained ajp_pass_header
syn keyword ngxDirectiveThirdParty contained ajp_pass_request_body
syn keyword ngxDirectiveThirdParty contained ajp_pass_request_headers
syn keyword ngxDirectiveThirdParty contained ajp_read_timeout
syn keyword ngxDirectiveThirdParty contained ajp_script_url
syn keyword ngxDirectiveThirdParty contained ajp_secret
syn keyword ngxDirectiveThirdParty contained ajp_send_lowat
syn keyword ngxDirectiveThirdParty contained ajp_send_timeout
syn keyword ngxDirectiveThirdParty contained ajp_store
syn keyword ngxDirectiveThirdParty contained ajp_store_access
syn keyword ngxDirectiveThirdParty contained ajp_temp_file_write_size
syn keyword ngxDirectiveThirdParty contained ajp_temp_path
syn keyword ngxDirectiveThirdParty contained ajp_upstream_fail_timeout
syn keyword ngxDirectiveThirdParty contained ajp_upstream_max_fails

" https://github.com/openresty/array-var-nginx-module
syn keyword ngxDirectiveThirdParty contained array_join
syn keyword ngxDirectiveThirdParty contained array_map
syn keyword ngxDirectiveThirdParty contained array_map_op
syn keyword ngxDirectiveThirdParty contained array_split

" https://github.com/anomalizer/ngx_aws_auth
syn keyword ngxDirectiveThirdParty contained aws_access_key
syn keyword ngxDirectiveThirdParty contained aws_endpoint
syn keyword ngxDirectiveThirdParty contained aws_key_scope
syn keyword ngxDirectiveThirdParty contained aws_s3_bucket
syn keyword ngxDirectiveThirdParty contained aws_sign
syn keyword ngxDirectiveThirdParty contained aws_signing_key

" https://github.com/google/ngx_brotli
syn keyword ngxDirectiveThirdParty contained brotli
syn keyword ngxDirectiveThirdParty contained brotli_buffers
syn keyword ngxDirectiveThirdParty contained brotli_comp_level
syn keyword ngxDirectiveThirdParty contained brotli_min_length
syn keyword ngxDirectiveThirdParty contained brotli_static
syn keyword ngxDirectiveThirdParty contained brotli_types
syn keyword ngxDirectiveThirdParty contained brotli_window

" https://github.com/torden/ngx_cache_purge
syn keyword ngxDirectiveThirdParty contained cache_purge_response_type

" https://github.com/nginx-clojure/nginx-clojure
syn keyword ngxDirectiveThirdParty contained access_handler_code
syn keyword ngxDirectiveThirdParty contained access_handler_name
syn keyword ngxDirectiveThirdParty contained access_handler_property
syn keyword ngxDirectiveThirdParty contained access_handler_type
syn keyword ngxDirectiveThirdParty contained always_read_body
syn keyword ngxDirectiveThirdParty contained auto_upgrade_ws
syn keyword ngxDirectiveThirdParty contained body_filter_code
syn keyword ngxDirectiveThirdParty contained body_filter_name
syn keyword ngxDirectiveThirdParty contained body_filter_property
syn keyword ngxDirectiveThirdParty contained body_filter_type
syn keyword ngxDirectiveThirdParty contained content_handler_code
syn keyword ngxDirectiveThirdParty contained content_handler_name
syn keyword ngxDirectiveThirdParty contained content_handler_property
syn keyword ngxDirectiveThirdParty contained content_handler_type
syn keyword ngxDirectiveThirdParty contained handler_code
syn keyword ngxDirectiveThirdParty contained handler_name
syn keyword ngxDirectiveThirdParty contained handler_type
syn keyword ngxDirectiveThirdParty contained handlers_lazy_init
syn keyword ngxDirectiveThirdParty contained header_filter_code
syn keyword ngxDirectiveThirdParty contained header_filter_name
syn keyword ngxDirectiveThirdParty contained header_filter_property
syn keyword ngxDirectiveThirdParty contained header_filter_type
syn keyword ngxDirectiveThirdParty contained jvm_classpath
syn keyword ngxDirectiveThirdParty contained jvm_classpath_check
syn keyword ngxDirectiveThirdParty contained jvm_exit_handler_code
syn keyword ngxDirectiveThirdParty contained jvm_exit_handler_name
syn keyword ngxDirectiveThirdParty contained jvm_handler_type
syn keyword ngxDirectiveThirdParty contained jvm_init_handler_code
syn keyword ngxDirectiveThirdParty contained jvm_init_handler_name
syn keyword ngxDirectiveThirdParty contained jvm_options
syn keyword ngxDirectiveThirdParty contained jvm_path
syn keyword ngxDirectiveThirdParty contained jvm_var
syn keyword ngxDirectiveThirdParty contained jvm_workers
syn keyword ngxDirectiveThirdParty contained log_handler_code
syn keyword ngxDirectiveThirdParty contained log_handler_name
syn keyword ngxDirectiveThirdParty contained log_handler_property
syn keyword ngxDirectiveThirdParty contained log_handler_type
syn keyword ngxDirectiveThirdParty contained max_balanced_tcp_connections
syn keyword ngxDirectiveThirdParty contained rewrite_handler_code
syn keyword ngxDirectiveThirdParty contained rewrite_handler_name
syn keyword ngxDirectiveThirdParty contained rewrite_handler_property
syn keyword ngxDirectiveThirdParty contained rewrite_handler_type
syn keyword ngxDirectiveThirdParty contained shared_map
syn keyword ngxDirectiveThirdParty contained write_page_size

" https://github.com/AirisX/nginx_cookie_flag_module
syn keyword ngxDirectiveThirdParty contained set_cookie_flag

" https://github.com/grahamedgecombe/nginx-ct
syn keyword ngxDirectiveThirdParty contained ssl_ct
syn keyword ngxDirectiveThirdParty contained ssl_ct_static_scts

" https://github.com/openresty/echo-nginx-module
syn keyword ngxDirectiveThirdParty contained echo
syn keyword ngxDirectiveThirdParty contained echo_abort_parent
syn keyword ngxDirectiveThirdParty contained echo_after_body
syn keyword ngxDirectiveThirdParty contained echo_before_body
syn keyword ngxDirectiveThirdParty contained echo_blocking_sleep
syn keyword ngxDirectiveThirdParty contained echo_duplicate
syn keyword ngxDirectiveThirdParty contained echo_end
syn keyword ngxDirectiveThirdParty contained echo_exec
syn keyword ngxDirectiveThirdParty contained echo_flush
syn keyword ngxDirectiveThirdParty contained echo_foreach_split
syn keyword ngxDirectiveThirdParty contained echo_location
syn keyword ngxDirectiveThirdParty contained echo_location_async
syn keyword ngxDirectiveThirdParty contained echo_read_request_body
syn keyword ngxDirectiveThirdParty contained echo_request_body
syn keyword ngxDirectiveThirdParty contained echo_reset_timer
syn keyword ngxDirectiveThirdParty contained echo_sleep
syn keyword ngxDirectiveThirdParty contained echo_status
syn keyword ngxDirectiveThirdParty contained echo_subrequest
syn keyword ngxDirectiveThirdParty contained echo_subrequest_async

" https://github.com/openresty/drizzle-nginx-module
syn keyword ngxDirectiveThirdParty contained drizzle_buffer_size
syn keyword ngxDirectiveThirdParty contained drizzle_connect_timeout
syn keyword ngxDirectiveThirdParty contained drizzle_dbname
syn keyword ngxDirectiveThirdParty contained drizzle_keepalive
syn keyword ngxDirectiveThirdParty contained drizzle_module_header
syn keyword ngxDirectiveThirdParty contained drizzle_pass
syn keyword ngxDirectiveThirdParty contained drizzle_query
syn keyword ngxDirectiveThirdParty contained drizzle_recv_cols_timeout
syn keyword ngxDirectiveThirdParty contained drizzle_recv_rows_timeout
syn keyword ngxDirectiveThirdParty contained drizzle_send_query_timeout
syn keyword ngxDirectiveThirdParty contained drizzle_server
syn keyword ngxDirectiveThirdParty contained drizzle_status

" https://github.com/ZigzagAK/ngx_dynamic_upstream
syn keyword ngxDirectiveThirdParty contained dns_add_down
syn keyword ngxDirectiveThirdParty contained dns_ipv6
syn keyword ngxDirectiveThirdParty contained dns_update
syn keyword ngxDirectiveThirdParty contained dynamic_state_file
syn keyword ngxDirectiveThirdParty contained dynamic_upstream

" https://github.com/ZigzagAK/ngx_dynamic_healthcheck
syn keyword ngxDirectiveThirdParty contained check
syn keyword ngxDirectiveThirdParty contained check_disable_host
syn keyword ngxDirectiveThirdParty contained check_exclude_host
syn keyword ngxDirectiveThirdParty contained check_persistent
syn keyword ngxDirectiveThirdParty contained check_request_body
syn keyword ngxDirectiveThirdParty contained check_request_headers
syn keyword ngxDirectiveThirdParty contained check_request_uri
syn keyword ngxDirectiveThirdParty contained check_response_body
syn keyword ngxDirectiveThirdParty contained check_response_codes
syn keyword ngxDirectiveThirdParty contained healthcheck
syn keyword ngxDirectiveThirdParty contained healthcheck_buffer_size
syn keyword ngxDirectiveThirdParty contained healthcheck_disable_host
syn keyword ngxDirectiveThirdParty contained healthcheck_get
syn keyword ngxDirectiveThirdParty contained healthcheck_persistent
syn keyword ngxDirectiveThirdParty contained healthcheck_request_body
syn keyword ngxDirectiveThirdParty contained healthcheck_request_headers
syn keyword ngxDirectiveThirdParty contained healthcheck_request_uri
syn keyword ngxDirectiveThirdParty contained healthcheck_response_body
syn keyword ngxDirectiveThirdParty contained healthcheck_response_codes
syn keyword ngxDirectiveThirdParty contained healthcheck_status
syn keyword ngxDirectiveThirdParty contained healthcheck_update

" https://github.com/openresty/encrypted-session-nginx-module
syn keyword ngxDirectiveThirdParty contained encrypted_session_expires
syn keyword ngxDirectiveThirdParty contained encrypted_session_iv
syn keyword ngxDirectiveThirdParty contained encrypted_session_key
syn keyword ngxDirectiveThirdParty contained set_decrypt_session
syn keyword ngxDirectiveThirdParty contained set_encrypt_session

" https://github.com/calio/form-input-nginx-module
syn keyword ngxDirectiveThirdParty contained set_form_input
syn keyword ngxDirectiveThirdParty contained set_form_input_multi

" https://github.com/nieoding/nginx-gridfs
syn keyword ngxDirectiveThirdParty contained gridfs
syn keyword ngxDirectiveThirdParty contained mongo

" https://github.com/openresty/headers-more-nginx-module
syn keyword ngxDirectiveThirdParty contained more_clear_headers
syn keyword ngxDirectiveThirdParty contained more_clear_input_headers
syn keyword ngxDirectiveThirdParty contained more_set_headers
syn keyword ngxDirectiveThirdParty contained more_set_input_headers

" https://github.com/dvershinin/nginx_accept_language_module
syn keyword ngxDirectiveThirdParty contained set_from_accept_language

" https://github.com/atomx/nginx-http-auth-digest
syn keyword ngxDirectiveThirdParty contained auth_digest
syn keyword ngxDirectiveThirdParty contained auth_digest_drop_time
syn keyword ngxDirectiveThirdParty contained auth_digest_evasion_time
syn keyword ngxDirectiveThirdParty contained auth_digest_expires
syn keyword ngxDirectiveThirdParty contained auth_digest_maxtries
syn keyword ngxDirectiveThirdParty contained auth_digest_replays
syn keyword ngxDirectiveThirdParty contained auth_digest_shm_size
syn keyword ngxDirectiveThirdParty contained auth_digest_timeout
syn keyword ngxDirectiveThirdParty contained auth_digest_user_file

" https://github.com/stnoonan/spnego-http-auth-nginx-module
syn keyword ngxDirectiveThirdParty contained auth_gss
syn keyword ngxDirectiveThirdParty contained auth_gss_allow_basic_fallback
syn keyword ngxDirectiveThirdParty contained auth_gss_authorized_principal
syn keyword ngxDirectiveThirdParty contained auth_gss_authorized_principal_regex
syn keyword ngxDirectiveThirdParty contained auth_gss_constrained_delegation
syn keyword ngxDirectiveThirdParty contained auth_gss_delegate_credentials
syn keyword ngxDirectiveThirdParty contained auth_gss_force_realm
syn keyword ngxDirectiveThirdParty contained auth_gss_format_full
syn keyword ngxDirectiveThirdParty contained auth_gss_keytab
syn keyword ngxDirectiveThirdParty contained auth_gss_map_to_local
syn keyword ngxDirectiveThirdParty contained auth_gss_realm
syn keyword ngxDirectiveThirdParty contained auth_gss_service_ccache
syn keyword ngxDirectiveThirdParty contained auth_gss_service_name

" https://github.com/kvspb/nginx-auth-ldap
syn keyword ngxDirectiveThirdParty contained auth_ldap
syn keyword ngxDirectiveThirdParty contained auth_ldap_cache_enabled
syn keyword ngxDirectiveThirdParty contained auth_ldap_cache_expiration_time
syn keyword ngxDirectiveThirdParty contained auth_ldap_cache_size
syn keyword ngxDirectiveThirdParty contained auth_ldap_servers
syn keyword ngxDirectiveThirdParty contained auth_ldap_servers_size
syn keyword ngxDirectiveThirdParty contained ldap_server

" https://github.com/sto/ngx_http_auth_pam_module
syn keyword ngxDirectiveThirdParty contained auth_pam
syn keyword ngxDirectiveThirdParty contained auth_pam_service_name
syn keyword ngxDirectiveThirdParty contained auth_pam_set_pam_env

" https://github.com/arut/nginx-dav-ext-module
syn keyword ngxDirectiveThirdParty contained dav_ext_lock
syn keyword ngxDirectiveThirdParty contained dav_ext_lock_zone
syn keyword ngxDirectiveThirdParty contained dav_ext_methods

" https://github.com/openresty/nginx-eval-module
syn keyword ngxDirectiveThirdParty contained eval
syn keyword ngxDirectiveThirdParty contained eval_buffer_size
syn keyword ngxDirectiveThirdParty contained eval_escalate
syn keyword ngxDirectiveThirdParty contained eval_override_content_type
syn keyword ngxDirectiveThirdParty contained eval_subrequest_in_memory

" https://github.com/aperezdc/ngx-fancyindex
syn keyword ngxDirectiveThirdParty contained fancyindex
syn keyword ngxDirectiveThirdParty contained fancyindex_css_href
syn keyword ngxDirectiveThirdParty contained fancyindex_default_sort
syn keyword ngxDirectiveThirdParty contained fancyindex_directories_first
syn keyword ngxDirectiveThirdParty contained fancyindex_exact_size
syn keyword ngxDirectiveThirdParty contained fancyindex_footer
syn keyword ngxDirectiveThirdParty contained fancyindex_header
syn keyword ngxDirectiveThirdParty contained fancyindex_hide_parent_dir
syn keyword ngxDirectiveThirdParty contained fancyindex_hide_symlinks
syn keyword ngxDirectiveThirdParty contained fancyindex_ignore
syn keyword ngxDirectiveThirdParty contained fancyindex_localtime
syn keyword ngxDirectiveThirdParty contained fancyindex_show_dotfiles
syn keyword ngxDirectiveThirdParty contained fancyindex_show_path
syn keyword ngxDirectiveThirdParty contained fancyindex_time_format

" https://github.com/alibaba/nginx-http-footer-filter
syn keyword ngxDirectiveThirdParty contained footer
syn keyword ngxDirectiveThirdParty contained footer_types

" https://github.com/leev/ngx_http_geoip2_module
syn keyword ngxDirectiveThirdParty contained geoip2
syn keyword ngxDirectiveThirdParty contained geoip2_proxy
syn keyword ngxDirectiveThirdParty contained geoip2_proxy_recursive

" https://github.com/ip2location/ip2location-nginx
syn keyword ngxDirectiveThirdParty contained ip2location_database
syn keyword ngxDirectiveThirdParty contained ip2location_proxy
syn keyword ngxDirectiveThirdParty contained ip2location_proxy_recursive

" https://github.com/ip2location/ip2proxy-nginx
syn keyword ngxDirectiveThirdParty contained ip2proxy_database
syn keyword ngxDirectiveThirdParty contained ip2proxy_proxy
syn keyword ngxDirectiveThirdParty contained ip2proxy_proxy_recursive

" https://github.com/kr/nginx-notice
syn keyword ngxDirectiveThirdParty contained notice
syn keyword ngxDirectiveThirdParty contained notice_type

" https://github.com/slact/nchan
syn keyword ngxDirectiveThirdParty contained nchan_access_control_allow_credentials
syn keyword ngxDirectiveThirdParty contained nchan_access_control_allow_origin
syn keyword ngxDirectiveThirdParty contained nchan_authorize_request
syn keyword ngxDirectiveThirdParty contained nchan_benchmark
syn keyword ngxDirectiveThirdParty contained nchan_benchmark_channels
syn keyword ngxDirectiveThirdParty contained nchan_benchmark_message_padding_bytes
syn keyword ngxDirectiveThirdParty contained nchan_benchmark_messages_per_channel_per_minute
syn keyword ngxDirectiveThirdParty contained nchan_benchmark_publisher_distribution
syn keyword ngxDirectiveThirdParty contained nchan_benchmark_subscriber_distribution
syn keyword ngxDirectiveThirdParty contained nchan_benchmark_subscribers_per_channel
syn keyword ngxDirectiveThirdParty contained nchan_benchmark_time
syn keyword ngxDirectiveThirdParty contained nchan_channel_event_string
syn keyword ngxDirectiveThirdParty contained nchan_channel_events_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_channel_group
syn keyword ngxDirectiveThirdParty contained nchan_channel_group_accounting
syn keyword ngxDirectiveThirdParty contained nchan_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_channel_id_split_delimiter
syn keyword ngxDirectiveThirdParty contained nchan_channel_timeout
syn keyword ngxDirectiveThirdParty contained nchan_deflate_message_for_websocket
syn keyword ngxDirectiveThirdParty contained nchan_eventsource_event
syn keyword ngxDirectiveThirdParty contained nchan_eventsource_ping_comment
syn keyword ngxDirectiveThirdParty contained nchan_eventsource_ping_data
syn keyword ngxDirectiveThirdParty contained nchan_eventsource_ping_event
syn keyword ngxDirectiveThirdParty contained nchan_eventsource_ping_interval
syn keyword ngxDirectiveThirdParty contained nchan_group_location
syn keyword ngxDirectiveThirdParty contained nchan_group_max_channels
syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages
syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages_disk
syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages_memory
syn keyword ngxDirectiveThirdParty contained nchan_group_max_subscribers
syn keyword ngxDirectiveThirdParty contained nchan_longpoll_multipart_response
syn keyword ngxDirectiveThirdParty contained nchan_max_channel_id_length
syn keyword ngxDirectiveThirdParty contained nchan_max_channel_subscribers
syn keyword ngxDirectiveThirdParty contained nchan_max_reserved_memory
syn keyword ngxDirectiveThirdParty contained nchan_message_buffer_length
syn keyword ngxDirectiveThirdParty contained nchan_message_max_buffer_length
syn keyword ngxDirectiveThirdParty contained nchan_message_temp_path
syn keyword ngxDirectiveThirdParty contained nchan_message_timeout
syn keyword ngxDirectiveThirdParty contained nchan_permessage_deflate_compression_level
syn keyword ngxDirectiveThirdParty contained nchan_permessage_deflate_compression_memlevel
syn keyword ngxDirectiveThirdParty contained nchan_permessage_deflate_compression_strategy
syn keyword ngxDirectiveThirdParty contained nchan_permessage_deflate_compression_window
syn keyword ngxDirectiveThirdParty contained nchan_pub_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_publisher
syn keyword ngxDirectiveThirdParty contained nchan_publisher_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_publisher_location
syn keyword ngxDirectiveThirdParty contained nchan_publisher_upstream_request
syn keyword ngxDirectiveThirdParty contained nchan_pubsub
syn keyword ngxDirectiveThirdParty contained nchan_pubsub_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_pubsub_location
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval_backoff
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval_jitter
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval_max
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval_min
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_connect_timeout
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_max_failing_time
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay_backoff
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay_jitter
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay_max
syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay_min
syn keyword ngxDirectiveThirdParty contained nchan_redis_command_timeout
syn keyword ngxDirectiveThirdParty contained nchan_redis_connect_timeout
syn keyword ngxDirectiveThirdParty contained nchan_redis_discovered_ip_range_blacklist
syn keyword ngxDirectiveThirdParty contained nchan_redis_fakesub_timer_interval
syn keyword ngxDirectiveThirdParty contained nchan_redis_idle_channel_cache_timeout
syn keyword ngxDirectiveThirdParty contained nchan_redis_load_scripts_unconditionally
syn keyword ngxDirectiveThirdParty contained nchan_redis_namespace
syn keyword ngxDirectiveThirdParty contained nchan_redis_node_connect_timeout
syn keyword ngxDirectiveThirdParty contained nchan_redis_nostore_fastpublish
syn keyword ngxDirectiveThirdParty contained nchan_redis_optimize_target
syn keyword ngxDirectiveThirdParty contained nchan_redis_pass
syn keyword ngxDirectiveThirdParty contained nchan_redis_pass_inheritable
syn keyword ngxDirectiveThirdParty contained nchan_redis_password
syn keyword ngxDirectiveThirdParty contained nchan_redis_ping_interval
syn keyword ngxDirectiveThirdParty contained nchan_redis_publish_msgpacked_max_size
syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay
syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay_backoff
syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay_jitter
syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay_max
syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay_min
syn keyword ngxDirectiveThirdParty contained nchan_redis_retry_commands
syn keyword ngxDirectiveThirdParty contained nchan_redis_retry_commands_max_wait
syn keyword ngxDirectiveThirdParty contained nchan_redis_server
syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl
syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_ciphers
syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_client_certificate
syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_client_certificate_key
syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_server_name
syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_trusted_certificate
syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_trusted_certificate_path
syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_verify_certificate
syn keyword ngxDirectiveThirdParty contained nchan_redis_storage_mode
syn keyword ngxDirectiveThirdParty contained nchan_redis_subscribe_weights
syn keyword ngxDirectiveThirdParty contained nchan_redis_tls
syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_ciphers
syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_client_certificate
syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_server_name
syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_trusted_certificate
syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_trusted_certificate_path
syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_verify_certificate
syn keyword ngxDirectiveThirdParty contained nchan_redis_url
syn keyword ngxDirectiveThirdParty contained nchan_redis_username
syn keyword ngxDirectiveThirdParty contained nchan_redis_wait_after_connecting
syn keyword ngxDirectiveThirdParty contained nchan_shared_memory_size
syn keyword ngxDirectiveThirdParty contained nchan_storage_engine
syn keyword ngxDirectiveThirdParty contained nchan_store_messages
syn keyword ngxDirectiveThirdParty contained nchan_stub_status
syn keyword ngxDirectiveThirdParty contained nchan_sub_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_subscribe_existing_channels_only
syn keyword ngxDirectiveThirdParty contained nchan_subscribe_request
syn keyword ngxDirectiveThirdParty contained nchan_subscriber
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_channel_id
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_compound_etag_message_id
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_first_message
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_http_raw_stream_separator
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_info
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_info_string
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_last_message_id
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_location
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_message_id_custom_etag_header
syn keyword ngxDirectiveThirdParty contained nchan_subscriber_timeout
syn keyword ngxDirectiveThirdParty contained nchan_unsubscribe_request
syn keyword ngxDirectiveThirdParty contained nchan_use_redis
syn keyword ngxDirectiveThirdParty contained nchan_websocket_client_heartbeat
syn keyword ngxDirectiveThirdParty contained nchan_websocket_ping_interval
syn keyword ngxDirectiveThirdParty contained push_authorized_channels_only
syn keyword ngxDirectiveThirdParty contained push_channel_group
syn keyword ngxDirectiveThirdParty contained push_channel_timeout
syn keyword ngxDirectiveThirdParty contained push_max_channel_id_length
syn keyword ngxDirectiveThirdParty contained push_max_channel_subscribers
syn keyword ngxDirectiveThirdParty contained push_max_message_buffer_length
syn keyword ngxDirectiveThirdParty contained push_max_reserved_memory
syn keyword ngxDirectiveThirdParty contained push_message_buffer_length
syn keyword ngxDirectiveThirdParty contained push_message_timeout
syn keyword ngxDirectiveThirdParty contained push_min_message_buffer_length
syn keyword ngxDirectiveThirdParty contained push_publisher
syn keyword ngxDirectiveThirdParty contained push_store_messages
syn keyword ngxDirectiveThirdParty contained push_subscriber
syn keyword ngxDirectiveThirdParty contained push_subscriber_concurrency
syn keyword ngxDirectiveThirdParty contained push_subscriber_timeout

" https://github.com/wandenberg/nginx-push-stream-module
syn keyword ngxDirectiveThirdParty contained push_stream_allow_connections_to_events_channel
syn keyword ngxDirectiveThirdParty contained push_stream_allowed_origins
syn keyword ngxDirectiveThirdParty contained push_stream_authorized_channels_only
syn keyword ngxDirectiveThirdParty contained push_stream_channel_deleted_message_text
syn keyword ngxDirectiveThirdParty contained push_stream_channel_inactivity_time
syn keyword ngxDirectiveThirdParty contained push_stream_channel_info_on_publish
syn keyword ngxDirectiveThirdParty contained push_stream_channels_path
syn keyword ngxDirectiveThirdParty contained push_stream_channels_statistics
syn keyword ngxDirectiveThirdParty contained push_stream_events_channel_id
syn keyword ngxDirectiveThirdParty contained push_stream_footer_template
syn keyword ngxDirectiveThirdParty contained push_stream_header_template
syn keyword ngxDirectiveThirdParty contained push_stream_header_template_file
syn keyword ngxDirectiveThirdParty contained push_stream_last_event_id
syn keyword ngxDirectiveThirdParty contained push_stream_last_received_message_tag
syn keyword ngxDirectiveThirdParty contained push_stream_last_received_message_time
syn keyword ngxDirectiveThirdParty contained push_stream_longpolling_connection_ttl
syn keyword ngxDirectiveThirdParty contained push_stream_max_channel_id_length
syn keyword ngxDirectiveThirdParty contained push_stream_max_messages_stored_per_channel
syn keyword ngxDirectiveThirdParty contained push_stream_max_number_of_channels
syn keyword ngxDirectiveThirdParty contained push_stream_max_number_of_wildcard_channels
syn keyword ngxDirectiveThirdParty contained push_stream_max_subscribers_per_channel
syn keyword ngxDirectiveThirdParty contained push_stream_message_template
syn keyword ngxDirectiveThirdParty contained push_stream_message_ttl
syn keyword ngxDirectiveThirdParty contained push_stream_padding_by_user_agent
syn keyword ngxDirectiveThirdParty contained push_stream_ping_message_interval
syn keyword ngxDirectiveThirdParty contained push_stream_ping_message_text
syn keyword ngxDirectiveThirdParty contained push_stream_publisher
syn keyword ngxDirectiveThirdParty contained push_stream_shared_memory_size
syn keyword ngxDirectiveThirdParty contained push_stream_store_messages
syn keyword ngxDirectiveThirdParty contained push_stream_subscriber
syn keyword ngxDirectiveThirdParty contained push_stream_subscriber_connection_ttl
syn keyword ngxDirectiveThirdParty contained push_stream_timeout_with_body
syn keyword ngxDirectiveThirdParty contained push_stream_user_agent
syn keyword ngxDirectiveThirdParty contained push_stream_websocket_allow_publish
syn keyword ngxDirectiveThirdParty contained push_stream_wildcard_channel_max_qtd
syn keyword ngxDirectiveThirdParty contained push_stream_wildcard_channel_prefix

" https://github.com/yaoweibin/ngx_http_substitutions_filter_module
syn keyword ngxDirectiveThirdParty contained subs_buffers
syn keyword ngxDirectiveThirdParty contained subs_filter
syn keyword ngxDirectiveThirdParty contained subs_filter_bypass
syn keyword ngxDirectiveThirdParty contained subs_filter_types
syn keyword ngxDirectiveThirdParty contained subs_line_buffer_size

" https://github.com/tarantool/nginx_upstream_module
syn keyword ngxDirectiveThirdParty contained tnt_allowed_indexes
syn keyword ngxDirectiveThirdParty contained tnt_allowed_spaces
syn keyword ngxDirectiveThirdParty contained tnt_buffer_size
syn keyword ngxDirectiveThirdParty contained tnt_connect_timeout
syn keyword ngxDirectiveThirdParty contained tnt_delete
syn keyword ngxDirectiveThirdParty contained tnt_http_methods
syn keyword ngxDirectiveThirdParty contained tnt_http_rest_methods
syn keyword ngxDirectiveThirdParty contained tnt_in_multiplier
syn keyword ngxDirectiveThirdParty contained tnt_insert
syn keyword ngxDirectiveThirdParty contained tnt_method
syn keyword ngxDirectiveThirdParty contained tnt_multireturn_skip_count
syn keyword ngxDirectiveThirdParty contained tnt_next_upstream
syn keyword ngxDirectiveThirdParty contained tnt_next_upstream_timeout
syn keyword ngxDirectiveThirdParty contained tnt_next_upstream_tries
syn keyword ngxDirectiveThirdParty contained tnt_out_multiplier
syn keyword ngxDirectiveThirdParty contained tnt_pass
syn keyword ngxDirectiveThirdParty contained tnt_pass_http_request
syn keyword ngxDirectiveThirdParty contained tnt_pass_http_request_buffer_size
syn keyword ngxDirectiveThirdParty contained tnt_pure_result
syn keyword ngxDirectiveThirdParty contained tnt_read_timeout
syn keyword ngxDirectiveThirdParty contained tnt_replace
syn keyword ngxDirectiveThirdParty contained tnt_select
syn keyword ngxDirectiveThirdParty contained tnt_select_limit_max
syn keyword ngxDirectiveThirdParty contained tnt_send_timeout
syn keyword ngxDirectiveThirdParty contained tnt_set_header
syn keyword ngxDirectiveThirdParty contained tnt_update
syn keyword ngxDirectiveThirdParty contained tnt_upsert

" https://github.com/fdintino/nginx-upload-module
syn keyword ngxDirectiveThirdParty contained upload_add_header
syn keyword ngxDirectiveThirdParty contained upload_aggregate_form_field
syn keyword ngxDirectiveThirdParty contained upload_buffer_size
syn keyword ngxDirectiveThirdParty contained upload_cleanup
syn keyword ngxDirectiveThirdParty contained upload_empty_fiels_names
syn keyword ngxDirectiveThirdParty contained upload_limit_rate
syn keyword ngxDirectiveThirdParty contained upload_max_file_size
syn keyword ngxDirectiveThirdParty contained upload_max_output_body_len
syn keyword ngxDirectiveThirdParty contained upload_max_part_header_len
syn keyword ngxDirectiveThirdParty contained upload_merge_buffer_size
syn keyword ngxDirectiveThirdParty contained upload_pass
syn keyword ngxDirectiveThirdParty contained upload_pass_args
syn keyword ngxDirectiveThirdParty contained upload_pass_form_field
syn keyword ngxDirectiveThirdParty contained upload_range_header_buffer_size
syn keyword ngxDirectiveThirdParty contained upload_resumable
syn keyword ngxDirectiveThirdParty contained upload_set_form_field
syn keyword ngxDirectiveThirdParty contained upload_state_store
syn keyword ngxDirectiveThirdParty contained upload_store
syn keyword ngxDirectiveThirdParty contained upload_store_access
syn keyword ngxDirectiveThirdParty contained upload_tame_arrays

" https://github.com/masterzen/nginx-upload-progress-module
syn keyword ngxDirectiveThirdParty contained report_uploads
syn keyword ngxDirectiveThirdParty contained track_uploads
syn keyword ngxDirectiveThirdParty contained upload_progress
syn keyword ngxDirectiveThirdParty contained upload_progress_content_type
syn keyword ngxDirectiveThirdParty contained upload_progress_header
syn keyword ngxDirectiveThirdParty contained upload_progress_java_output
syn keyword ngxDirectiveThirdParty contained upload_progress_json_output
syn keyword ngxDirectiveThirdParty contained upload_progress_jsonp_output
syn keyword ngxDirectiveThirdParty contained upload_progress_jsonp_parameter
syn keyword ngxDirectiveThirdParty contained upload_progress_template

" https://github.com/yaoweibin/nginx_upstream_check_module
syn keyword ngxDirectiveThirdParty contained check_fastcgi_param
syn keyword ngxDirectiveThirdParty contained check_http_expect_alive
syn keyword ngxDirectiveThirdParty contained check_http_send
syn keyword ngxDirectiveThirdParty contained check_keepalive_requests
syn keyword ngxDirectiveThirdParty contained check_shm_size
syn keyword ngxDirectiveThirdParty contained check_status

" https://github.com/jaygooby/nginx-upstream-fair
syn keyword ngxDirectiveThirdParty contained fair
syn keyword ngxDirectiveThirdParty contained upstream_fair_shm_size

" https://github.com/ayty-adrianomartins/nginx-sticky-module-ng
syn keyword ngxDirectiveThirdParty contained sticky_no_fallback

" https://github.com/Novetta/nginx-video-thumbextractor-module
syn keyword ngxDirectiveThirdParty contained video_thumbextractor
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_image_height
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_image_width
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_baseline
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_dpi
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_optimize
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_progressive_mode
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_quality
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_smooth
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_next_time
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_only_keyframe
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_processes_per_worker
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_threads
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_color
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_cols
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_margin
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_max_cols
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_max_rows
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_padding
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_rows
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_sample_interval
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_video_filename
syn keyword ngxDirectiveThirdParty contained video_thumbextractor_video_second

" https://github.com/calio/iconv-nginx-module
syn keyword ngxDirectiveThirdParty contained iconv_buffer_size
syn keyword ngxDirectiveThirdParty contained iconv_filter
syn keyword ngxDirectiveThirdParty contained set_iconv

" https://github.com/baysao/nginx-let-module
syn keyword ngxDirectiveThirdParty contained let

" https://github.com/openresty/lua-nginx-module
syn keyword ngxDirectiveThirdParty contained access_by_lua
syn keyword ngxDirectiveThirdParty contained access_by_lua_block
syn keyword ngxDirectiveThirdParty contained access_by_lua_file
syn keyword ngxDirectiveThirdParty contained access_by_lua_no_postpone
syn keyword ngxDirectiveThirdParty contained balancer_by_lua_block
syn keyword ngxDirectiveThirdParty contained balancer_by_lua_file
syn keyword ngxDirectiveThirdParty contained body_filter_by_lua
syn keyword ngxDirectiveThirdParty contained body_filter_by_lua_block
syn keyword ngxDirectiveThirdParty contained body_filter_by_lua_file
syn keyword ngxDirectiveThirdParty contained content_by_lua
syn keyword ngxDirectiveThirdParty contained content_by_lua_block
syn keyword ngxDirectiveThirdParty contained content_by_lua_file
syn keyword ngxDirectiveThirdParty contained exit_worker_by_lua_block
syn keyword ngxDirectiveThirdParty contained exit_worker_by_lua_file
syn keyword ngxDirectiveThirdParty contained header_filter_by_lua
syn keyword ngxDirectiveThirdParty contained header_filter_by_lua_block
syn keyword ngxDirectiveThirdParty contained header_filter_by_lua_file
syn keyword ngxDirectiveThirdParty contained init_by_lua
syn keyword ngxDirectiveThirdParty contained init_by_lua_block
syn keyword ngxDirectiveThirdParty contained init_by_lua_file
syn keyword ngxDirectiveThirdParty contained init_worker_by_lua
syn keyword ngxDirectiveThirdParty contained init_worker_by_lua_block
syn keyword ngxDirectiveThirdParty contained init_worker_by_lua_file
syn keyword ngxDirectiveThirdParty contained log_by_lua
syn keyword ngxDirectiveThirdParty contained log_by_lua_block
syn keyword ngxDirectiveThirdParty contained log_by_lua_file
syn keyword ngxDirectiveThirdParty contained lua_capture_error_log
syn keyword ngxDirectiveThirdParty contained lua_check_client_abort
syn keyword ngxDirectiveThirdParty contained lua_code_cache
syn keyword ngxDirectiveThirdParty contained lua_fake_shm
syn keyword ngxDirectiveThirdParty contained lua_http10_buffering
syn keyword ngxDirectiveThirdParty contained lua_load_resty_core
syn keyword ngxDirectiveThirdParty contained lua_malloc_trim
syn keyword ngxDirectiveThirdParty contained lua_max_pending_timers
syn keyword ngxDirectiveThirdParty contained lua_max_running_timers
syn keyword ngxDirectiveThirdParty contained lua_need_request_body
syn keyword ngxDirectiveThirdParty contained lua_package_cpath
syn keyword ngxDirectiveThirdParty contained lua_package_path
syn keyword ngxDirectiveThirdParty contained lua_regex_cache_max_entries
syn keyword ngxDirectiveThirdParty contained lua_regex_match_limit
syn keyword ngxDirectiveThirdParty contained lua_sa_restart
syn keyword ngxDirectiveThirdParty contained lua_shared_dict
syn keyword ngxDirectiveThirdParty contained lua_socket_buffer_size
syn keyword ngxDirectiveThirdParty contained lua_socket_connect_timeout
syn keyword ngxDirectiveThirdParty contained lua_socket_keepalive_timeout
syn keyword ngxDirectiveThirdParty contained lua_socket_log_errors
syn keyword ngxDirectiveThirdParty contained lua_socket_pool_size
syn keyword ngxDirectiveThirdParty contained lua_socket_read_timeout
syn keyword ngxDirectiveThirdParty contained lua_socket_send_lowat
syn keyword ngxDirectiveThirdParty contained lua_socket_send_timeout
syn keyword ngxDirectiveThirdParty contained lua_ssl_ciphers
syn keyword ngxDirectiveThirdParty contained lua_ssl_conf_command
syn keyword ngxDirectiveThirdParty contained lua_ssl_crl
syn keyword ngxDirectiveThirdParty contained lua_ssl_protocols
syn keyword ngxDirectiveThirdParty contained lua_ssl_trusted_certificate
syn keyword ngxDirectiveThirdParty contained lua_ssl_verify_depth
syn keyword ngxDirectiveThirdParty contained lua_thread_cache_max_entries
syn keyword ngxDirectiveThirdParty contained lua_transform_underscores_in_response_headers
syn keyword ngxDirectiveThirdParty contained lua_use_default_type
syn keyword ngxDirectiveThirdParty contained lua_worker_thread_vm_pool_size
syn keyword ngxDirectiveThirdParty contained rewrite_by_lua
syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_block
syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_file
syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_no_postpone
syn keyword ngxDirectiveThirdParty contained server_rewrite_by_lua_block
syn keyword ngxDirectiveThirdParty contained server_rewrite_by_lua_file
syn keyword ngxDirectiveThirdParty contained set_by_lua
syn keyword ngxDirectiveThirdParty contained set_by_lua_block
syn keyword ngxDirectiveThirdParty contained set_by_lua_file
syn keyword ngxDirectiveThirdParty contained ssl_certificate_by_lua_block
syn keyword ngxDirectiveThirdParty contained ssl_certificate_by_lua_file
syn keyword ngxDirectiveThirdParty contained ssl_client_hello_by_lua_block
syn keyword ngxDirectiveThirdParty contained ssl_client_hello_by_lua_file
syn keyword ngxDirectiveThirdParty contained ssl_session_fetch_by_lua_block
syn keyword ngxDirectiveThirdParty contained ssl_session_fetch_by_lua_file
syn keyword ngxDirectiveThirdParty contained ssl_session_store_by_lua_block
syn keyword ngxDirectiveThirdParty contained ssl_session_store_by_lua_file

" https://github.com/Taymindis/nginx-link-function
syn keyword ngxDirectiveThirdParty contained ngx_link_func_add_prop
syn keyword ngxDirectiveThirdParty contained ngx_link_func_add_req_header
syn keyword ngxDirectiveThirdParty contained ngx_link_func_ca_cert
syn keyword ngxDirectiveThirdParty contained ngx_link_func_call
syn keyword ngxDirectiveThirdParty contained ngx_link_func_download_link_lib
syn keyword ngxDirectiveThirdParty contained ngx_link_func_lib
syn keyword ngxDirectiveThirdParty contained ngx_link_func_shm_size
syn keyword ngxDirectiveThirdParty contained ngx_link_func_subrequest

" https://github.com/openresty/memc-nginx-module
syn keyword ngxDirectiveThirdParty contained memc_buffer_size
syn keyword ngxDirectiveThirdParty contained memc_cmds_allowed
syn keyword ngxDirectiveThirdParty contained memc_connect_timeout
syn keyword ngxDirectiveThirdParty contained memc_flags_to_last_modified
syn keyword ngxDirectiveThirdParty contained memc_ignore_client_abort
syn keyword ngxDirectiveThirdParty contained memc_next_upstream
syn keyword ngxDirectiveThirdParty contained memc_pass
syn keyword ngxDirectiveThirdParty contained memc_read_timeout
syn keyword ngxDirectiveThirdParty contained memc_send_timeout
syn keyword ngxDirectiveThirdParty contained memc_upstream_fail_timeout
syn keyword ngxDirectiveThirdParty contained memc_upstream_max_fails

" https://github.com/SpiderLabs/ModSecurity-nginx
syn keyword ngxDirectiveThirdParty contained modsecurity
syn keyword ngxDirectiveThirdParty contained modsecurity_rules
syn keyword ngxDirectiveThirdParty contained modsecurity_rules_file
syn keyword ngxDirectiveThirdParty contained modsecurity_rules_remote
syn keyword ngxDirectiveThirdParty contained modsecurity_transaction_id

" https://github.com/nbs-system/naxsi
syn keyword ngxDirectiveThirdParty contained BasicRule
syn keyword ngxDirectiveThirdParty contained CheckRule
syn keyword ngxDirectiveThirdParty contained DeniedUrl
syn keyword ngxDirectiveThirdParty contained IgnoreCIDR
syn keyword ngxDirectiveThirdParty contained IgnoreIP
syn keyword ngxDirectiveThirdParty contained LearningMode
syn keyword ngxDirectiveThirdParty contained LibInjectionSql
syn keyword ngxDirectiveThirdParty contained LibInjectionXss
syn keyword ngxDirectiveThirdParty contained MainRule
syn keyword ngxDirectiveThirdParty contained NaxsiLogFile
syn keyword ngxDirectiveThirdParty contained SecRulesDisabled
syn keyword ngxDirectiveThirdParty contained SecRulesEnabled
syn keyword ngxDirectiveThirdParty contained basic_rule
syn keyword ngxDirectiveThirdParty contained check_rule
syn keyword ngxDirectiveThirdParty contained denied_url
syn keyword ngxDirectiveThirdParty contained learning_mode
syn keyword ngxDirectiveThirdParty contained libinjection_sql
syn keyword ngxDirectiveThirdParty contained libinjection_xss
syn keyword ngxDirectiveThirdParty contained main_rule
syn keyword ngxDirectiveThirdParty contained naxsi_log
syn keyword ngxDirectiveThirdParty contained rules_disabled
syn keyword ngxDirectiveThirdParty contained rules_enabled

" https://github.com/opentracing-contrib/nginx-opentracing
syn keyword ngxDirectiveThirdParty contained opentracing
syn keyword ngxDirectiveThirdParty contained opentracing_fastcgi_propagate_context
syn keyword ngxDirectiveThirdParty contained opentracing_grpc_propagate_context
syn keyword ngxDirectiveThirdParty contained opentracing_load_tracer
syn keyword ngxDirectiveThirdParty contained opentracing_location_operation_name
syn keyword ngxDirectiveThirdParty contained opentracing_operation_name
syn keyword ngxDirectiveThirdParty contained opentracing_propagate_context
syn keyword ngxDirectiveThirdParty contained opentracing_tag
syn keyword ngxDirectiveThirdParty contained opentracing_trace_locations
syn keyword ngxDirectiveThirdParty contained opentracing_trust_incoming_span

" https://github.com/phusion/passenger
syn keyword ngxDirectiveThirdParty contained passenger_abort_on_startup_error
syn keyword ngxDirectiveThirdParty contained passenger_abort_websockets_on_process_shutdown
syn keyword ngxDirectiveThirdParty contained passenger_admin_panel_auth_type
syn keyword ngxDirectiveThirdParty contained passenger_admin_panel_password
syn keyword ngxDirectiveThirdParty contained passenger_admin_panel_url
syn keyword ngxDirectiveThirdParty contained passenger_admin_panel_username
syn keyword ngxDirectiveThirdParty contained passenger_analytics_log_group
syn keyword ngxDirectiveThirdParty contained passenger_analytics_log_user
syn keyword ngxDirectiveThirdParty contained passenger_anonymous_telemetry_proxy
syn keyword ngxDirectiveThirdParty contained passenger_app_env
syn keyword ngxDirectiveThirdParty contained passenger_app_file_descriptor_ulimit
syn keyword ngxDirectiveThirdParty contained passenger_app_group_name
syn keyword ngxDirectiveThirdParty contained passenger_app_log_file
syn keyword ngxDirectiveThirdParty contained passenger_app_rights
syn keyword ngxDirectiveThirdParty contained passenger_app_root
syn keyword ngxDirectiveThirdParty contained passenger_app_start_command
syn keyword ngxDirectiveThirdParty contained passenger_app_type
syn keyword ngxDirectiveThirdParty contained passenger_base_uri
syn keyword ngxDirectiveThirdParty contained passenger_buffer_response
syn keyword ngxDirectiveThirdParty contained passenger_buffer_size
syn keyword ngxDirectiveThirdParty contained passenger_buffer_upload
syn keyword ngxDirectiveThirdParty contained passenger_buffers
syn keyword ngxDirectiveThirdParty contained passenger_busy_buffers_size
syn keyword ngxDirectiveThirdParty contained passenger_concurrency_model
syn keyword ngxDirectiveThirdParty contained passenger_core_file_descriptor_ulimit
syn keyword ngxDirectiveThirdParty contained passenger_ctl
syn keyword ngxDirectiveThirdParty contained passenger_data_buffer_dir
syn keyword ngxDirectiveThirdParty contained passenger_debug_log_file
syn keyword ngxDirectiveThirdParty contained passenger_debugger
syn keyword ngxDirectiveThirdParty contained passenger_default_group
syn keyword ngxDirectiveThirdParty contained passenger_default_user
syn keyword ngxDirectiveThirdParty contained passenger_direct_instance_request_address
syn keyword ngxDirectiveThirdParty contained passenger_disable_anonymous_telemetry
syn keyword ngxDirectiveThirdParty contained passenger_disable_log_prefix
syn keyword ngxDirectiveThirdParty contained passenger_disable_security_update_check
syn keyword ngxDirectiveThirdParty contained passenger_document_root
syn keyword ngxDirectiveThirdParty contained passenger_dump_config_manifest
syn keyword ngxDirectiveThirdParty contained passenger_enabled
syn keyword ngxDirectiveThirdParty contained passenger_env_var
syn keyword ngxDirectiveThirdParty contained passenger_file_descriptor_log_file
syn keyword ngxDirectiveThirdParty contained passenger_fly_with
syn keyword ngxDirectiveThirdParty contained passenger_force_max_concurrent_requests_per_process
syn keyword ngxDirectiveThirdParty contained passenger_friendly_error_pages
syn keyword ngxDirectiveThirdParty contained passenger_group
syn keyword ngxDirectiveThirdParty contained passenger_headers_hash_bucket_size
syn keyword ngxDirectiveThirdParty contained passenger_headers_hash_max_size
syn keyword ngxDirectiveThirdParty contained passenger_ignore_client_abort
syn keyword ngxDirectiveThirdParty contained passenger_ignore_headers
syn keyword ngxDirectiveThirdParty contained passenger_instance_registry_dir
syn keyword ngxDirectiveThirdParty contained passenger_intercept_errors
syn keyword ngxDirectiveThirdParty contained passenger_load_shell_envvars
syn keyword ngxDirectiveThirdParty contained passenger_log_file
syn keyword ngxDirectiveThirdParty contained passenger_log_level
syn keyword ngxDirectiveThirdParty contained passenger_max_instances
syn keyword ngxDirectiveThirdParty contained passenger_max_instances_per_app
syn keyword ngxDirectiveThirdParty contained passenger_max_pool_size
syn keyword ngxDirectiveThirdParty contained passenger_max_preloader_idle_time
syn keyword ngxDirectiveThirdParty contained passenger_max_request_queue_size
syn keyword ngxDirectiveThirdParty contained passenger_max_request_queue_time
syn keyword ngxDirectiveThirdParty contained passenger_max_request_time
syn keyword ngxDirectiveThirdParty contained passenger_max_requests
syn keyword ngxDirectiveThirdParty contained passenger_memory_limit
syn keyword ngxDirectiveThirdParty contained passenger_meteor_app_settings
syn keyword ngxDirectiveThirdParty contained passenger_min_instances
syn keyword ngxDirectiveThirdParty contained passenger_monitor_log_file
syn keyword ngxDirectiveThirdParty contained passenger_nodejs
syn keyword ngxDirectiveThirdParty contained passenger_pass_header
syn keyword ngxDirectiveThirdParty contained passenger_pool_idle_time
syn keyword ngxDirectiveThirdParty contained passenger_pre_start
syn keyword ngxDirectiveThirdParty contained passenger_preload_bundler
syn keyword ngxDirectiveThirdParty contained passenger_python
syn keyword ngxDirectiveThirdParty contained passenger_read_timeout
syn keyword ngxDirectiveThirdParty contained passenger_request_buffering
syn keyword ngxDirectiveThirdParty contained passenger_request_queue_overflow_status_code
syn keyword ngxDirectiveThirdParty contained passenger_resist_deployment_errors
syn keyword ngxDirectiveThirdParty contained passenger_response_buffer_high_watermark
syn keyword ngxDirectiveThirdParty contained passenger_restart_dir
syn keyword ngxDirectiveThirdParty contained passenger_rolling_restarts
syn keyword ngxDirectiveThirdParty contained passenger_root
syn keyword ngxDirectiveThirdParty contained passenger_ruby
syn keyword ngxDirectiveThirdParty contained passenger_security_update_check_proxy
syn keyword ngxDirectiveThirdParty contained passenger_set_header
syn keyword ngxDirectiveThirdParty contained passenger_show_version_in_header
syn keyword ngxDirectiveThirdParty contained passenger_socket_backlog
syn keyword ngxDirectiveThirdParty contained passenger_spawn_dir
syn keyword ngxDirectiveThirdParty contained passenger_spawn_exception_status_code
syn keyword ngxDirectiveThirdParty contained passenger_spawn_method
syn keyword ngxDirectiveThirdParty contained passenger_start_timeout
syn keyword ngxDirectiveThirdParty contained passenger_startup_file
syn keyword ngxDirectiveThirdParty contained passenger_stat_throttle_rate
syn keyword ngxDirectiveThirdParty contained passenger_sticky_sessions
syn keyword ngxDirectiveThirdParty contained passenger_sticky_sessions_cookie_attributes
syn keyword ngxDirectiveThirdParty contained passenger_sticky_sessions_cookie_name
syn keyword ngxDirectiveThirdParty contained passenger_temp_path
syn keyword ngxDirectiveThirdParty contained passenger_thread_count
syn keyword ngxDirectiveThirdParty contained passenger_turbocaching
syn keyword ngxDirectiveThirdParty contained passenger_use_global_queue
syn keyword ngxDirectiveThirdParty contained passenger_user
syn keyword ngxDirectiveThirdParty contained passenger_user_switching
syn keyword ngxDirectiveThirdParty contained passenger_vary_turbocache_by_cookie
syn keyword ngxDirectiveThirdParty contained rack_env
syn keyword ngxDirectiveThirdParty contained rails_app_spawner_idle_time
syn keyword ngxDirectiveThirdParty contained rails_env
syn keyword ngxDirectiveThirdParty contained rails_framework_spawner_idle_time
syn keyword ngxDirectiveThirdParty contained rails_spawn_method
syn keyword ngxDirectiveThirdParty contained union_station_filter
syn keyword ngxDirectiveThirdParty contained union_station_gateway_address
syn keyword ngxDirectiveThirdParty contained union_station_gateway_cert
syn keyword ngxDirectiveThirdParty contained union_station_gateway_port
syn keyword ngxDirectiveThirdParty contained union_station_key
syn keyword ngxDirectiveThirdParty contained union_station_proxy_address
syn keyword ngxDirectiveThirdParty contained union_station_support

" https://github.com/konstruxi/ngx_postgres
syn keyword ngxDirectiveThirdParty contained postgres_connect_timeout
syn keyword ngxDirectiveThirdParty contained postgres_escape
syn keyword ngxDirectiveThirdParty contained postgres_keepalive
syn keyword ngxDirectiveThirdParty contained postgres_output
syn keyword ngxDirectiveThirdParty contained postgres_pass
syn keyword ngxDirectiveThirdParty contained postgres_query
syn keyword ngxDirectiveThirdParty contained postgres_result_timeout
syn keyword ngxDirectiveThirdParty contained postgres_rewrite
syn keyword ngxDirectiveThirdParty contained postgres_server
syn keyword ngxDirectiveThirdParty contained postgres_set

" https://github.com/openresty/rds-csv-nginx-module
syn keyword ngxDirectiveThirdParty contained rds_csv
syn keyword ngxDirectiveThirdParty contained rds_csv_buffer_size
syn keyword ngxDirectiveThirdParty contained rds_csv_content_type
syn keyword ngxDirectiveThirdParty contained rds_csv_field_name_header
syn keyword ngxDirectiveThirdParty contained rds_csv_field_separator
syn keyword ngxDirectiveThirdParty contained rds_csv_row_terminator

" https://github.com/openresty/rds-json-nginx-module
syn keyword ngxDirectiveThirdParty contained rds_json
syn keyword ngxDirectiveThirdParty contained rds_json_buffer_size
syn keyword ngxDirectiveThirdParty contained rds_json_content_type
syn keyword ngxDirectiveThirdParty contained rds_json_errcode_key
syn keyword ngxDirectiveThirdParty contained rds_json_errstr_key
syn keyword ngxDirectiveThirdParty contained rds_json_format
syn keyword ngxDirectiveThirdParty contained rds_json_ret
syn keyword ngxDirectiveThirdParty contained rds_json_root
syn keyword ngxDirectiveThirdParty contained rds_json_success_property
syn keyword ngxDirectiveThirdParty contained rds_json_user_property

" https://github.com/openresty/redis2-nginx-module
syn keyword ngxDirectiveThirdParty contained redis2_bind
syn keyword ngxDirectiveThirdParty contained redis2_buffer_size
syn keyword ngxDirectiveThirdParty contained redis2_connect_timeout
syn keyword ngxDirectiveThirdParty contained redis2_literal_raw_query
syn keyword ngxDirectiveThirdParty contained redis2_next_upstream
syn keyword ngxDirectiveThirdParty contained redis2_pass
syn keyword ngxDirectiveThirdParty contained redis2_query
syn keyword ngxDirectiveThirdParty contained redis2_raw_queries
syn keyword ngxDirectiveThirdParty contained redis2_raw_query
syn keyword ngxDirectiveThirdParty contained redis2_read_timeout
syn keyword ngxDirectiveThirdParty contained redis2_send_timeout

" https://github.com/arut/nginx-rtmp-module
syn keyword ngxDirectiveThirdParty contained ack_window
syn keyword ngxDirectiveThirdParty contained application
syn keyword ngxDirectiveThirdParty contained buffer
syn keyword ngxDirectiveThirdParty contained buflen
syn keyword ngxDirectiveThirdParty contained busy
syn keyword ngxDirectiveThirdParty contained chunk_size
syn keyword ngxDirectiveThirdParty contained dash
syn keyword ngxDirectiveThirdParty contained dash_cleanup
syn keyword ngxDirectiveThirdParty contained dash_fragment
syn keyword ngxDirectiveThirdParty contained dash_nested
syn keyword ngxDirectiveThirdParty contained dash_path
syn keyword ngxDirectiveThirdParty contained dash_playlist_length
syn keyword ngxDirectiveThirdParty contained drop_idle_publisher
syn keyword ngxDirectiveThirdParty contained exec
syn keyword ngxDirectiveThirdParty contained exec_block
syn keyword ngxDirectiveThirdParty contained exec_kill_signal
syn keyword ngxDirectiveThirdParty contained exec_options
syn keyword ngxDirectiveThirdParty contained exec_play
syn keyword ngxDirectiveThirdParty contained exec_play_done
syn keyword ngxDirectiveThirdParty contained exec_publish
syn keyword ngxDirectiveThirdParty contained exec_publish_done
syn keyword ngxDirectiveThirdParty contained exec_pull
syn keyword ngxDirectiveThirdParty contained exec_push
syn keyword ngxDirectiveThirdParty contained exec_record_done
syn keyword ngxDirectiveThirdParty contained exec_static
syn keyword ngxDirectiveThirdParty contained hls_audio_buffer_size
syn keyword ngxDirectiveThirdParty contained hls_base_url
syn keyword ngxDirectiveThirdParty contained hls_cleanup
syn keyword ngxDirectiveThirdParty contained hls_continuous
syn keyword ngxDirectiveThirdParty contained hls_fragment_naming
syn keyword ngxDirectiveThirdParty contained hls_fragment_naming_granularity
syn keyword ngxDirectiveThirdParty contained hls_fragment_slicing
syn keyword ngxDirectiveThirdParty contained hls_fragments_per_key
syn keyword ngxDirectiveThirdParty contained hls_key_path
syn keyword ngxDirectiveThirdParty contained hls_key_url
syn keyword ngxDirectiveThirdParty contained hls_keys
syn keyword ngxDirectiveThirdParty contained hls_max_audio_delay
syn keyword ngxDirectiveThirdParty contained hls_max_fragment
syn keyword ngxDirectiveThirdParty contained hls_muxdelay
syn keyword ngxDirectiveThirdParty contained hls_nested
syn keyword ngxDirectiveThirdParty contained hls_path
syn keyword ngxDirectiveThirdParty contained hls_playlist_length
syn keyword ngxDirectiveThirdParty contained hls_sync
syn keyword ngxDirectiveThirdParty contained hls_type
syn keyword ngxDirectiveThirdParty contained hls_variant
syn keyword ngxDirectiveThirdParty contained idle_streams
syn keyword ngxDirectiveThirdParty contained interleave
syn keyword ngxDirectiveThirdParty contained live
syn keyword ngxDirectiveThirdParty contained max_connections
syn keyword ngxDirectiveThirdParty contained max_message
syn keyword ngxDirectiveThirdParty contained max_streams
syn keyword ngxDirectiveThirdParty contained meta
syn keyword ngxDirectiveThirdParty contained netcall_buffer
syn keyword ngxDirectiveThirdParty contained netcall_timeout
syn keyword ngxDirectiveThirdParty contained notify_method
syn keyword ngxDirectiveThirdParty contained notify_relay_redirect
syn keyword ngxDirectiveThirdParty contained notify_update_strict
syn keyword ngxDirectiveThirdParty contained notify_update_timeout
syn keyword ngxDirectiveThirdParty contained on_connect
syn keyword ngxDirectiveThirdParty contained on_disconnect
syn keyword ngxDirectiveThirdParty contained on_done
syn keyword ngxDirectiveThirdParty contained on_play
syn keyword ngxDirectiveThirdParty contained on_play_done
syn keyword ngxDirectiveThirdParty contained on_publish
syn keyword ngxDirectiveThirdParty contained on_publish_done
syn keyword ngxDirectiveThirdParty contained on_record_done
syn keyword ngxDirectiveThirdParty contained on_update
syn keyword ngxDirectiveThirdParty contained out_cork
syn keyword ngxDirectiveThirdParty contained out_queue
syn keyword ngxDirectiveThirdParty contained ping
syn keyword ngxDirectiveThirdParty contained ping_timeout
syn keyword ngxDirectiveThirdParty contained play
syn keyword ngxDirectiveThirdParty contained play_local_path
syn keyword ngxDirectiveThirdParty contained play_restart
syn keyword ngxDirectiveThirdParty contained play_temp_path
syn keyword ngxDirectiveThirdParty contained play_time_fix
syn keyword ngxDirectiveThirdParty contained publish_notify
syn keyword ngxDirectiveThirdParty contained publish_time_fix
syn keyword ngxDirectiveThirdParty contained pull
syn keyword ngxDirectiveThirdParty contained pull_reconnect
syn keyword ngxDirectiveThirdParty contained push
syn keyword ngxDirectiveThirdParty contained push_reconnect
syn keyword ngxDirectiveThirdParty contained record
syn keyword ngxDirectiveThirdParty contained record_append
syn keyword ngxDirectiveThirdParty contained record_interval
syn keyword ngxDirectiveThirdParty contained record_lock
syn keyword ngxDirectiveThirdParty contained record_max_frames
syn keyword ngxDirectiveThirdParty contained record_max_size
syn keyword ngxDirectiveThirdParty contained record_notify
syn keyword ngxDirectiveThirdParty contained record_path
syn keyword ngxDirectiveThirdParty contained record_suffix
syn keyword ngxDirectiveThirdParty contained record_unique
syn keyword ngxDirectiveThirdParty contained recorder
syn keyword ngxDirectiveThirdParty contained relay_buffer
syn keyword ngxDirectiveThirdParty contained respawn
syn keyword ngxDirectiveThirdParty contained respawn_timeout
syn keyword ngxDirectiveThirdParty contained rtmp
syn keyword ngxDirectiveThirdParty contained rtmp_auto_push
syn keyword ngxDirectiveThirdParty contained rtmp_auto_push_reconnect
syn keyword ngxDirectiveThirdParty contained rtmp_control
syn keyword ngxDirectiveThirdParty contained rtmp_socket_dir
syn keyword ngxDirectiveThirdParty contained rtmp_stat
syn keyword ngxDirectiveThirdParty contained rtmp_stat_stylesheet
syn keyword ngxDirectiveThirdParty contained session_relay
syn keyword ngxDirectiveThirdParty contained so_keepalive
syn keyword ngxDirectiveThirdParty contained stream_buckets
syn keyword ngxDirectiveThirdParty contained sync
syn keyword ngxDirectiveThirdParty contained wait_key
syn keyword ngxDirectiveThirdParty contained wait_video

" https://github.com/openresty/set-misc-nginx-module
syn keyword ngxDirectiveThirdParty contained set_base32_alphabet
syn keyword ngxDirectiveThirdParty contained set_base32_padding
syn keyword ngxDirectiveThirdParty contained set_decode_base32
syn keyword ngxDirectiveThirdParty contained set_decode_base64
syn keyword ngxDirectiveThirdParty contained set_decode_base64url
syn keyword ngxDirectiveThirdParty contained set_decode_hex
syn keyword ngxDirectiveThirdParty contained set_encode_base32
syn keyword ngxDirectiveThirdParty contained set_encode_base64
syn keyword ngxDirectiveThirdParty contained set_encode_base64url
syn keyword ngxDirectiveThirdParty contained set_encode_hex
syn keyword ngxDirectiveThirdParty contained set_escape_uri
syn keyword ngxDirectiveThirdParty contained set_formatted_gmt_time
syn keyword ngxDirectiveThirdParty contained set_formatted_local_time
syn keyword ngxDirectiveThirdParty contained set_hashed_upstream
syn keyword ngxDirectiveThirdParty contained set_hmac_sha1
syn keyword ngxDirectiveThirdParty contained set_hmac_sha256
syn keyword ngxDirectiveThirdParty contained set_if_empty
syn keyword ngxDirectiveThirdParty contained set_local_today
syn keyword ngxDirectiveThirdParty contained set_md5
syn keyword ngxDirectiveThirdParty contained set_misc_base32_padding
syn keyword ngxDirectiveThirdParty contained set_quote_json_str
syn keyword ngxDirectiveThirdParty contained set_quote_pgsql_str
syn keyword ngxDirectiveThirdParty contained set_quote_sql_str
syn keyword ngxDirectiveThirdParty contained set_random
syn keyword ngxDirectiveThirdParty contained set_rotate
syn keyword ngxDirectiveThirdParty contained set_secure_random_alphanum
syn keyword ngxDirectiveThirdParty contained set_secure_random_lcalpha
syn keyword ngxDirectiveThirdParty contained set_sha1
syn keyword ngxDirectiveThirdParty contained set_unescape_uri

" https://github.com/sflow/nginx-sflow-module
syn keyword ngxDirectiveThirdParty contained sflow

" https://github.com/nginx-shib/nginx-http-shibboleth
syn keyword ngxDirectiveThirdParty contained shib_request
syn keyword ngxDirectiveThirdParty contained shib_request_set
syn keyword ngxDirectiveThirdParty contained shib_request_use_headers

" https://github.com/baysao/ngx_slowfs_cache
syn keyword ngxDirectiveThirdParty contained slowfs_big_file_size
syn keyword ngxDirectiveThirdParty contained slowfs_cache
syn keyword ngxDirectiveThirdParty contained slowfs_cache_key
syn keyword ngxDirectiveThirdParty contained slowfs_cache_min_uses
syn keyword ngxDirectiveThirdParty contained slowfs_cache_path
syn keyword ngxDirectiveThirdParty contained slowfs_cache_purge
syn keyword ngxDirectiveThirdParty contained slowfs_cache_valid
syn keyword ngxDirectiveThirdParty contained slowfs_temp_path

" https://github.com/kawakibi/ngx_small_light
syn keyword ngxDirectiveThirdParty contained small_light
syn keyword ngxDirectiveThirdParty contained small_light_buffer
syn keyword ngxDirectiveThirdParty contained small_light_getparam_mode
syn keyword ngxDirectiveThirdParty contained small_light_imlib2_temp_dir
syn keyword ngxDirectiveThirdParty contained small_light_material_dir
syn keyword ngxDirectiveThirdParty contained small_light_pattern_define
syn keyword ngxDirectiveThirdParty contained small_light_radius_max
syn keyword ngxDirectiveThirdParty contained small_light_sigma_max

" https://github.com/openresty/srcache-nginx-module
syn keyword ngxDirectiveThirdParty contained srcache_buffer
syn keyword ngxDirectiveThirdParty contained srcache_default_expire
syn keyword ngxDirectiveThirdParty contained srcache_fetch
syn keyword ngxDirectiveThirdParty contained srcache_fetch_skip
syn keyword ngxDirectiveThirdParty contained srcache_header_buffer_size
syn keyword ngxDirectiveThirdParty contained srcache_ignore_content_encoding
syn keyword ngxDirectiveThirdParty contained srcache_max_expire
syn keyword ngxDirectiveThirdParty contained srcache_methods
syn keyword ngxDirectiveThirdParty contained srcache_request_cache_control
syn keyword ngxDirectiveThirdParty contained srcache_response_cache_control
syn keyword ngxDirectiveThirdParty contained srcache_store
syn keyword ngxDirectiveThirdParty contained srcache_store_hide_header
syn keyword ngxDirectiveThirdParty contained srcache_store_max_size
syn keyword ngxDirectiveThirdParty contained srcache_store_no_cache
syn keyword ngxDirectiveThirdParty contained srcache_store_no_store
syn keyword ngxDirectiveThirdParty contained srcache_store_pass_header
syn keyword ngxDirectiveThirdParty contained srcache_store_private
syn keyword ngxDirectiveThirdParty contained srcache_store_ranges
syn keyword ngxDirectiveThirdParty contained srcache_store_skip
syn keyword ngxDirectiveThirdParty contained srcache_store_statuses

" https://github.com/kaltura/nginx-vod-module
syn keyword ngxDirectiveThirdParty contained vod
syn keyword ngxDirectiveThirdParty contained vod_align_segments_to_key_frames
syn keyword ngxDirectiveThirdParty contained vod_apply_dynamic_mapping
syn keyword ngxDirectiveThirdParty contained vod_base_url
syn keyword ngxDirectiveThirdParty contained vod_bootstrap_segment_durations
syn keyword ngxDirectiveThirdParty contained vod_cache_buffer_size
syn keyword ngxDirectiveThirdParty contained vod_clip_from_param_name
syn keyword ngxDirectiveThirdParty contained vod_clip_to_param_name
syn keyword ngxDirectiveThirdParty contained vod_drm_clear_lead_segment_count
syn keyword ngxDirectiveThirdParty contained vod_drm_enabled
syn keyword ngxDirectiveThirdParty contained vod_drm_info_cache
syn keyword ngxDirectiveThirdParty contained vod_drm_max_info_length
syn keyword ngxDirectiveThirdParty contained vod_drm_request_uri
syn keyword ngxDirectiveThirdParty contained vod_drm_single_key
syn keyword ngxDirectiveThirdParty contained vod_drm_upstream_location
syn keyword ngxDirectiveThirdParty contained vod_dynamic_clip_map_uri
syn keyword ngxDirectiveThirdParty contained vod_dynamic_mapping_cache
syn keyword ngxDirectiveThirdParty contained vod_encryption_iv_seed
syn keyword ngxDirectiveThirdParty contained vod_expires
syn keyword ngxDirectiveThirdParty contained vod_expires_live
syn keyword ngxDirectiveThirdParty contained vod_expires_live_time_dependent
syn keyword ngxDirectiveThirdParty contained vod_fallback_upstream_location
syn keyword ngxDirectiveThirdParty contained vod_force_continuous_timestamps
syn keyword ngxDirectiveThirdParty contained vod_force_playlist_type_vod
syn keyword ngxDirectiveThirdParty contained vod_force_sequence_index
syn keyword ngxDirectiveThirdParty contained vod_gop_look_ahead
syn keyword ngxDirectiveThirdParty contained vod_gop_look_behind
syn keyword ngxDirectiveThirdParty contained vod_ignore_edit_list
syn keyword ngxDirectiveThirdParty contained vod_initial_read_size
syn keyword ngxDirectiveThirdParty contained vod_lang_param_name
syn keyword ngxDirectiveThirdParty contained vod_last_modified
syn keyword ngxDirectiveThirdParty contained vod_last_modified_types
syn keyword ngxDirectiveThirdParty contained vod_live_mapping_cache
syn keyword ngxDirectiveThirdParty contained vod_live_response_cache
syn keyword ngxDirectiveThirdParty contained vod_live_window_duration
syn keyword ngxDirectiveThirdParty contained vod_manifest_duration_policy
syn keyword ngxDirectiveThirdParty contained vod_manifest_segment_durations_mode
syn keyword ngxDirectiveThirdParty contained vod_mapping_cache
syn keyword ngxDirectiveThirdParty contained vod_max_frame_count
syn keyword ngxDirectiveThirdParty contained vod_max_frames_size
syn keyword ngxDirectiveThirdParty contained vod_max_mapping_response_size
syn keyword ngxDirectiveThirdParty contained vod_max_metadata_size
syn keyword ngxDirectiveThirdParty contained vod_max_upstream_headers_size
syn keyword ngxDirectiveThirdParty contained vod_media_set_map_uri
syn keyword ngxDirectiveThirdParty contained vod_media_set_override_json
syn keyword ngxDirectiveThirdParty contained vod_metadata_cache
syn keyword ngxDirectiveThirdParty contained vod_min_single_nalu_per_frame_segment
syn keyword ngxDirectiveThirdParty contained vod_mode
syn keyword ngxDirectiveThirdParty contained vod_multi_uri_suffix
syn keyword ngxDirectiveThirdParty contained vod_notification_uri
syn keyword ngxDirectiveThirdParty contained vod_open_file_thread_pool
syn keyword ngxDirectiveThirdParty contained vod_output_buffer_pool
syn keyword ngxDirectiveThirdParty contained vod_parse_hdlr_name
syn keyword ngxDirectiveThirdParty contained vod_parse_udta_name
syn keyword ngxDirectiveThirdParty contained vod_path_response_postfix
syn keyword ngxDirectiveThirdParty contained vod_path_response_prefix
syn keyword ngxDirectiveThirdParty contained vod_performance_counters
syn keyword ngxDirectiveThirdParty contained vod_proxy_header_name
syn keyword ngxDirectiveThirdParty contained vod_proxy_header_value
syn keyword ngxDirectiveThirdParty contained vod_redirect_segments_url
syn keyword ngxDirectiveThirdParty contained vod_remote_upstream_location
syn keyword ngxDirectiveThirdParty contained vod_response_cache
syn keyword ngxDirectiveThirdParty contained vod_secret_key
syn keyword ngxDirectiveThirdParty contained vod_segment_count_policy
syn keyword ngxDirectiveThirdParty contained vod_segment_duration
syn keyword ngxDirectiveThirdParty contained vod_segment_max_frame_count
syn keyword ngxDirectiveThirdParty contained vod_segments_base_url
syn keyword ngxDirectiveThirdParty contained vod_source_clip_map_uri
syn keyword ngxDirectiveThirdParty contained vod_speed_param_name
syn keyword ngxDirectiveThirdParty contained vod_status
syn keyword ngxDirectiveThirdParty contained vod_time_shift_param_name
syn keyword ngxDirectiveThirdParty contained vod_tracks_param_name
syn keyword ngxDirectiveThirdParty contained vod_upstream_extra_args
syn keyword ngxDirectiveThirdParty contained vod_upstream_location

" https://github.com/vozlt/nginx-module-vts
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_average_method
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_bypass_limit
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_bypass_stats
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display_format
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display_jsonp
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display_sum_key
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_dump
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_by_host
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_by_set_key
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_check_duplicate
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_max_node
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_histogram_buckets
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_check_duplicate
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_traffic
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_traffic_by_set_key
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_set_by_filter
syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_zone

" https://github.com/openresty/xss-nginx-module
syn keyword ngxDirectiveThirdParty contained xss_callback_arg
syn keyword ngxDirectiveThirdParty contained xss_check_status
syn keyword ngxDirectiveThirdParty contained xss_get
syn keyword ngxDirectiveThirdParty contained xss_input_types
syn keyword ngxDirectiveThirdParty contained xss_output_type
syn keyword ngxDirectiveThirdParty contained xss_override_status

" https://github.com/tg123/websockify-nginx-module
syn keyword ngxDirectiveThirdParty contained websockify_buffer_size
syn keyword ngxDirectiveThirdParty contained websockify_connect_timeout
syn keyword ngxDirectiveThirdParty contained websockify_pass
syn keyword ngxDirectiveThirdParty contained websockify_read_timeout
syn keyword ngxDirectiveThirdParty contained websockify_send_timeout

" highlight

hi def link ngxComment Comment
hi def link ngxParamComment Comment
hi def link ngxListenComment Comment
hi def link ngxVariable Identifier
hi def link ngxVariableString PreProc
hi def link ngxString String
hi def link ngxListenString String

hi def link ngxBoolean Boolean
hi def link ngxDirectiveBlock Statement
hi def link ngxDirectiveImportant Type
hi def link ngxDirectiveListen Type
hi def link ngxDirectiveControl Keyword
hi def link ngxDirectiveError Constant
hi def link ngxDirectiveDeprecated Error
hi def link ngxDirective Identifier
hi def link ngxDirectiveThirdParty Special
hi def link ngxDirectiveThirdPartyDeprecated Error

hi def link ngxListenOptions Keyword
hi def link ngxListenOptionsDeprecated Error

let &cpo = s:save_cpo
unlet s:save_cpo

let b:current_syntax = "nginx"
