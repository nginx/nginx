
/*
 *
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


struct ngx_quic_connection_s {
    ngx_str_t   scid;
    ngx_str_t   dcid;
    ngx_str_t   token;

    ngx_str_t   client_in;
    ngx_str_t   client_in_key;
    ngx_str_t   client_in_iv;
    ngx_str_t   client_in_hp;

    size_t      handshake_secret_len;
    uint8_t    *handshake_read_secret;
    uint8_t    *handshake_write_secret;

    size_t      application_secret_len;
    uint8_t    *application_read_secret;
    uint8_t    *application_write_secret;
};


#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
