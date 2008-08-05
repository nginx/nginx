
// stub module to test header files' C++ compatibilty

extern "C" {
  #include <ngx_config.h>
  #include <ngx_core.h>
  #include <ngx_event.h>
  #include <ngx_event_connect.h>
  #include <ngx_event_pipe.h>

  #include <ngx_http.h>

  #include <ngx_mail.h>
  #include <ngx_mail_pop3_module.h>
  #include <ngx_mail_imap_module.h>
  #include <ngx_mail_smtp_module.h>
}

// nginx header files should go before other, because they define 64-bit off_t
// #include <string>


void
ngx_cpp_test_handler(void *data)
{
    return;
}
