
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_command_t  ngx_imap_commands[] = {

    { ngx_string("imap"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_imap_block,
      0,
      0,
      NULL },

      ngx_null_command
};

    
static ngx_core_module_t  ngx_imap_module_ctx = {
    ngx_string("imap"),
    NULL,
    NULL
};  


ngx_module_t  ngx_imap_module = {
    NGX_MODULE, 
    &ngx_imap_module_ctx,                  /* module context */
    ngx_imap_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};
