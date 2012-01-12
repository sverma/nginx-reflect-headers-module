/* 
* Copyright: saurabh Verma
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pcre.h>

static char * ngx_http_reflect_headers (  ngx_conf_t  * cf, ngx_command_t *  cmd, void * conf) ; 
typedef struct { 
    ngx_str_t header;

} ngx_http_reflect_headers_loc_conf_t;


static ngx_command_t ngx_http_reflect_headers_commands[] = { 
    { 
        ngx_string("reflect_headers") , 
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_reflect_headers,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL,
    }, 

    { 
        ngx_string("header") , 
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, 
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_reflect_headers_loc_conf_t,header),
        NULL,
    }, 
    ngx_null_command
}; 


static void * ngx_http_reflect_headers_create_loc_conf ( ngx_conf_t *cf ) 
{
    ngx_http_reflect_headers_loc_conf_t     *conf;
    conf = ngx_pcalloc ( cf->pool , sizeof(ngx_http_reflect_headers_loc_conf_t) ) ; 
    if ( conf == NULL ) { 
        return NGX_CONF_ERROR; 
    }
//conf->header = NGX_CONF_UNSET; 
    return conf; 
} 

static char * ngx_http_reflect_headers_merge_loc_conf ( ngx_conf_t *cf , void *parent , void *child ) 
{
    //static u_char  header[] = "HostChanged"; 
    ngx_http_reflect_headers_loc_conf_t *prev = parent ; 
    ngx_http_reflect_headers_loc_conf_t *conf = child ; 
    //if (! prev->header ) { 
    //    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error : in prev->header");
    //    return NGX_CONF_ERROR;
    //}

    ngx_conf_merge_str_value(conf->header , prev->header , "TestString" ) ; 
    return NGX_CONF_OK; 
} 


static ngx_http_module_t ngx_http_reflect_headers_module_ctx =  { 
    NULL , 
    NULL , 
    NULL, 
    NULL, 
    NULL , 
    NULL, 
    ngx_http_reflect_headers_create_loc_conf , /* create location configuration */
    ngx_http_reflect_headers_merge_loc_conf, /*merge location configuration */
};
ngx_module_t ngx_http_reflect_headers_module = { 
    NGX_MODULE_V1, 
    &ngx_http_reflect_headers_module_ctx, 
    ngx_http_reflect_headers_commands,
    NGX_HTTP_MODULE,
    NULL, 
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_reflect_headers_handler (ngx_http_request_t *r) 
{
    ngx_http_reflect_headers_loc_conf_t *reflect_headers_config; 
    reflect_headers_config = ngx_http_get_module_loc_conf(r,ngx_http_reflect_headers_module); 

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Arguement to reflect_headers: %s : ", (u_char * ) (&reflect_headers_config->header)->data );

    ngx_table_elt_t * in_host; 
    in_host = r->headers_in.host; 
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Host header value: %s : ", (u_char *) (&in_host->value)->data );
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI String:%s: ", (u_char *) (&r->uri)->data );
// URI Matching 

    pcre *re ; 
    const char *err ; 
    int err_offset;
    int ovector[30]; 
    int rc,i;

    re = pcre_compile(
            "^/(.*)/",
            0,
            &err,
            &err_offset,
            NULL
            );
    if ( re == NULL ) { 
        ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"Error in compiling , failed at offset %d: %s :", err_offset , err)  ;
        return NGX_ERROR; 
    }

    rc = pcre_exec ( 
            re , 
            NULL , 
            (&r->uri)->data, 
            (int) strlen((&r->uri)->data), 
            0,
            0,
            ovector,
            30); 
    if ( rc < 0 ) { 
        switch(rc) { 
            case PCRE_ERROR_NOMATCH: ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"No match find for URI")  ; break;
            default: ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"Matching Error: %d " , rc ) ; break;
        }
    }

    ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"Match Succeeded" ) ; 

    
    for ( i = 0 ; i < rc ; i ++ ) { 
        u_char *substring_start = (&r->uri)->data + ovector[2*i];
        int substring_len =  ovector[2*i+1] - ovector[2*i];
        ngx_error_log(NGX_LOG_ERR , r->connection->log , 0 , "Matched pattern is %s :" , substring_start ) 
    } 

        
// URI Matching End 



// declare a buffer 
    ngx_buf_t *b ; 
    ngx_chain_t  out ; 
    ngx_int_t rc; 

    if ( ! ( r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED; 
    } 
// initialize buffer 

    b = ngx_pcalloc(r->pool , sizeof(ngx_buf_t) ) ; 

    if ( b == NULL ) { 
        ngx_log_error(NGX_LOG_ERR,r->connection->log , 0  , "Failed to create response buffer") ; 
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    } 

    static u_char test_str[] = "Hello World\n"; 
    b->pos = test_str; 
    b->last = test_str + sizeof(test_str) -1 ; 
    b->memory = 1 ; 
    b->last_buf = 1;
    /* set the status line */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = sizeof(test_str) -1 ; 
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf =b ; 
    out.next = NULL ; 
    return ngx_http_output_filter(r, &out);
}

static char * ngx_http_reflect_headers(ngx_conf_t *cf , ngx_command_t *cmd , void * conf ) 
{
    ngx_http_core_loc_conf_t *core_conf; 
    core_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_conf->handler = ngx_http_reflect_headers_handler; 
    return NGX_CONF_OK;
}


