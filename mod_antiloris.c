/*
   mod_antiloris 0.2
   Copyright (C) 2008 Monshouwer Internet Diensten

   Author: Kees Monshouwer

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include "scoreboard.h"

#define MODULE_NAME "mod_antiloris"
#define MODULE_VERSION "0.4"

module AP_MODULE_DECLARE_DATA antiloris_module;

static int server_limit, thread_limit;

#define antiloris_MAX_PER_IP	5

typedef struct
{
    signed int limit;
} antiloris_config;

typedef struct {
    int child_num;
    int thread_num;
} sb_handle;


/* Create per-server configuration structure */
static void *create_config(apr_pool_t *p, server_rec *s)
{
    antiloris_config *conf = apr_pcalloc(p, sizeof (*conf));

    conf->limit = antiloris_MAX_PER_IP;
    return conf;
}
                                                       

/* Parse the IPReadLimit directive */
static const char *ipreadlimit_config_cmd(cmd_parms *parms, void *mconfig, const char *arg)
{
    antiloris_config *conf = ap_get_module_config(parms->server->module_config, &antiloris_module);
    const char *err = ap_check_cmd_context (parms, GLOBAL_ONLY);
    
    if (err != NULL) {
	return err;
    }
    
    signed long int limit = strtol(arg, (char **) NULL, 10);

    /* No reasonable person would want more than 2^16. Better would be
       to use LONG_MAX but that causes portability problems on win32 */
    if ((limit > 65535) || (limit < 0)) {
        return "Integer overflow or invalid number";
    }

    conf->limit = limit;
    return NULL;
}


/* Array describing structure of configuration directives */
static command_rec antiloris_cmds[] = {
    AP_INIT_TAKE1("IPReadLimit", ipreadlimit_config_cmd, NULL, RSRC_CONF, "Maximum simultaneous connections in READ state per IP address"),
    {NULL}
};


/* Set up startup-time initialization */
static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    void *data;
    const char *userdata_key = "antiloris_init";
    
    /* initialize_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
	apr_pool_userdata_set((const void *)1, userdata_key,apr_pool_cleanup_null, s->process->pool);
	return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, MODULE_NAME " " MODULE_VERSION " started");
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    return OK;
}


static int pre_connection(conn_rec *c)
{
    antiloris_config *conf = ap_get_module_config (c->base_server->module_config,  &antiloris_module);
    sb_handle *sbh = c->sbh;
    
    /* loop index variables */
    int i;
    int j;
    
    /* running count of number of connections from this address */
    int ip_count = 0;
    
    /* scoreboard data structure */
    worker_score *ws_record;
    
    ws_record = &ap_scoreboard_image->servers[sbh->child_num][sbh->thread_num];
    apr_cpystrn(ws_record->client, c->remote_ip, sizeof(ws_record->client));
    
    char *client_ip = ws_record->client;
    
    /* Count up the number of connections we are handling right now from this IP address */
    for (i = 0; i < server_limit; ++i) {
	for (j = 0; j < thread_limit; ++j) {
    	    ws_record = ap_get_scoreboard_worker(i, j);
            switch (ws_record->status) {
        	case SERVER_BUSY_READ:
            	    if (strcmp(client_ip, ws_record->client) == 0)
            		ip_count++;
                    break;
                default:
            	    break;
            }
        }
    }
    
    if (ip_count > conf->limit) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "Rejected, too many connections in READ state from %s", c->remote_ip);
	return OK;
    } else {
	return DECLINED;
    }
}


static void child_init (apr_pool_t *p, server_rec *s)
{
    ap_add_version_component(p, MODULE_NAME "/" MODULE_VERSION);
}


static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_process_connection(pre_connection, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);    
}

module AP_MODULE_DECLARE_DATA antiloris_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-dir config structures */
    NULL,			/* merge  per-dir    config structures */
    create_config,		/* create per-server config structures */
    NULL,			/* merge  per-server config structures */
    antiloris_cmds,		/* table of config file commands       */
    register_hooks
};
