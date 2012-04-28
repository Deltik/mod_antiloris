/*
   mod_antiloris 0.5.2
   Copyright (C) 2010 Monshouwer Internet Diensten

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
   
   Instalation:
   - /usr/apache/bin/apxs -a -i -l cap -c mod_antiloris.c
*/

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_connection.h"
#include "http_log.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "ap_release.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "scoreboard.h"

#define MODULE_NAME "mod_antiloris"
#define MODULE_VERSION "0.5.2"
#define ANTILORIS_DEFAULT_MAX_CONN 20

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(antiloris);
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
#define remote_ip client_ip
#endif

#ifndef INT_MAX
#define INT_MAX 32767
#endif

module AP_MODULE_DECLARE_DATA antiloris_module;

static int server_limit, thread_limit;

typedef struct {
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

	conf->limit = ANTILORIS_DEFAULT_MAX_CONN;
	return conf;
}

/* Parse the IPReadLimit directive */
static const char *ipreadlimit_config_cmd(cmd_parms *parms, void *mconfig, const char *arg)
{
	signed long int limit;

	antiloris_config *conf = ap_get_module_config(parms->server->module_config, &antiloris_module);
	const char *err = ap_check_cmd_context (parms, GLOBAL_ONLY);

	if (!err) {
		limit = strtol(arg, (char **) NULL, 10);

		if ((limit > INT_MAX) || (limit < 0))
			return "Integer overflow or invalid number";

		conf->limit = limit;
	}

	return err;
}

/* Array describing structure of configuration directives */
static command_rec antiloris_cmds[] = {
	AP_INIT_TAKE1("IPReadLimit", ipreadlimit_config_cmd, NULL, RSRC_CONF, "Maximum simultaneous connections per IP address"),
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

	ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
	ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

	ap_add_version_component(p, MODULE_NAME "/" MODULE_VERSION);
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, MODULE_NAME " " MODULE_VERSION " started");

	return OK;
}

static int pre_connection(conn_rec *c)
{
	char *remote_ip;

	antiloris_config *conf = ap_get_module_config(c->base_server->module_config, &antiloris_module);
	sb_handle *sbh = c->sbh;

	/* loop index variables */
	int i, j;

	/* running count of number of connections from this address */
	int ip_count = 0;

#if AP_MODULE_MAGIC_AT_LEAST(20071023,0)
	/* get the socket descriptor */
	apr_socket_t *csd = ap_get_conn_socket(c);
#endif

	/* scoreboard data structure */
	worker_score *ws_record;

	ws_record = &ap_scoreboard_image->servers[sbh->child_num][sbh->thread_num];
	apr_cpystrn(ws_record->client, c->remote_ip, sizeof(ws_record->client));

	remote_ip = ws_record->client;

	/* Count up the number of connections we are handling right now from this IP address */
	for (i = 0; i < server_limit; ++i) {
		for (j = 0; j < thread_limit; ++j) {
#if AP_MODULE_MAGIC_AT_LEAST(20071023,0)
			ws_record = ap_get_scoreboard_worker_from_indexes(i, j);
#else
			ws_record = ap_get_scoreboard_worker(i, j);
#endif
			switch (ws_record->status) {
				case SERVER_BUSY_READ:
				case SERVER_BUSY_WRITE:
				case SERVER_BUSY_KEEPALIVE:
				case SERVER_BUSY_DNS:
				case SERVER_BUSY_LOG:
					if (strcmp(remote_ip, ws_record->client) == 0)
					ip_count++;
					break;
				default:
					break;
			}
		}
	}

	if (ip_count > conf->limit) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "[client %s] Antiloris rejected, too many connections", c->remote_ip);
#if AP_MODULE_MAGIC_AT_LEAST(20071023,0)
		apr_socket_close(csd);
		return DONE;
#else
		return OK;
#endif
	}

	return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_process_connection(pre_connection, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA antiloris_module = {
	STANDARD20_MODULE_STUFF,
	NULL,			/* create per-dir config structures */
	NULL,			/* merge  per-dir config structures */
	create_config,	/* create per-server config structures */
	NULL,			/* merge  per-server config structures */
	antiloris_cmds,	/* table of config file commands */
	register_hooks
};
