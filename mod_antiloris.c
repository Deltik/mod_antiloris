/*
   mod_antiloris 0.6.0
   Copyright (C) 2008-2010 Monshouwer Internet Diensten

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

   This file is a Derivative Work with changes from the following contributors:

   - NewEraCracker
   - diovoemor
   - Deltik
*/

/*
   Installation:

   apxs -a -i -l cap -c mod_antiloris.c
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
#define MODULE_VERSION "0.6.0"
#define ANTILORIS_DEFAULT_MAX_CONN_PER_TYPE 10

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(antiloris);
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
#define remote_ip client_ip
#endif

module AP_MODULE_DECLARE_DATA antiloris_module;

static int server_limit, thread_limit;

typedef struct {
	/* IP Connection Limits */
	signed long int read_limit;
	signed long int write_limit;
	signed long int other_limit;

	/* Local IP Addresses */
	apr_array_header_t *local_ips;
} antiloris_config;

typedef struct {
	int child_num;
	int thread_num;
} sb_handle;

/** Create per-server configuration structure */
static void *create_config(apr_pool_t *p, server_rec *s)
{
	antiloris_config *conf = apr_pcalloc(p, sizeof (*conf));

	conf->read_limit  = ANTILORIS_DEFAULT_MAX_CONN_PER_TYPE;
	conf->write_limit = ANTILORIS_DEFAULT_MAX_CONN_PER_TYPE;
	conf->other_limit = ANTILORIS_DEFAULT_MAX_CONN_PER_TYPE;
	conf->local_ips   = apr_array_make(p, 0, sizeof(char *));

	return conf;
}

/** Parse IPReadLimit directive */
static const char *ip_read_limit_config_cmd(cmd_parms *parms, void *mconfig, const char *arg)
{
	signed long int limit;

	antiloris_config *conf = ap_get_module_config(parms->server->module_config, &antiloris_module);
	const char *err = ap_check_cmd_context (parms, GLOBAL_ONLY);

	if (!err) {
		limit = strtol(arg, (char **) NULL, 10);

		/* No reasonable person would want more than 2^16. Better would be
		   to use LONG_MAX but that causes portability problems on win32 */
		if (limit > 65535) { return "Limit can't be higher than 65535"; }
		if (limit < 0)     { return "Limit can't be lower than zero"; }

		conf->read_limit = limit;
	}

	return err;
}

/** Parse IPWriteLimit directive */
static const char *ip_write_limit_config_cmd(cmd_parms *parms, void *mconfig, const char *arg)
{
	signed long int limit;

	antiloris_config *conf = ap_get_module_config(parms->server->module_config, &antiloris_module);
	const char *err = ap_check_cmd_context (parms, GLOBAL_ONLY);

	if (!err) {
		limit = strtol(arg, (char **) NULL, 10);

		/* No reasonable person would want more than 2^16. Better would be
		   to use LONG_MAX but that causes portability problems on win32 */
		if (limit > 65535) { return "Limit can't be higher than 65535"; }
		if (limit < 0)     { return "Limit can't be lower than zero"; }

		conf->write_limit = limit;
	}

	return err;
}

/** Parse IPOtherLimit directive */
static const char *ip_other_limit_config_cmd(cmd_parms *parms, void *mconfig, const char *arg)
{
	signed long int limit;

	antiloris_config *conf = ap_get_module_config(parms->server->module_config, &antiloris_module);
	const char *err = ap_check_cmd_context (parms, GLOBAL_ONLY);

	if (!err) {
		limit = strtol(arg, (char **) NULL, 10);

		/* No reasonable person would want more than 2^16. Better would be
		   to use LONG_MAX but that causes portability problems on win32 */
		if (limit > 65535) { return "Limit can't be higher than 65535"; }
		if (limit < 0)     { return "Limit can't be lower than zero"; }

		conf->other_limit = limit;
	}

	return err;
}

/** Parse LocalIPs directive */
static const char *local_ips_config_cmd(cmd_parms *parms, void *mconfig, const char *arg)
{
	antiloris_config *conf = ap_get_module_config(parms->server->module_config, &antiloris_module);

	*(char **) apr_array_push(conf->local_ips) = apr_pstrdup(parms->pool, arg);

	return NULL;
}

/** Configuration directives */
static command_rec antiloris_cmds[] = {
	AP_INIT_TAKE1("IPReadLimit",  ip_read_limit_config_cmd,  NULL, RSRC_CONF, "Maximum simultaneous connections in READ state per IP address"),
	AP_INIT_TAKE1("IPWriteLimit", ip_write_limit_config_cmd, NULL, RSRC_CONF, "Maximum simultaneous connections in WRITE state per IP address"),
	AP_INIT_TAKE1("IPOtherLimit", ip_other_limit_config_cmd, NULL, RSRC_CONF, "Maximum simultaneous idle connections per IP address"),
	AP_INIT_ITERATE("LocalIPs",   local_ips_config_cmd,      NULL, RSRC_CONF, "List of IPs (separated by spaces) whose connection are always allowed"),
	{NULL}
};

/** Startup-time initialization */
static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	void *data;
	const char *userdata_key = "antiloris_init";

	/* initialize_module() will be called twice, and if it's a DSO
	 * then all static data from the first call will be lost. Only
	 * set up our static data on the second call. */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (!data) {
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
	ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

	ap_add_version_component(p, MODULE_NAME "/" MODULE_VERSION);
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, MODULE_NAME " " MODULE_VERSION " started");

	return OK;
}

/** Our hook at connection processing */
static int pre_connection(conn_rec *c)
{
	/* Remote IP to be used in checking operations */
	char *remote_ip = c->remote_ip;

	/* loop index variables */
	int i = 0, j = 0;

	/* running count of number of connections from this address */
	signed long int ip_read_count = 0, ip_write_count = 0, ip_other_count = 0;

	/* other variables we'll be using */
	antiloris_config *conf = ap_get_module_config(c->base_server->module_config, &antiloris_module);
	sb_handle *sbh = c->sbh;

#if AP_MODULE_MAGIC_AT_LEAST(20110605,2)
	/* get the socket descriptor */
	apr_socket_t *csd = ap_get_conn_socket(c);
#endif

	/* scoreboard data structure */
	worker_score *ws_record;

	/* Save current remote ip in current ws_record */
	ws_record = &ap_scoreboard_image->servers[sbh->child_num][sbh->thread_num];
	apr_cpystrn(ws_record->client, remote_ip, sizeof(ws_record->client));

	/* Take local IPs in consideration */
	if(conf->local_ips->nelts) {
		char **ip = (char **) conf->local_ips->elts;
		for (i = 0; i < conf->local_ips->nelts; i++) {
#if AP_MODULE_MAGIC_AT_LEAST(20050101,0)
			ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "Performing IP check versus: \"%s\"", ip[i]);
#else
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "[client %s] Performing IP check versus: \"%s\"", remote_ip, ip[i]);
#endif
			if (ap_strcasecmp_match(remote_ip, ip[i]) == 0) {
#if AP_MODULE_MAGIC_AT_LEAST(20050101,0)
				ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "Exempted from connection limit");
#else
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "[client %s] Exempted from connection limit", remote_ip);
#endif
				/* Pass request to appropriate module */
				return DECLINED;
			}
		}
	}

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
					/* Handle read state if limit is higher than zero */
					if (conf->read_limit > 0 && strcmp(remote_ip, ws_record->client) == 0) ip_read_count++;
					break;
				case SERVER_BUSY_WRITE:
					/* Handle write state if limit is higher than zero */
					if (conf->write_limit > 0 && strcmp(remote_ip, ws_record->client) == 0) ip_write_count++;
					break;
				case SERVER_BUSY_KEEPALIVE:
					/* Handle keep-alive state if limit is higher than zero */
					if (conf->other_limit > 0 && strcmp(remote_ip, ws_record->client) == 0) ip_other_count++;
					break;
				case SERVER_BUSY_LOG:
				case SERVER_BUSY_DNS:
				case SERVER_CLOSING:
				case SERVER_GRACEFUL:
				default:
					/* Other states are ignored */
					break;
			}
		}
	}

	/* Deny the request if it exceeds limits */
	if (ip_read_count > conf->read_limit || ip_write_count > conf->write_limit || ip_other_count > conf->other_limit) {
#if AP_MODULE_MAGIC_AT_LEAST(20050101,0)
		ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c, "Connection rejected by Antiloris, too many connections");
#else
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "[client %s] Connection rejected by Antiloris, too many connections", remote_ip);
#endif
#if AP_MODULE_MAGIC_AT_LEAST(20110605,2)
		apr_socket_close(csd);
		return DONE;
#else
		return OK;
#endif
	}

	/* Pass request to appropriate module */
	return DECLINED;
}

/** Registration of our hooks */
static void register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_process_connection(pre_connection, NULL, NULL, APR_HOOK_FIRST);
}

/** Our module data */
module AP_MODULE_DECLARE_DATA antiloris_module = {
	STANDARD20_MODULE_STUFF,
	NULL,			/* create per-dir config structures */
	NULL,			/* merge  per-dir config structures */
	create_config,	/* create per-server config structures */
	NULL,			/* merge  per-server config structures */
	antiloris_cmds,	/* table of config file commands */
	register_hooks
};
