/*
   mod_antiloris 0.7.0
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

   This file is a Derivative Work with changes from the following Contributors:

   - NewEraCracker
   - diovoemor
   - Deltik
*/

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_connection.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "scoreboard.h"
#include "ip_helper.h"
#include <stdlib.h>

#define MODULE_NAME "mod_antiloris"
#define MODULE_VERSION "0.7.0"
#define ANTILORIS_DEFAULT_MAX_CONN_TOTAL 30
#define ANTILORIS_DEFAULT_MAX_CONN_READ 10
#define ANTILORIS_DEFAULT_MAX_CONN_WRITE 10
#define ANTILORIS_DEFAULT_MAX_CONN_OTHER 10

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(antiloris);
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20111130, 0)
#define remote_ip client_ip
#endif

#define READ_COUNT_INDEX 0
#define WRITE_COUNT_INDEX 1
#define OTHER_COUNT_INDEX 2

module AP_MODULE_DECLARE_DATA
        antiloris_module;

static int server_limit, thread_limit;

typedef struct {
    /* IP Connection Limits */
    signed long int total_limit;
    signed long int read_limit;
    signed long int write_limit;
    signed long int other_limit;

    /* Whitelist IP Addresses */
    struct flexmap *ip_whitelist;
} antiloris_config;

typedef struct {
    int child_num;
    int thread_num;
} sb_handle;

/** Create per-server configuration structure */
static void *create_config(apr_pool_t *p, server_rec *s) {
    apr_pool = p;
    antiloris_config *conf = apr_pcalloc(p, sizeof(*conf));

    conf->total_limit = ANTILORIS_DEFAULT_MAX_CONN_TOTAL;
    conf->read_limit = ANTILORIS_DEFAULT_MAX_CONN_READ;
    conf->write_limit = ANTILORIS_DEFAULT_MAX_CONN_WRITE;
    conf->other_limit = ANTILORIS_DEFAULT_MAX_CONN_OTHER;
    conf->ip_whitelist = create_flexmap();

    return conf;
}

/**
 * Get module config from cmd_parms struct
 * @param cmd cmd_parms struct
 * @return antiloris_config struct
 */
static antiloris_config *_get_config(cmd_parms *cmd) {
    return ap_get_module_config(cmd->server->module_config, &antiloris_module);
}

/**
 * Set the value of the antiloris_config IP limit type
 * @param limit_type Pointer to the value of the IP limit type in struct antiloris_config
 * @param cmd Apache instance configuration data
 * @param value Directive value from configuration
 * @return Error message as a string, if there was an error
 */
static const char *_set_ip_limit_config_value(signed long int *limit_type, cmd_parms *cmd, const char *value) {
    signed long int limit;
    limit = strtol(value, (char **) NULL, 10);

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err) return err;

    /* No reasonable person would want more than 2^16. Better would be
       to use LONG_MAX but that causes portability problems on win32 */
    if (limit > 65535) { return "Limit can't be higher than 65535"; }
    if (limit < 0) { return "Limit can't be lower than 0"; }

    *limit_type = limit;

    return NULL;
}

/** Parse IPTotalLimit directive */
static const char *ip_total_limit_config_cmd(cmd_parms *parms, void *_mconfig, const char *arg) {
    return _set_ip_limit_config_value(&_get_config(parms)->total_limit, parms, arg);
}

/** Parse IPReadLimit directive */
static const char *ip_read_limit_config_cmd(cmd_parms *parms, void *_mconfig, const char *arg) {
    return _set_ip_limit_config_value(&_get_config(parms)->read_limit, parms, arg);
}

/** Parse IPWriteLimit directive */
static const char *ip_write_limit_config_cmd(cmd_parms *parms, void *_mconfig, const char *arg) {
    return _set_ip_limit_config_value(&_get_config(parms)->write_limit, parms, arg);
}

/** Parse IPOtherLimit directive */
static const char *ip_other_limit_config_cmd(cmd_parms *parms, void *_mconfig, const char *arg) {
    return _set_ip_limit_config_value(&_get_config(parms)->other_limit, parms, arg);
}

/** Parse WhitelistIPs/LocalIPs directive */
static const char *whitelist_ips_config_cmd(cmd_parms *parms, void *_mconfig, const char *arg) {
    int rc;
    struct flexmap *whitelist = _get_config(parms)->ip_whitelist;
    char input_ips[strlen(arg) + 1];
    strcpy(input_ips, arg);
    char *input_ip = strtok(input_ips, " ");
    while (input_ip != NULL) {
        char * original_input_ip = strdup(input_ip);
        rc = whitelist_ip(whitelist, input_ip);
        if (rc != 0) {
            const int MAX_ERROR_STRING_LENGTH = 128;
            char error_string_buffer[MAX_ERROR_STRING_LENGTH];
            switch (rc) {
                case ANTILORIS_CONFIG_ERROR_IP_PARSE:
                    snprintf(error_string_buffer, MAX_ERROR_STRING_LENGTH,
                             "Cannot parse this as an IP address: %s", original_input_ip);
                    break;
                case ANTILORIS_CONFIG_ERROR_IP_CIDR:
                    snprintf(error_string_buffer, MAX_ERROR_STRING_LENGTH,
                             "Invalid CIDR provided: %s", original_input_ip);
                    break;
                case ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK:
                    snprintf(error_string_buffer, MAX_ERROR_STRING_LENGTH,
                             "IP address cannot have host bits in netmask: %s", original_input_ip);
                    break;
                case ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER:
                    snprintf(error_string_buffer, MAX_ERROR_STRING_LENGTH,
                             "Lower bound cannot be higher than upper bound in range: %s", original_input_ip);
                    break;
                default:
                    snprintf(error_string_buffer, MAX_ERROR_STRING_LENGTH,
                             "Unknown error (%d) parsing this IP address: %s", rc, original_input_ip);
            }
            return strdup(error_string_buffer);
        }
        input_ip = strtok(NULL, " ");
    }

    return NULL;
}

/** Configuration directives */
static command_rec antiloris_cmds[] = {
        AP_INIT_TAKE1("IPTotalLimit", ip_total_limit_config_cmd, NULL, RSRC_CONF,
                      "the maximum number of simultaneous connections in any state per IP address"),
        AP_INIT_TAKE1("IPReadLimit", ip_read_limit_config_cmd, NULL, RSRC_CONF,
                      "the maximum number of simultaneous connections in READ state per IP address"),
        AP_INIT_TAKE1("IPWriteLimit", ip_write_limit_config_cmd, NULL, RSRC_CONF,
                      "the maximum number of simultaneous connections in WRITE state per IP address"),
        AP_INIT_TAKE1("IPOtherLimit", ip_other_limit_config_cmd, NULL, RSRC_CONF,
                      "the maximum number of simultaneous idle connections per IP address"),
        AP_INIT_ITERATE("LocalIPs", whitelist_ips_config_cmd, NULL, RSRC_CONF,
                        "a list of IPs (separated by spaces) whose connection are always allowed. "
                        "The WhitelistIPs directive overrides this one."),
        AP_INIT_ITERATE("WhitelistIPs", whitelist_ips_config_cmd, NULL, RSRC_CONF,
                        "a space-delimited list of IPv4 and IPv6 addresses, ranges, or CIDRs "
                        "which should not be subjected to any limits by mod_antiloris. "
                        "This directive overrides the LocalIPs directive."),
        {NULL}
};

/** Startup-time initialization */
static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    void *data;
    const char *userdata_key = "antiloris_init";

    /* initialize_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *) 1, userdata_key, apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    ap_add_version_component(p, MODULE_NAME "/" MODULE_VERSION);
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, MODULE_NAME
            " "
            MODULE_VERSION
            " started");

    return OK;
}

/**
 * Check if the ip_counts hit any limits in antiloris_config
 * @param ip_counts Array of connections for an IP address by type
 * @param conf The configuration struct
 * @return 1 if a limit has been reached or 0 if no limits have been reached
 */
static int _reached_ip_con_limit(signed long int *ip_counts, antiloris_config *conf) {
    int i, ip_total_count = 0;
    for (i = 0; i < sizeof(ip_counts) / sizeof(ip_counts[0]); i++)
        ip_total_count += ip_counts[i];
    if ((conf->total_limit > 0 && ip_total_count >= conf->total_limit) ||
        (conf->read_limit > 0 && ip_counts[READ_COUNT_INDEX] >= conf->read_limit) ||
        (conf->write_limit > 0 && ip_counts[WRITE_COUNT_INDEX] >= conf->write_limit) ||
        (conf->other_limit > 0 && ip_counts[OTHER_COUNT_INDEX] >= conf->other_limit))
        return 1;
    return 0;
}

/** Our hook at connection processing */
static int pre_connection(conn_rec *c) {
    /* Remote IP to be used in checking operations */
    char *remote_ip = c->remote_ip;

    /* loop index variables */
    int i = 0, j = 0;

    /* running count of number of connections from this address */
    signed long int ip_counts[3] = {0};

    /* other variables we'll be using */
    antiloris_config *conf = ap_get_module_config(c->base_server->module_config, &antiloris_module);
    sb_handle *sbh = c->sbh;

#if AP_MODULE_MAGIC_AT_LEAST(20110605, 2)
    /* get the socket descriptor */
    apr_socket_t *csd = ap_get_conn_socket(c);
#endif

    /* scoreboard data structure */
    worker_score *ws_record;

    /* Save current remote ip in current ws_record */
    ws_record = &ap_scoreboard_image->servers[sbh->child_num][sbh->thread_num];
    apr_cpystrn(ws_record->client, remote_ip, sizeof(ws_record->client));

    /* Take whitelist IPs in consideration */
    if (is_ip_whitelisted(remote_ip, conf->ip_whitelist)) {
#if AP_MODULE_MAGIC_AT_LEAST(20050101, 0)
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "Exempted from connection limit");
#else
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "[client %s] Exempted from connection limit", remote_ip);
#endif
        /* Pass request to appropriate module */
        return DECLINED;
    }

    /* Count up the number of connections we are handling right now from this IP address */
    for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
#if AP_MODULE_MAGIC_AT_LEAST(20071023, 0)
            ws_record = ap_get_scoreboard_worker_from_indexes(i, j);
#else
            ws_record = ap_get_scoreboard_worker(i, j);
#endif
            switch (ws_record->status) {
                case SERVER_BUSY_READ:
                    /* Handle read state */
                    if (strcmp(remote_ip, ws_record->client) == 0)
                        ip_counts[READ_COUNT_INDEX]++;
                    break;
                case SERVER_BUSY_WRITE:
                    /* Handle write state */
                    if (strcmp(remote_ip, ws_record->client) == 0)
                        ip_counts[WRITE_COUNT_INDEX]++;
                    break;
                case SERVER_BUSY_KEEPALIVE:
                case SERVER_BUSY_LOG:
                case SERVER_BUSY_DNS:
                case SERVER_CLOSING:
                case SERVER_GRACEFUL:
                    /* Handle any other connection state */
                    if (strcmp(remote_ip, ws_record->client) == 0)
                        ip_counts[OTHER_COUNT_INDEX]++;
                    break;
                default:
                    /* Other states are ignored */
                    break;
            }
        }
    }

    /* Deny the request if it exceeds limits */
    if (_reached_ip_con_limit(ip_counts, conf)) {
#if AP_MODULE_MAGIC_AT_LEAST(20050101, 0)
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c, "Connection rejected by Antiloris, too many connections");
#else
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                     "[client %s] Connection rejected by Antiloris, too many connections", remote_ip);
#endif
#if AP_MODULE_MAGIC_AT_LEAST(20110605, 2)
        apr_socket_close(csd);
#endif
        return OK;
    }

    /* Pass request to appropriate module */
    return DECLINED;
}

/** Registration of our hooks */
static void register_hooks(apr_pool_t *p) {
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_process_connection(pre_connection, NULL, NULL, APR_HOOK_FIRST);
}

/** Our module data */
module AP_MODULE_DECLARE_DATA
        antiloris_module = {
        STANDARD20_MODULE_STUFF,
        NULL,            /* create per-dir config structures */
        NULL,            /* merge  per-dir config structures */
        create_config,    /* create per-server config structures */
        NULL,            /* merge  per-server config structures */
        antiloris_cmds,    /* table of config file commands */
        register_hooks
};
