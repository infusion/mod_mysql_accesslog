#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "sys-socket.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <arpa/inet.h>

#ifdef HAVE_MYSQL
#include <mysql.h>
#endif



#ifdef HAVE_MYSQL

typedef struct {
	char key;
	enum {
		FORMAT_UNSET,
		FORMAT_UNSUPPORTED,
		FORMAT_REMOTE_HOST,
		FORMAT_REMOTE_IDENT,
		FORMAT_REMOTE_USER,
		FORMAT_TIMESTAMP,
		FORMAT_REQUEST_LINE,
		FORMAT_STATUS,
		FORMAT_BYTES_OUT_NO_HEADER,
		FORMAT_HEADER,

		FORMAT_REMOTE_ADDR,
		FORMAT_LOCAL_ADDR,
		FORMAT_COOKIE,
		FORMAT_TIME_USED_MS,
		FORMAT_ENV,
		FORMAT_FILENAME,
		FORMAT_REQUEST_PROTOCOL,
		FORMAT_REQUEST_METHOD,
		FORMAT_SERVER_PORT,
		FORMAT_QUERY_STRING,
		FORMAT_TIME_USED,
		FORMAT_URL,
		FORMAT_SERVER_NAME,
		FORMAT_HTTP_HOST,
		FORMAT_CONNECTION_STATUS,
		FORMAT_BYTES_IN,
		FORMAT_BYTES_OUT,

		FORMAT_RESPONSE_HEADER
	} type;
} format_mapping;

const format_mapping fmap[] = {

	{ 'h', FORMAT_REMOTE_HOST },
	{ 'l', FORMAT_REMOTE_IDENT },
	{ 'u', FORMAT_REMOTE_USER },
	{ 't', FORMAT_TIMESTAMP },
	{ 'r', FORMAT_REQUEST_LINE },
	{ 's', FORMAT_STATUS },
	{ 'b', FORMAT_BYTES_OUT_NO_HEADER },
	{ 'i', FORMAT_HEADER },

	{ 'a', FORMAT_REMOTE_ADDR },
	{ 'A', FORMAT_LOCAL_ADDR },
	{ 'B', FORMAT_BYTES_OUT_NO_HEADER },
	{ 'C', FORMAT_COOKIE },
	{ 'D', FORMAT_TIME_USED_MS },
	{ 'e', FORMAT_ENV },
	{ 'f', FORMAT_FILENAME },
	{ 'H', FORMAT_REQUEST_PROTOCOL },
	{ 'm', FORMAT_REQUEST_METHOD },
	{ 'n', FORMAT_UNSUPPORTED }, /* we have no notes */
	{ 'p', FORMAT_SERVER_PORT },
	{ 'P', FORMAT_UNSUPPORTED }, /* we are only one process */
	{ 'q', FORMAT_QUERY_STRING },
	{ 'T', FORMAT_TIME_USED },
	{ 'U', FORMAT_URL }, /* w/o querystring */
	{ 'v', FORMAT_SERVER_NAME },
	{ 'V', FORMAT_HTTP_HOST },
	{ 'X', FORMAT_CONNECTION_STATUS },
	{ 'I', FORMAT_BYTES_IN },
	{ 'O', FORMAT_BYTES_OUT },

	{ 'o', FORMAT_RESPONSE_HEADER },

	{ '\0', FORMAT_UNSET }
};

typedef struct {
	buffer *string;
	int field;
} format_field;

typedef struct {
	format_field **ptr;

	size_t used;
	size_t size;
} format_fields;

typedef struct {

	MYSQL *mysql;
	MYSQL_BIND *bind;

	buffer *user;
	buffer *pass;
	buffer *sock;
	buffer *host;
	buffer *database;

	buffer *query;

	format_fields *parsed_query;
	buffer *format_query;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;

INIT_FUNC(mod_mysql_accesslog_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	return p;
}


static int mysql_accesslog_parse_query(server *srv, format_fields *fields, buffer *format_query, buffer *format) {
	size_t i, j, k = 0, start = 0;

	if (format->used == 0) return -1;

	for (i = 0; i < format->used - 1; i++) {

		switch(format->ptr[i]) {
			case '%':
				buffer_append_string_len(format_query, format->ptr + start, i - start);

				/* we need a new field */
				if (fields->size == 0) {
					fields->size = 16;
					fields->used = 0;
					fields->ptr = malloc(fields->size * sizeof(format_field * ));
				} else if (fields->used == fields->size) {
					fields->size+= 16;
					fields->ptr = realloc(fields->ptr, fields->size * sizeof(format_field * ));
				}

				/* search for the terminating command */
				switch (format->ptr[i+1]) {
					case '>':
					case '<':

						/* after the } has to be a character */
						if (format->ptr[i+2] == '\0') {
							log_error_write(srv, __FILE__, __LINE__, "s", "%< and %> have to be followed by a format-specifier");
							return -1;
						}

						for (j = 0; fmap[j].key != '\0'; j++) {
							if (fmap[j].key != format->ptr[i+2]) continue;

							/* found key */
							fields->ptr[fields->used] = malloc(sizeof(format_field));
							fields->ptr[fields->used]->field = fmap[j].type;
							fields->ptr[fields->used]->string = NULL;
							fields->used++;
							break;
						}

						if (fmap[j].key == '\0') {
							log_error_write(srv, __FILE__, __LINE__, "s", "%< and %> have to be followed by a valid format-specifier");
							return -1;
						}

						start = i + 3;
						i = start - 1; /* skip the string */

						break;

					case '{':
						/* go forward to } */

						for (k = i+2; k < format->used - 1; k++) {
							if (format->ptr[k] == '}') break;
						}

						if (k == format->used - 1) {
							log_error_write(srv, __FILE__, __LINE__, "s", "%{ has to be terminated by a }");
							return -1;
						}

						/* after the } has to be a character */
						if (format->ptr[k+1] == '\0') {
							log_error_write(srv, __FILE__, __LINE__, "s", "%{...} has to be followed by a format-specifier");
							return -1;
						}

						if (k == i + 2) {
							log_error_write(srv, __FILE__, __LINE__, "s", "%{...} has to be contain a string");
							return -1;
						}

						for (j = 0; fmap[j].key != '\0'; j++) {
							if (fmap[j].key != format->ptr[k+1]) continue;

							/* found key */
							fields->ptr[fields->used] = malloc(sizeof(format_field));
							fields->ptr[fields->used]->field = fmap[j].type;
							fields->ptr[fields->used]->string = buffer_init();

							buffer_copy_string_len(fields->ptr[fields->used]->string, format->ptr + i + 2, k - (i + 2));

							fields->used++;
							break;
						}

						if (fmap[j].key == '\0') {
							log_error_write(srv, __FILE__, __LINE__, "s", "%{...} has to be followed by a valid format-specifier");
							return -1;
						}

						start = k + 2;
						i = start - 1; /* skip the string */

						break;

					default:
						/* after the % has to be a character */
						if (format->ptr[i+1] == '\0') {
							log_error_write(srv, __FILE__, __LINE__, "s", "% has to be followed by a format-specifier");
							return -1;
						}

						for (j = 0; fmap[j].key != '\0'; j++) {
							if (fmap[j].key != format->ptr[i+1]) continue;

							/* found key */
							fields->ptr[fields->used] = malloc(sizeof(format_field));
							fields->ptr[fields->used]->field = fmap[j].type;
							fields->ptr[fields->used]->string = NULL;

							fields->used++;
							break;
						}

						if (fmap[j].key == '\0') {
							if (format->ptr[i+1] == '%') {
								BUFFER_APPEND_STRING_CONST(format_query, "%");
							} else {
								log_error_write(srv, __FILE__, __LINE__, "s", "% has to be followed by a valid format-specifier");
								return -1;
							}
						}

						start = i + 2;
						i = start - 1; /* skip the string */

						break;
				}

				BUFFER_APPEND_STRING_CONST(format_query, "?");
				break;
		}
	}

	if (start < i) {
		buffer_append_string_len(format_query, format->ptr + start, i - start);
	}

	return 0;
}

FREE_FUNC(mod_mysql_accesslog_free) {
	plugin_data *p = p_d;

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;

			mysql_close(s->mysql);
			free(s->bind);

			buffer_free(s->user);
			buffer_free(s->pass);
			buffer_free(s->sock);
			buffer_free(s->host);
			buffer_free(s->database);

			buffer_free(s->query);
			buffer_free(s->format_query);

			if (s->parsed_query) {
				size_t j;
				for (j = 0; j < s->parsed_query->used; j++) {
					if (s->parsed_query->ptr[j]->string) buffer_free(s->parsed_query->ptr[j]->string);
					free(s->parsed_query->ptr[j]);
				}
				free(s->parsed_query->ptr);
				free(s->parsed_query);
			}

			free(s);
		}
		free(p->config_storage);
	}
	free(p);

	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_mysql_accesslog_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "mysql-accesslog.user",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "mysql-accesslog.pass",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
		{ "mysql-accesslog.data",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 2 */
		{ "mysql-accesslog.sock",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 3 */
		{ "mysql-accesslog.host",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 4 */
		{ "mysql-accesslog.query",     NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 5 */
		{ NULL,                        NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->mysql = NULL;
		s->bind  = NULL;
		s->user = buffer_init();
		s->pass = buffer_init();
		s->sock = buffer_init();
		s->host = buffer_init();
		s->database = buffer_init();

		s->query = buffer_init();
		s->format_query = buffer_init();

		cv[0].destination = s->user;
		cv[1].destination = s->pass;
		cv[2].destination = s->database;
		cv[3].destination = s->sock;
		cv[4].destination = s->host;
		cv[5].destination = s->query;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}

		if (!buffer_is_empty(s->query) && (!buffer_is_empty(s->host) || !buffer_is_empty(s->sock))) {
			my_bool reconnect = 1;

			/* parse */
			s->parsed_query = calloc(1, sizeof(*(s->parsed_query)));

			if (-1 == mysql_accesslog_parse_query(srv, s->parsed_query, s->format_query, s->query)) {

				log_error_write(srv, __FILE__, __LINE__, "sb", "parsing accesslog-definition failed:", s->query);
				return HANDLER_ERROR;
			}

			/* Create bind array */
			s->bind = calloc(s->parsed_query->used, sizeof(*(s->bind)));

#if 1
			/* debugging */
			size_t j;
			for (j = 0; j < s->parsed_query->used; j++) {
				log_error_write(srv, __FILE__, __LINE__, "ssds",
					"config:", "format", s->parsed_query->ptr[j]->field,
					s->parsed_query->ptr[j]->string ?
					s->parsed_query->ptr[j]->string->ptr : "" );
			}
			log_error_write(srv, __FILE__, __LINE__, "sb", "format query: ", s->format_query);
#endif

			if (NULL == (s->mysql = mysql_init(NULL))) {
				log_error_write(srv, __FILE__, __LINE__, "s", "mysql_init() failed, exiting...");
				return HANDLER_ERROR;
			}

#if MYSQL_VERSION_ID >= 50013
			/* in mysql versions above 5.0.3 the reconnect flag is off by default */
			mysql_options(s->mysql, MYSQL_OPT_RECONNECT, &reconnect);
#endif

#define PATCH(x) s->x->used ? s->x->ptr : NULL

			if (!mysql_real_connect(s->mysql, PATCH(host), PATCH(user), PATCH(pass), PATCH(database), 0, PATCH(sock), CLIENT_REMEMBER_OPTIONS)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "mysql_real_connect() failed, ", mysql_error(s->mysql));
				return HANDLER_ERROR;
			}
#undef PATCH

#ifdef FD_CLOEXEC
			fcntl(s->mysql->net.fd, F_SETFD, FD_CLOEXEC);
#endif
		}
	}
	return HANDLER_GO_ON;
}


#define PATCH(x) \
p->conf.x = s->x;
static int mod_mysql_accesslog_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(mysql);
	PATCH(bind);

	PATCH(parsed_query);
	PATCH(format_query);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("mysql-accesslog.query"))) {
				PATCH(parsed_query);
				PATCH(format_query);
				break;
			}
		}

		if (s->mysql) {
			PATCH(mysql);
			PATCH(bind);
		}
	}
	return 0;
}
#undef PATCH


#define HANDLE_LEN(len)		(len <= 1 ? 0 : len - 1)
REQUESTDONE_FUNC(mod_mysql_accesslog_write) {
	plugin_data *p = p_d;

	size_t j;

	data_string *request_header, *response_header, *environment;

	MYSQL_BIND *b;
	MYSQL_STMT *stmt;

	my_bool maybe_null = 1;

	uint32_t ip;

	unsigned long time_used, port, http_method, http_version, user_length, request_length, body_length, req_header_length, res_header_length, file_length, server_length, host_length, query_length, url_length, environment_length;
	char *colon;

	mod_mysql_accesslog_patch_connection(srv, con, p);

	if (p->conf.mysql == NULL) {
		log_error_write(srv, __FILE__, __LINE__, "s", "No active mysql connection!");
		return HANDLER_GO_ON;
	}

	if (!(stmt = mysql_stmt_init(p->conf.mysql))) {
		return HANDLER_ERROR;
	}

	if (mysql_stmt_prepare(stmt, p->conf.format_query->ptr, p->conf.format_query->used - 1)) {
		return HANDLER_ERROR;
	}

	b = p->conf.bind;


	for (j = 0; j < p->conf.parsed_query->used; j++) {

		switch(p->conf.parsed_query->ptr[j]->field) {

		case FORMAT_TIMESTAMP:
			b[j].buffer_type    = MYSQL_TYPE_LONG;
			b[j].buffer         = (char *)&(srv->cur_ts);
			b[j].is_unsigned    = 1;
			break;

		case FORMAT_REMOTE_HOST:
			ip = htonl(con->dst_addr.ipv4.sin_addr.s_addr);
			b[j].buffer_type	= MYSQL_TYPE_LONG;
			b[j].buffer			= (char *)&ip;
			b[j].is_unsigned    = 1;
			break;

		case FORMAT_REMOTE_USER:
			user_length			= HANDLE_LEN(con->authed_user->used);

			b[j].buffer_type	= MYSQL_TYPE_STRING;
			b[j].buffer			= con->authed_user->ptr;
			b[j].buffer_length	= 2048;
			b[j].length			= &user_length;
			if (!user_length) {
				b[j].is_null	= &maybe_null;
			} else {
				b[j].is_null	= NULL;
			}
			break;

		case FORMAT_REQUEST_LINE:
			request_length = HANDLE_LEN(con->request.request_line->used);

			b[j].buffer_type	= MYSQL_TYPE_STRING;
			b[j].buffer			= con->request.request_line->ptr;
			b[j].buffer_length	= 2048;
			b[j].length			= &request_length;
			break;

		case FORMAT_STATUS:
			b[j].buffer_type    = MYSQL_TYPE_LONG;
			b[j].buffer         = (char *)&(con->http_status);
			b[j].is_unsigned	= 1;
			break;

		case FORMAT_BYTES_OUT_NO_HEADER:
			if (con->bytes_written > 0) {
				body_length = con->bytes_written - con->bytes_header <= 0 ? 0 : con->bytes_written - con->bytes_header;
			} else {
				body_length = 0;
			}

			b[j].buffer_type	= MYSQL_TYPE_LONG;
			b[j].buffer			= (char *)&body_length;
			b[j].is_unsigned	= 1;
			break;

		case FORMAT_HEADER:
			b[j].buffer_type	= MYSQL_TYPE_STRING;
			b[j].buffer_length	= 2048;
			if (NULL != p->conf.parsed_query->ptr[j]->string && NULL != (request_header = (data_string *)array_get_element(con->request.headers, p->conf.parsed_query->ptr[j]->string->ptr))) {
				req_header_length = HANDLE_LEN(request_header->value->used);
				b[j].buffer		= request_header->value->ptr;
				b[j].length		= &req_header_length;
				b[j].is_null	= NULL;
			} else {
				b[j].is_null	= &maybe_null;
			}
			break;

		case FORMAT_RESPONSE_HEADER:
			b[j].buffer_type	= MYSQL_TYPE_STRING;
			b[j].buffer_length	= 2048;
			if (NULL != p->conf.parsed_query->ptr[j]->string && NULL != (response_header = (data_string *)array_get_element(con->response.headers, p->conf.parsed_query->ptr[j]->string->ptr))) {
				res_header_length = HANDLE_LEN(response_header->value->used);
				b[j].buffer		= response_header->value->ptr;
				b[j].length		= &res_header_length;;
				b[j].is_null	= NULL;
			} else {
				b[j].is_null	= &maybe_null;
			}
			break;

		case FORMAT_ENV:
			b[j].buffer_type	= MYSQL_TYPE_STRING;
			b[j].buffer_length	= 2048;
			if (NULL != p->conf.parsed_query->ptr[j]->string && NULL != (environment = (data_string *)array_get_element(con->environment, p->conf.parsed_query->ptr[j]->string->ptr))) {
				environment_length = HANDLE_LEN(environment->value->used);
				b[j].buffer		= environment->value->ptr;
				b[j].length		= &environment_length;
				b[j].is_null	= NULL;
			} else {
				 b[j].is_null	=&maybe_null;
			}
			break;

		case FORMAT_FILENAME:
			file_length = HANDLE_LEN(con->physical.path->used);

			b[j].buffer_type	= MYSQL_TYPE_STRING;
			b[j].buffer			= con->physical.path->ptr;
			b[j].buffer_length	= 2048;
			b[j].length			= &file_length;
			if (!file_length) {
				b[j].is_null	= &maybe_null;
			} else {
				b[j].is_null	= NULL;
			}
			break;

		case FORMAT_BYTES_OUT:
			b[j].buffer_type    = MYSQL_TYPE_LONG;
			b[j].buffer         = (char *)&(con->bytes_written);
			b[j].is_unsigned    = 1;
			break;

		case FORMAT_BYTES_IN:
			b[j].buffer_type    = MYSQL_TYPE_LONG;
			b[j].buffer         = (char *)&(con->bytes_read);
			b[j].is_unsigned    = 1;
			break;

		case FORMAT_TIME_USED:
			time_used = srv->cur_ts - con->request_start;

            b[j].buffer_type    = MYSQL_TYPE_LONG;
            b[j].buffer         = (char *)&(time_used);
			b[j].is_unsigned	= 1;
			break;

		case FORMAT_SERVER_NAME:
			server_length = HANDLE_LEN(con->server_name->used);

			b[j].buffer_type	= MYSQL_TYPE_VAR_STRING;
			b[j].buffer			= con->server_name->ptr;
			b[j].buffer_length	= 2048;
			b[j].length			= &server_length;
			if (!server_length) {
				b[j].is_null	= &maybe_null;
			} else {
				b[j].is_null	= NULL;
			}
			break;

		case FORMAT_HTTP_HOST:
			host_length = HANDLE_LEN(con->uri.authority->used);

			b[j].buffer_type	= MYSQL_TYPE_VAR_STRING;
			b[j].buffer			= con->uri.authority->ptr;
			b[j].buffer_length	= 2048;
			b[j].length			= &host_length;
			if (!host_length) {
				b[j].is_null	= &maybe_null;
			} else {
				b[j].is_null	= NULL;
			}
			break;

		case FORMAT_REQUEST_PROTOCOL:
			http_version = con->request.http_version + 1;

			b[j].buffer_type	= MYSQL_TYPE_LONG;
			b[j].buffer			= (char *)&http_version;
			break;

		case FORMAT_REQUEST_METHOD:
			http_method = con->request.http_method + 1;

			b[j].buffer_type	= MYSQL_TYPE_LONG;
			b[j].buffer			= (char *)&http_method;
			break;

		case FORMAT_SERVER_PORT:
			colon = strchr(((server_socket *)(con->srv_socket))->srv_token->ptr, ':');

			if (colon) {
				port = atol(colon + 1);
			} else {
				port = srv->srvconf.port;
			}
			b[j].buffer_type	= MYSQL_TYPE_LONG;
			b[j].buffer			= (char *)&port;
			b[j].is_unsigned	= 1;
			break;

		case FORMAT_QUERY_STRING:
			query_length = HANDLE_LEN(con->uri.query->used);

			b[j].buffer_type    = MYSQL_TYPE_VAR_STRING;
			b[j].buffer         = con->uri.query->ptr;
            b[j].buffer_length  = 2048;
            b[j].length         = &query_length;

			if (!query_length) {
				b[j].is_null	= &maybe_null;
			} else {
				b[j].is_null	= NULL;
			}
			break;

		case FORMAT_URL:
			url_length = HANDLE_LEN(con->uri.path_raw->used);

			b[j].buffer_type	= MYSQL_TYPE_VAR_STRING;
			b[j].buffer			= con->uri.path_raw->ptr;
			b[j].buffer_length	= 2048;
			b[j].length			= &url_length;
			break;

		case FORMAT_CONNECTION_STATUS:
			b[j].buffer_type	= MYSQL_TYPE_LONG;
			b[j].buffer			= (char *)&(con->keep_alive);
			b[j].is_unsigned	= 1;
			break;

		default:
			b[j].buffer_type	= MYSQL_TYPE_STRING;
			b[j].buffer			= NULL;
			b[j].is_null		= &maybe_null;
			break;
		}
	}


	if (mysql_stmt_bind_param(stmt, b)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "Parameter binding failed: ", mysql_stmt_error(stmt));	
		return HANDLER_ERROR;
	}

	if (mysql_stmt_execute(stmt)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "Query execution failed: ", mysql_stmt_error(stmt));
		return HANDLER_ERROR;
	}

	return HANDLER_GO_ON;
}

int mod_mysql_accesslog_plugin_init(plugin *p) {

	p->version				= LIGHTTPD_VERSION_ID;
	p->name					= buffer_init_string("mysql-accesslog");

	p->init					= mod_mysql_accesslog_init;
	p->cleanup				= mod_mysql_accesslog_free;
	p->set_defaults			= mod_mysql_accesslog_set_defaults;

	p->handle_request_done	= mod_mysql_accesslog_write;

	p->data					= NULL;

	return 0;
}

#else
int mod_mysql_vhost_plugin_init(plugin *p) {
	p->version				= LIGHTTPD_VERSION_ID;
	p->name					= buffer_init_string("mysql-accesslog");

	return 0;
}
#endif

