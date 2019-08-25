/*
 * Copyright(c) 2019 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 */
#include <config.h>
#include <wget.h>
#include <gettext.h>
#include <readline/readline.h>
#include <readline/history.h>

#ifdef ENABLE_NLS
#	define _(STRING) gettext(STRING)
#else
#	define _(STRING) STRING
#endif

/* Number of elements within an array */
#define countof(a) (sizeof(a)/sizeof(*(a)))

struct wget_interactive_ctx {
	char *site;
};

struct wget_interactive_cmd {
	const char *cmd;
	int (* cmd_handler) (struct wget_interactive_ctx *,
				char *const *, unsigned int);
};

static int parse_html(const char *html, size_t html_len, const char *encoding, const char *extension)
{
	char *p, *path;
	wget_html_parsed_url *html_url;
	wget_html_parsed_result *document;

	document = wget_html_get_urls_inline(html, NULL, NULL);

	for (int it = 0; it < wget_vector_size(document->uris); it++) {
		html_url = wget_vector_get(document->uris, it);

		path = wget_strmemdup(html_url->url.p, html_url->url.len);

		if (extension) {
			if (strlen(extension) < strlen(path)) {
				p = path + (strlen(path) - strlen(extension));
				if (!wget_strncasecmp(p, extension, strlen(extension)))
					wget_info_printf("%s\n", path);
			}
		} else {
			wget_info_printf("%s\n", path);
		}
	}

	wget_html_free_urls_inline(&document);
	return 0;
}

static int do_ls(const char *url, const char *extension)
{
	wget_dns *dns;
	wget_http_response *resp = NULL;

	wget_net_init();
	wget_dns_init(&dns);
	wget_tcp_set_dns(NULL, dns);

//	uri = wget_iri_parse(url, NULL);
//
//	req = wget_http_create_request(uri, "GET");
//
//	wget_http_add_header(req, "User-Agent", "Mozilla/5.0");
//	wget_http_add_header(req, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
//	wget_http_add_header(req, "Accept-Encoding", "gzip, br");
//
//	wget_http_request_set_int(req, WGET_HTTP_RESPONSE_KEEPHEADER, 1);
//	wget_http_request_set_int(req, WGET_HTTP_MAX_REDIRECTIONS, 0);

	resp = wget_http_get(
		WGET_HTTP_URL, url,
		WGET_HTTP_HEADER_ADD, "User-Agent", "Mozilla/5.0",
		WGET_HTTP_HEADER_ADD, "Accept-Encoding", "gzip, br",
		WGET_HTTP_HEADER_ADD, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		WGET_HTTP_MAX_REDIRECTIONS, 0,
		0);

//	wget_http_open(&conn, uri);
//
//	if (conn) {
//		if (wget_http_send_request(conn, req) == 0) {
//			resp = wget_http_get_response(conn);
//			wget_http_close(&conn);
//		}
//	}

	if (!resp) {
		wget_info_printf(_("Could not connect to host\n"));
		return 0;
	}

	if (resp->body) {
		parse_html(resp->body->data,
				resp->body->length,
				resp->content_type_encoding,
				extension);
	} else {
		wget_info_printf(_("No HTML body was returned"));
	}

	wget_http_free_response(&resp);
	return 0;
}

static int __handle_tab_key(int count, int key)
{
	/* TODO this should search in the link list */
	printf("\tPressed tab (%d).\n", key);
	return 0;
}

static int __cmd_help(struct wget_interactive_ctx *ctx,
		char *const *args, unsigned int nargs)
{
	wget_info_printf("Here goes the help.\n");
	return 0;
}

static int __cmd_site(struct wget_interactive_ctx *ctx,
		char *const *args, unsigned int nargs)
{
	if (nargs == 0)
		return 0;

	if (ctx->site)
		free(ctx->site);

	ctx->site = wget_strdup(args[0]);
	return 0;
}

static int __cmd_ls(struct wget_interactive_ctx *ctx,
		char *const *args, unsigned int nargs)
{
	const char *extension = NULL;

	if (!ctx->site) {
		wget_error_printf(_("No site was set"));
		return 0;
	}

	if (nargs == 1)
		extension = args[0];

	do_ls(ctx->site, extension);

	return 0;
}

#define MAX_ARGS 5

static int split_args(const char *line, char **cmd_out, char ***args_out)
{
	int nargs;
	char **args, *p;

	p = strchr(line, ' ');
	if (!p)
		return 0;

	*cmd_out = calloc(p - line, 1);
	if (!cmd_out)
		return -1;

	strncpy(*cmd_out, line, p - line);

	args = malloc(sizeof(char *) * MAX_ARGS);
	if (!args)
		return -1;

	nargs = 0;

	for (unsigned i = 0; i < MAX_ARGS; i++) {
		args[i] = ++p;
		nargs++;

		p = strchr(p, ' ');
		if (!p)
			break;
	}

	*args_out = args;
	return nargs;
}

static int process_cmd(char *line,
		struct wget_interactive_ctx *ctx,
		const struct wget_interactive_cmd *cmds, int ncmds,
		int *exit_code)
{
	int i, retval = 0, cmd_found = 0, nargs;
	char *cmd = line, **args = NULL;

	if (!wget_strcmp(cmd, "exit"))
		return 1;

	nargs = split_args(line, &cmd, &args);
	if (nargs < 0) {
		wget_error_printf(_("Out of memory"));
		*exit_code = 2;
		return 1;
	}

	for (i = 0; i < ncmds && cmd_found == 0; i++) {
		if (!wget_strcmp(cmds[i].cmd, cmd)) {
			retval = cmds[i].cmd_handler(ctx, args, nargs);
			cmd_found = 1;
		}
	}

	if (cmd_found == 0)
		wget_error_printf(_("Unknown command '%s'\n"), cmd);

	free(args);
	/* FIXME this could trigger a double free later */
	free(cmd);

	return retval;
}

static void wget_interactive_ctx_init(struct wget_interactive_ctx *ctx)
{
	memset(ctx, 0, sizeof(struct wget_interactive_ctx));
}

static void wget_interactive_ctx_deinit(struct wget_interactive_ctx *ctx)
{
	if (ctx->site) {
		free(ctx->site);
		ctx->site = NULL;
	}
}

static int init_readline()
{
	/* Bind TAB key to our custom handler */
	return !rl_bind_key('\t', __handle_tab_key);
}

int main(int argc, char **argv)
{
	char *line = NULL;
	int exit = 0, retval = 0, debug = 0;
	struct wget_interactive_ctx ctx;
	struct wget_interactive_cmd cmds[] = {
		{
			.cmd = "help",
			.cmd_handler = __cmd_help
		},
		{
			.cmd = "site",
			.cmd_handler = __cmd_site
		},
		{
			.cmd = "ls",
			.cmd_handler = __cmd_ls
		}
	};

	if (argc == 2 && (!wget_strcmp(argv[1], "-d") || !wget_strcmp(argv[1], "--debug")))
		debug = 1;

	/* Initialize GNU readline */
	if (!init_readline()) {
		wget_error_printf(_("Could not initialize readline"));
		return 2;
	}

	/* Set some libwget globals */
	wget_global_init(
		WGET_INFO_STREAM, stdout,
		WGET_ERROR_STREAM, stderr,
		WGET_DNS_CACHING, 1,
		0);

	wget_tcp_set_timeout(NULL, 5000);
	wget_tcp_set_connect_timeout(NULL, 5000);
	wget_dns_set_timeout(NULL, 5000);

	if (debug)
		wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);

	wget_interactive_ctx_init(&ctx);

	wget_info_printf(_("Entering wget2 interactive console.\n"));
	wget_info_printf(_("Type 'help' for a list of available commands.\n"));
	wget_info_printf(_("Type 'exit' to exit from wget2.\n\n"));

	do {
		line = readline("wget2 > ");

		if (line) {
			if (*line)
				exit = process_cmd(line, &ctx, cmds, countof(cmds), &retval);

			free(line);
		}
	} while (!exit);

	wget_interactive_ctx_deinit(&ctx);
	wget_console_deinit();
	return retval;
}
