/*
 * Copyright (C) 2026 crypto512
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "command.h"
#include "swanctl.h"
#include "load_conns.h"

/**
 * Check if we should handle a key as a list of comma separated values
 */
static bool is_list_key(char *key)
{
	char *keys[] = {
		"local_addrs",
		"remote_addrs",
		"proposals",
		"esp_proposals",
		"ah_proposals",
		"local_ts",
		"remote_ts",
		"vips",
		"pools",
		"groups",
		"cert_policy",
	};
	int i;

	for (i = 0; i < countof(keys); i++)
	{
		if (strcaseeq(keys[i], key))
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Add a vici list from a comma separated string value
 */
static void add_list_key(vici_req_t *req, char *key, char *value)
{
	enumerator_t *enumerator;
	char *token;

	vici_begin_list(req, key);
	enumerator = enumerator_create_token(value, ",", " ");
	while (enumerator->enumerate(enumerator, &token))
	{
		vici_add_list_itemf(req, "%s", token);
	}
	enumerator->destroy(enumerator);
	vici_end_list(req);
}

/**
 * Add key/values to a VICI request from a settings section
 */
static bool add_key_values(vici_req_t *req, settings_t *cfg, char *section)
{
	enumerator_t *enumerator;
	char *key, *value;

	enumerator = cfg->create_key_value_enumerator(cfg, section);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		if (is_list_key(key))
		{
			add_list_key(req, key, value);
		}
		else
		{
			vici_add_key_valuef(req, key, "%s", value);
		}
	}
	enumerator->destroy(enumerator);
	return TRUE;
}

/**
 * Add sections to a VICI request from settings
 */
static bool add_sections(vici_req_t *req, settings_t *cfg, char *section)
{
	enumerator_t *enumerator;
	char *name, buf[1024];
	bool ret = TRUE;

	enumerator = cfg->create_section_enumerator(cfg, section);
	while (enumerator->enumerate(enumerator, &name))
	{
		vici_begin_section(req, name);
		snprintf(buf, sizeof(buf), "%s.%s", section, name);
		ret = add_key_values(req, cfg, buf);
		if (!ret)
		{
			break;
		}
		ret = add_sections(req, cfg, buf);
		if (!ret)
		{
			break;
		}
		vici_end_section(req);
	}
	enumerator->destroy(enumerator);

	return ret;
}

/**
 * Context for SA entry parsing
 */
typedef struct {
	char *unique_id;
	char *name;
	char *type;
	char *reason;
	char *details;
} sa_entry_t;

/**
 * Key-value callback for SA entry fields
 */
CALLBACK(sa_entry_kv, int,
	sa_entry_t *entry, vici_res_t *res, char *name, void *value, int len)
{
	if (streq(name, "unique_id"))
	{
		free(entry->unique_id);
		entry->unique_id = strndup(value, len);
	}
	else if (streq(name, "name"))
	{
		free(entry->name);
		entry->name = strndup(value, len);
	}
	else if (streq(name, "type"))
	{
		free(entry->type);
		entry->type = strndup(value, len);
	}
	else if (streq(name, "reason"))
	{
		free(entry->reason);
		entry->reason = strndup(value, len);
	}
	else if (streq(name, "details"))
	{
		free(entry->details);
		entry->details = strndup(value, len);
	}
	return 0;
}

/**
 * Parse individual SA entry (ike-0, child-0, etc.)
 */
CALLBACK(parse_sa_entry, int,
	void *null, vici_res_t *res, char *name)
{
	sa_entry_t entry = {};
	int ret;

	ret = vici_parse_cb(res, NULL, sa_entry_kv, NULL, &entry);
	if (ret == 0 && entry.type && entry.name && entry.unique_id)
	{
		if (entry.reason && strlen(entry.reason) > 0)
		{
			printf("      %s %s[%s]: %s\n", entry.type, entry.name,
				   entry.unique_id, entry.reason);
			/* Print details on separate line if available */
			if (entry.details && strlen(entry.details) > 0)
			{
				printf("        -> %s\n", entry.details);
			}
		}
		else
		{
			printf("      %s %s[%s]\n", entry.type, entry.name, entry.unique_id);
		}
	}
	free(entry.unique_id);
	free(entry.name);
	free(entry.type);
	free(entry.reason);
	free(entry.details);
	return ret;
}

/**
 * Context for top-level section parsing
 */
typedef struct {
	int preserved_count;
	int incompatible_count;
	bool printed_preserved_header;
	bool printed_incompatible_header;
} parse_context_t;

/**
 * Parse top-level sections and iterate SA entries
 */
CALLBACK(parse_top_section, int,
	parse_context_t *ctx, vici_res_t *res, char *name)
{
	if (streq(name, "preserved"))
	{
		if (!ctx->printed_preserved_header && ctx->preserved_count > 0)
		{
			printf("    Preserved:\n");
			ctx->printed_preserved_header = TRUE;
		}
		return vici_parse_cb(res, parse_sa_entry, NULL, NULL, NULL);
	}
	else if (streq(name, "incompatible"))
	{
		if (!ctx->printed_incompatible_header && ctx->incompatible_count > 0)
		{
			printf("    Incompatible:\n");
			ctx->printed_incompatible_header = TRUE;
		}
		return vici_parse_cb(res, parse_sa_entry, NULL, NULL, NULL);
	}
	return 0;
}

/**
 * Validate a connection config against running SAs (dry-run)
 */
static bool validate_conn(vici_conn_t *conn, settings_t *cfg,
						  char *section, command_format_options_t format,
						  int *preserved_total, int *incompatible_total)
{
	vici_req_t *req;
	vici_res_t *res;
	bool ret = TRUE;
	char buf[1024];
	int preserved, incompatible;

	snprintf(buf, sizeof(buf), "%s.%s", "connections", section);

	req = vici_begin("validate-conn");

	vici_begin_section(req, section);
	if (!add_key_values(req, cfg, buf) ||
		!add_sections(req, cfg, buf))
	{
		vici_free_req(req);
		return FALSE;
	}
	vici_end_section(req);

	res = vici_submit(req, conn);
	if (!res)
	{
		fprintf(stderr, "validate-conn request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "validate-conn reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "validating connection '%s' failed: %s\n",
				section, vici_find_str(res, "", "errmsg"));
		ret = FALSE;
	}
	else
	{
		parse_context_t ctx = {};

		preserved = atoi(vici_find_str(res, "0", "summary.preserved"));
		incompatible = atoi(vici_find_str(res, "0", "summary.incompatible"));

		ctx.preserved_count = preserved;
		ctx.incompatible_count = incompatible;

		printf("Connection '%s':\n", section);
		printf("  Preserved SAs: %d\n", preserved);
		printf("  Incompatible SAs: %d\n", incompatible);

		/* Parse all sections in one pass */
		if (preserved > 0 || incompatible > 0)
		{
			vici_parse_cb(res, parse_top_section, NULL, NULL, &ctx);
		}

		*preserved_total += preserved;
		*incompatible_total += incompatible;
	}
	vici_free_res(res);
	return ret;
}

/**
 * Validate all connections from configuration file
 */
static int validate_conns_cfg(vici_conn_t *conn, command_format_options_t format,
							  settings_t *cfg)
{
	u_int found = 0, validated = 0;
	int preserved_total = 0, incompatible_total = 0;
	char *section;
	enumerator_t *enumerator;

	enumerator = cfg->create_section_enumerator(cfg, "connections");
	while (enumerator->enumerate(enumerator, &section))
	{
		found++;
		if (validate_conn(conn, cfg, section, format,
						  &preserved_total, &incompatible_total))
		{
			validated++;
		}
	}
	enumerator->destroy(enumerator);

	if (format & COMMAND_FORMAT_RAW)
	{
		return 0;
	}
	if (found == 0)
	{
		printf("no connections found in configuration\n");
		return 0;
	}

	printf("\n");
	printf("=== Validation Summary ===\n");
	printf("Connections validated: %u\n", validated);
	printf("Total preserved SAs: %d\n", preserved_total);
	printf("Total incompatible SAs: %d\n", incompatible_total);

	if (incompatible_total > 0)
	{
		printf("\nWARNING: %d SA(s) would be terminated by this configuration change\n",
			   incompatible_total);
	}
	else if (preserved_total > 0)
	{
		printf("\nAll %d SA(s) compatible - safe to reload\n", preserved_total);
	}

	if (validated != found)
	{
		fprintf(stderr, "validated %u of %u connections, %u failed\n",
				validated, found, found - validated);
		return EINVAL;
	}
	return 0;
}

static int validate_conns(vici_conn_t *conn)
{
	command_format_options_t format = COMMAND_FORMAT_NONE;
	settings_t *cfg;
	char *arg, *file = NULL;
	int ret;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'P':
				format |= COMMAND_FORMAT_PRETTY;
				/* fall through to raw */
			case 'r':
				format |= COMMAND_FORMAT_RAW;
				continue;
			case 'f':
				file = arg;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --validate-conns option");
		}
		break;
	}

	cfg = load_swanctl_conf(file);
	if (!cfg)
	{
		return EINVAL;
	}

	ret = validate_conns_cfg(conn, format, cfg);

	cfg->destroy_clear(cfg);

	return ret;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		validate_conns, 'V', "validate-conns",
		"validate connection configuration against running SAs (dry-run)",
		{"[--raw|--pretty] [--file <file>]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
			{"file",		'f', 1, "custom path to swanctl.conf"},
		}
	});
}
