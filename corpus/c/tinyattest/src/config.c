/*
 * Config reader.
 *
 * The file is a flat `key = value` list; anything after a '#' is a comment.
 */

#include "tinyattest.h"

#include <stdio.h>
#include <string.h>

static char *trim(char *s)
{
	char *end;

	while (*s == ' ' || *s == '\t')
		s++;
	if (*s == '\0')
		return s;

	end = s + strlen(s) - 1;
	while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r' ||
	                   *end == '"' || *end == '\''))
		*end-- = '\0';

	if (*s == '"' || *s == '\'')
		s++;
	return s;
}

static void assign(struct ta_config *out, const char *key, const char *value)
{
	if (strcmp(key, "transport") == 0)
		snprintf(out->transport, sizeof(out->transport), "%s", value);
	else if (strcmp(key, "report_cipher") == 0)
		snprintf(out->report_cipher, sizeof(out->report_cipher), "%s", value);
	else if (strcmp(key, "report_signature") == 0)
		snprintf(out->report_signature, sizeof(out->report_signature), "%s", value);
	else if (strcmp(key, "key_agreement") == 0)
		snprintf(out->key_agreement, sizeof(out->key_agreement), "%s", value);
	else if (strcmp(key, "digest") == 0)
		snprintf(out->digest, sizeof(out->digest), "%s", value);
}

int ta_config_load(const char *path, struct ta_config *out)
{
	FILE *file;
	char line[256];

	if (path == NULL || out == NULL)
		return TA_ERR;

	memset(out, 0, sizeof(*out));

	file = fopen(path, "r");
	if (file == NULL)
		return TA_ERR;

	while (fgets(line, sizeof(line), file) != NULL) {
		char *comment = strchr(line, '#');
		char *separator;
		char *key;
		char *value;

		if (comment != NULL)
			*comment = '\0';

		separator = strchr(line, '=');
		if (separator == NULL)
			continue;

		*separator = '\0';
		key = trim(line);
		value = trim(separator + 1);

		if (*key != '\0' && *value != '\0')
			assign(out, key, value);
	}

	fclose(file);
	return TA_OK;
}
