/*
 * Report transports.
 *
 * Transports are resolved by the name in etc/tinyattest.conf and reached
 * through a function pointer, so adding one does not mean touching main.
 */

#include "tinyattest.h"

#include <string.h>

static const struct ta_transport transports[] = {
	{ "verifier-direct", ta_seal },
	{ "gateway-relay", ta_seal },
};

const struct ta_transport *ta_transport_lookup(const char *name)
{
	size_t i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < sizeof(transports) / sizeof(transports[0]); i++) {
		if (strcmp(transports[i].name, name) == 0)
			return &transports[i];
	}
	return NULL;
}

int ta_transport_seal(const char *name, const unsigned char *key, const unsigned char *report,
                      size_t report_len, struct ta_sealed *out)
{
	const struct ta_transport *transport = ta_transport_lookup(name);

	if (transport == NULL)
		return TA_ERR;

	return transport->seal(key, report, report_len, (const unsigned char *)name, strlen(name), out); /*@PS c-l3-wrapper|AES-256-GCM|3|algorithm|AEAD reached only through the transport table */
}
