/*
 * Local attestation listener.
 *
 * Field tooling collects reports from the device over TLS on the local link.
 * The listener context is built here: one TLS 1.2 cipher list, finite-field
 * DH parameters for the DHE suite, and the key exchange groups offered for
 * TLS 1.3, post-quantum hybrid first.
 */

#include "tinyattest.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/ssl.h>

SSL_CTX *ta_tls_listener_ctx(void);

static EVP_PKEY *dh_params_by_group(const char *group)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	EVP_PKEY *params = NULL;
	OSSL_PARAM settings[2];

	if (ctx == NULL)
		return NULL;

	if (EVP_PKEY_paramgen_init(ctx) <= 0)
		goto out;

	settings[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0);
	settings[1] = OSSL_PARAM_construct_end();
	if (EVP_PKEY_CTX_set_params(ctx, settings) <= 0)
		goto out;

	if (EVP_PKEY_paramgen(ctx, &params) <= 0)
		params = NULL;

out:
	EVP_PKEY_CTX_free(ctx);
	return params;
}

SSL_CTX *ta_tls_listener_ctx(void)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	EVP_PKEY *dh = NULL;

	if (ctx == NULL)
		return NULL;

	if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384") != 1)
		goto fail;

	dh = dh_params_by_group("ffdhe3072");
	if (dh == NULL || SSL_CTX_set0_tmp_dh_pkey(ctx, dh) != 1) {
		EVP_PKEY_free(dh);
		goto fail;
	}

	if (SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519:secp256r1") != 1)
		goto fail;

	return ctx;

fail:
	SSL_CTX_free(ctx);
	return NULL;
}
