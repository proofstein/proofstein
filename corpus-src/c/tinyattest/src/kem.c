/*
 * Session key agreement with the verifier.
 *
 * Attestation transcripts are archived for the lifetime of the fleet, so the
 * session key is agreed post-quantum rather than over P-256 ECDH.
 */

#include "tinyattest.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>

int ta_kem_keypair(unsigned char *public_key, size_t *public_key_len)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *key = NULL;
	int rc = TA_ERR;

	if (public_key == NULL || public_key_len == NULL)
		return TA_ERR;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-512", NULL); /*@PS c-l1-mlkem|ML-KEM-512|1|algorithm|verifier session key agreement */
	if (ctx == NULL)
		return TA_ERR;

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto out;

	if (EVP_PKEY_generate(ctx, &key) <= 0)
		goto out;

	if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, public_key,
	                                    *public_key_len, public_key_len) != 1)
		goto out;

	rc = TA_OK;
out:
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
	return rc;
}
