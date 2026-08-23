/*
 * Device identity.
 *
 * A device carries an Ed25519 key for report signatures, a P-256 key for the
 * mutual TLS session to the verifier, and an RSA key that only exists because
 * the 2018 provisioning service still checks it.
 */

#include "tinyattest.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <stdlib.h>

struct ta_identity {
	EVP_PKEY *report_signing;
	EVP_PKEY *verifier_mtls;
	EVP_PKEY *provisioning;
};

static EVP_PKEY *generate_by_name(const char *name, unsigned int rsa_bits)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *key = NULL;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL)
		return NULL;

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto out;

	if (rsa_bits > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)rsa_bits) <= 0)
		goto out;

	if (EVP_PKEY_generate(ctx, &key) <= 0)
		key = NULL;

out:
	EVP_PKEY_CTX_free(ctx);
	return key;
}

static EVP_PKEY *generate_p256(void)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY *key = NULL;

	if (ctx == NULL)
		return NULL;

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto out;

	if (EVP_PKEY_CTX_set_group_name(ctx, "P-256") <= 0) /*@PS c-l1-ecdsa|ECDSA-P256|1|algorithm|verifier mutual TLS key */
		goto out;

	if (EVP_PKEY_generate(ctx, &key) <= 0)
		key = NULL;

out:
	EVP_PKEY_CTX_free(ctx);
	return key;
}

struct ta_identity *ta_identity_generate(void)
{
	struct ta_identity *identity = calloc(1, sizeof(*identity));

	if (identity == NULL)
		return NULL;

	identity->report_signing = generate_by_name("ED25519", 0); /*@PS c-l1-ed25519|Ed25519|1|algorithm|attestation report signing key */
	identity->verifier_mtls = generate_p256();
	identity->provisioning = generate_by_name("RSA", 2048); /*@PS c-l1-rsa|RSA-2048|1|algorithm|legacy provisioning service key */

	if (identity->report_signing == NULL || identity->verifier_mtls == NULL ||
	    identity->provisioning == NULL) {
		ta_identity_free(identity);
		return NULL;
	}
	return identity;
}

void ta_identity_free(struct ta_identity *identity)
{
	if (identity == NULL)
		return;
	EVP_PKEY_free(identity->report_signing);
	EVP_PKEY_free(identity->verifier_mtls);
	EVP_PKEY_free(identity->provisioning);
	free(identity);
}

int ta_identity_sign_report(struct ta_identity *identity, const unsigned char *report,
                            size_t report_len, unsigned char *signature, size_t *signature_len)
{
	EVP_MD_CTX *ctx = NULL;
	int rc = TA_ERR;

	if (identity == NULL || report == NULL || signature == NULL || signature_len == NULL)
		return TA_ERR;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return TA_ERR;

	/* Ed25519 signs the message directly; no separate digest step. */
	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, identity->report_signing) != 1)
		goto out;

	if (EVP_DigestSign(ctx, signature, signature_len, report, report_len) != 1)
		goto out;

	rc = TA_OK;
out:
	EVP_MD_CTX_free(ctx);
	return rc;
}
