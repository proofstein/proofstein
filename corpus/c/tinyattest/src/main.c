/*
 * tinyattest -- produce one signed, sealed attestation report.
 */

#include "tinyattest.h"

#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>

#define DEFAULT_CONFIG "etc/tinyattest.conf"
#define SIGNATURE_MAX 128
#define KEM_PUBLIC_MAX 2048

static const char *report_body(void)
{
	return "tinyattest: device=field-0417 firmware=2.9.4 secureboot=1 rollback=0";
}

int main(int argc, char **argv)
{
	const char *config_path = (argc > 1) ? argv[1] : DEFAULT_CONFIG;
	struct ta_config config;
	struct ta_identity *identity = NULL;
	struct ta_sealed sealed;
	unsigned char key[TA_KEY_BYTES];
	unsigned char digest[TA_DIGEST_BYTES];
	unsigned char signature[SIGNATURE_MAX];
	unsigned char kem_public[KEM_PUBLIC_MAX];
	size_t signature_len = sizeof(signature);
	size_t kem_public_len = sizeof(kem_public);
	const char *report = report_body();
	size_t report_len = strlen(report);
	int rc = 1;

	if (ta_config_load(config_path, &config) != TA_OK) {
		fprintf(stderr, "tinyattest: cannot read config %s\n", config_path);
		return 1;
	}

	if (RAND_bytes(key, sizeof(key)) != 1) {
		fprintf(stderr, "tinyattest: no entropy\n");
		return 1;
	}

	identity = ta_identity_generate();
	if (identity == NULL) {
		fprintf(stderr, "tinyattest: cannot build device identity\n");
		return 1;
	}

	if (ta_report_digest((const unsigned char *)report, report_len, digest) != TA_OK) {
		fprintf(stderr, "tinyattest: digest failed\n");
		goto out;
	}

	if (ta_transport_seal(config.transport, key, (const unsigned char *)report, report_len,
	                      &sealed) != TA_OK) {
		fprintf(stderr, "tinyattest: seal failed for transport %s\n", config.transport);
		goto out;
	}

	if (ta_identity_sign_report(identity, (const unsigned char *)report, report_len, signature,
	                            &signature_len) != TA_OK) {
		fprintf(stderr, "tinyattest: sign failed\n");
		goto out;
	}

	if (ta_kem_keypair(kem_public, &kem_public_len) != TA_OK) {
		fprintf(stderr, "tinyattest: key agreement failed\n");
		goto out;
	}

	printf("report ready transport=%s cipher=%s sealed=%zuB sig=%zuB kem_public=%zuB digest=%02x%02x%02x%02x\n",
	       config.transport, config.report_cipher, sealed.ciphertext_len, signature_len,
	       kem_public_len, digest[0], digest[1], digest[2], digest[3]);
	rc = 0;

out:
	ta_identity_free(identity);
	return rc;
}
