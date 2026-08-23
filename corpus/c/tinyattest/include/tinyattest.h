/*
 * tinyattest -- attestation helper for field devices.
 *
 * The helper produces a signed, sealed attestation report and agrees a
 * post-quantum session key with the verifier.
 */

#ifndef TINYATTEST_H
#define TINYATTEST_H

#include <stddef.h>

#define TA_OK 0
#define TA_ERR (-1)

#define TA_KEY_BYTES 32
#define TA_NONCE_BYTES 12
#define TA_TAG_BYTES 16
#define TA_MAX_REPORT 4096
#define TA_DIGEST_BYTES 32

struct ta_sealed {
	unsigned char nonce[TA_NONCE_BYTES];
	unsigned char tag[TA_TAG_BYTES];
	unsigned char ciphertext[TA_MAX_REPORT];
	size_t ciphertext_len;
};

/* Report transports, resolved by name from etc/tinyattest.conf. */
struct ta_transport {
	const char *name;
	int (*seal)(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len,
	            const unsigned char *aad, size_t aad_len, struct ta_sealed *out);
};

/* seal.c */
int ta_seal(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len,
            const unsigned char *aad, size_t aad_len, struct ta_sealed *out);
int ta_open(const unsigned char *key, const struct ta_sealed *sealed, const unsigned char *aad,
            size_t aad_len, unsigned char *plaintext, size_t *plaintext_len);

/* transport.c */
const struct ta_transport *ta_transport_lookup(const char *name);
int ta_transport_seal(const char *name, const unsigned char *key, const unsigned char *report,
                      size_t report_len, struct ta_sealed *out);

/* digest.c */
int ta_report_digest(const unsigned char *report, size_t report_len, unsigned char *out);

/* identity.c */
struct ta_identity;
struct ta_identity *ta_identity_generate(void);
void ta_identity_free(struct ta_identity *identity);
int ta_identity_sign_report(struct ta_identity *identity, const unsigned char *report,
                            size_t report_len, unsigned char *signature, size_t *signature_len);

/* kem.c */
int ta_kem_keypair(unsigned char *public_key, size_t *public_key_len);

/* Long-term seals over provisioning records (src/seal_longterm.c). */
int ta_seal_record_keygen(unsigned char *public_key, size_t *public_key_len);
int ta_seal_firmware_keygen(unsigned char *public_key, size_t *public_key_len);

/* config.c */
struct ta_config {
	char transport[64];
	char report_cipher[64];
	char report_signature[64];
	char key_agreement[64];
	char digest[64];
};
int ta_config_load(const char *path, struct ta_config *out);

#endif /* TINYATTEST_H */
