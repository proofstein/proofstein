/*
 * Payload sealing for attestation reports.
 *
 * Reports leave the device sealed under a per-boot key so that a report
 * captured off the wire cannot be replayed into a different enclave.
 */

#include "tinyattest.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

int ta_seal(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len,
            const unsigned char *aad, size_t aad_len, struct ta_sealed *out)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;
	int rc = TA_ERR;

	if (key == NULL || plaintext == NULL || out == NULL)
		return TA_ERR;

	if (RAND_bytes(out->nonce, TA_NONCE_BYTES) != 1)
		return TA_ERR;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return TA_ERR;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, out->nonce) != 1) /*@PS c-l1-aesgcm|AES-256-GCM|1|algorithm|attestation report AEAD */
		goto out;

	if (aad != NULL && aad_len > 0) {
		if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
			goto out;
	}

	if (EVP_EncryptUpdate(ctx, out->ciphertext, &len, plaintext, (int)plaintext_len) != 1)
		goto out;
	out->ciphertext_len = (size_t)len;

	if (EVP_EncryptFinal_ex(ctx, out->ciphertext + len, &len) != 1)
		goto out;
	out->ciphertext_len += (size_t)len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TA_TAG_BYTES, out->tag) != 1)
		goto out;

	rc = TA_OK;
out:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}

int ta_open(const unsigned char *key, const struct ta_sealed *sealed, const unsigned char *aad,
            size_t aad_len, unsigned char *plaintext, size_t *plaintext_len)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;
	int rc = TA_ERR;

	if (key == NULL || sealed == NULL || plaintext == NULL || plaintext_len == NULL)
		return TA_ERR;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return TA_ERR;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, sealed->nonce) != 1)
		goto out;

	if (aad != NULL && aad_len > 0) {
		if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
			goto out;
	}

	if (EVP_DecryptUpdate(ctx, plaintext, &len, sealed->ciphertext, (int)sealed->ciphertext_len) != 1)
		goto out;
	*plaintext_len = (size_t)len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TA_TAG_BYTES, (void *)sealed->tag) != 1)
		goto out;

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
		goto out;
	*plaintext_len += (size_t)len;

	rc = TA_OK;
out:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}
