/*
 * Long-term seals over provisioning records.
 *
 * A provisioning record is written once when a device leaves the line and is
 * verified for the service life of the fleet, which is longer than any signing
 * key we would rotate. The seal is therefore stateful hash-based: its security
 * rests on the hash function alone, and the parameters fix the number of
 * signatures at key generation time.
 *
 * The one-time key index must never be reused, so the sealer owns its key file
 * exclusively and the provisioning station runs one sealer per device batch.
 */

#include "tinyattest.h"

#include <wolfssl/wolfcrypt/lms.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/xmss.h>

/* LmsKey and XmssKey are forward declarations in the public headers above; the
 * struct definitions live here. Both keys are stack-allocated below, so these
 * are required, and they are what wolfSSL's own tests and benchmarks include. */
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/wc_xmss.h>

/* Single tree of height 10: 1024 records before the key is exhausted, which is
 * one production batch with margin. */
#define TA_RECORD_SEAL_PARAMS "XMSS-SHA2_10_256"

int ta_seal_record_keygen(unsigned char *public_key, size_t *public_key_len)
{
	XmssKey key;
	WC_RNG rng;
	word32 pub_len;
	int rc = TA_ERR;

	if (public_key == NULL || public_key_len == NULL)
		return TA_ERR;

	if (wc_InitRng(&rng) != 0)
		return TA_ERR;

	if (wc_XmssKey_Init(&key, NULL, INVALID_DEVID) != 0)
		goto out_rng;

	if (wc_XmssKey_SetParamStr(&key, TA_RECORD_SEAL_PARAMS) != 0)
		goto out_key;

	if (wc_XmssKey_MakeKey(&key, &rng) != 0)
		goto out_key;

	/* ExportPub copies one key into another; the buffer form is ExportPubRaw.
	 * Its length is a word32, so it round-trips through a local rather than
	 * casting the caller's size_t pointer, which is a different width here. */
	pub_len = (word32)*public_key_len;
	if (wc_XmssKey_ExportPubRaw(&key, public_key, &pub_len) != 0)
		goto out_key;

	*public_key_len = pub_len;
	rc = TA_OK;

out_key:
	wc_XmssKey_Free(&key);
out_rng:
	wc_FreeRng(&rng);
	return rc;
}

/* Two-level scheme for the firmware manifest: a larger signature, in exchange
 * for a key the field station never has to re-provision. */
int ta_seal_firmware_keygen(unsigned char *public_key, size_t *public_key_len)
{
	LmsKey key;
	WC_RNG rng;
	word32 pub_len;
	int rc = TA_ERR;

	if (public_key == NULL || public_key_len == NULL)
		return TA_ERR;

	if (wc_InitRng(&rng) != 0)
		return TA_ERR;

	if (wc_LmsKey_Init(&key, NULL, INVALID_DEVID) != 0)
		goto out_rng;

	if (wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8) != 0)
		goto out_key;

	if (wc_LmsKey_MakeKey(&key, &rng) != 0)
		goto out_key;

	pub_len = (word32)*public_key_len;
	if (wc_LmsKey_ExportPubRaw(&key, public_key, &pub_len) != 0)
		goto out_key;

	*public_key_len = pub_len;
	rc = TA_OK;

out_key:
	wc_LmsKey_Free(&key);
out_rng:
	wc_FreeRng(&rng);
	return rc;
}
