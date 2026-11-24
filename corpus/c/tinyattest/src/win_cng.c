/*
 * Verifier pre-key agreement on Windows field units.
 *
 * The Windows build of the helper has no OpenSSL. It agrees the pre-key for the
 * verifier session through CNG, against the verifier's public key blob, and
 * hands the raw shared secret to the session setup.
 *
 * Built only for Windows: `make windows-check` compiles and links it with a
 * mingw-w64 cross compiler. On every other platform this file is empty.
 */

#ifdef _WIN32

#include <windows.h>
#include <bcrypt.h>

#define TA_WIN_OK 0
#define TA_WIN_ERR (-1)

int ta_win_agree_prekey(const unsigned char *verifier_blob, unsigned long verifier_blob_len,
                        unsigned char *secret, unsigned long secret_len, unsigned long *written);

int ta_win_agree_prekey(const unsigned char *verifier_blob, unsigned long verifier_blob_len,
                        unsigned char *secret, unsigned long secret_len, unsigned long *written)
{
	BCRYPT_ALG_HANDLE alg = NULL;
	BCRYPT_KEY_HANDLE own = NULL;
	BCRYPT_KEY_HANDLE verifier = NULL;
	BCRYPT_SECRET_HANDLE agreed = NULL;
	NTSTATUS status;
	int rc = TA_WIN_ERR;

	status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
	if (!BCRYPT_SUCCESS(status))
		return TA_WIN_ERR;

	status = BCryptGenerateKeyPair(alg, &own, 256, 0);
	if (!BCRYPT_SUCCESS(status))
		goto out;

	status = BCryptFinalizeKeyPair(own, 0);
	if (!BCRYPT_SUCCESS(status))
		goto out;

	status = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &verifier,
	                             (PUCHAR)verifier_blob, verifier_blob_len, 0);
	if (!BCRYPT_SUCCESS(status))
		goto out;

	status = BCryptSecretAgreement(own, verifier, &agreed, 0);
	if (!BCRYPT_SUCCESS(status))
		goto out;

	status = BCryptDeriveKey(agreed, BCRYPT_KDF_RAW_SECRET, NULL, secret, secret_len, written, 0);
	if (BCRYPT_SUCCESS(status))
		rc = TA_WIN_OK;

out:
	if (agreed != NULL)
		BCryptDestroySecret(agreed);
	if (verifier != NULL)
		BCryptDestroyKey(verifier);
	if (own != NULL)
		BCryptDestroyKey(own);
	BCryptCloseAlgorithmProvider(alg, 0);
	return rc;
}

#else

/* ISO C requires a translation unit to declare something. */
typedef int ta_win_cng_unused;

#endif /* _WIN32 */
