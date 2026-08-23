/*
 * Report digests.
 *
 * The EVP digest entry points are behind local macros so the helper can be
 * built against the vendored mbedTLS shim on the two platforms that still
 * lack a system OpenSSL. See docs/porting.md.
 */

#include "tinyattest.h"

#include <openssl/evp.h>

#define ta_md_ctx_new EVP_MD_CTX_new
#define ta_md_ctx_free EVP_MD_CTX_free
#define ta_md_sha256 EVP_sha256

int ta_report_digest(const unsigned char *report, size_t report_len, unsigned char *out)
{
	EVP_MD_CTX *ctx = NULL;
	unsigned int len = 0;
	int rc = TA_ERR;

	if (report == NULL || out == NULL)
		return TA_ERR;

	ctx = ta_md_ctx_new();
	if (ctx == NULL)
		return TA_ERR;

	if (EVP_DigestInit_ex(ctx, ta_md_sha256(), NULL) != 1)
		goto out;

	if (EVP_DigestUpdate(ctx, report, report_len) != 1)
		goto out;

	if (EVP_DigestFinal_ex(ctx, out, &len) != 1)
		goto out;

	rc = (len == TA_DIGEST_BYTES) ? TA_OK : TA_ERR;
out:
	ta_md_ctx_free(ctx);
	return rc;
}
