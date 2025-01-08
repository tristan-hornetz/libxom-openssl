#include <malloc.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include "xom.h"
#include "aes_xom.h"

struct {
    unsigned char __attribute__((aligned(32))) oiv[AES_128_CTR_IV_SIZE];
    unsigned char __attribute__((aligned(32))) iv[AES_128_CTR_IV_SIZE];
    unsigned char __attribute__((aligned(32))) block[AES_128_CTR_BLOCK_SIZE];
    unsigned int *refcount;
    unsigned char block_offset;
    void *aes_fun;
    unsigned int num;
    union {
        unsigned int d;
        unsigned char b[sizeof(unsigned int)];
    } ctr;
    unsigned char has_vaes : 1;
    unsigned char marked : 1;
} typedef xom_aes_ctr_context;

_Static_assert(sizeof(((xom_aes_ctr_context * )NULL)->ctr) <= AES_128_CTR_IV_SIZE, "Counter is too large");


void *aes_128_ctr_newctx(void *provctx) {
    // TODO incorporate provider context, more efficient memory management

    xom_provctx* ctx = provctx;
    xom_aes_ctr_context *ret = aligned_alloc(AVX2_ALIGNMENT, sizeof(*ret));
    unsigned int *restrict refcount = malloc(sizeof(*refcount));

    memset(ret, 0, sizeof(*ret));

    *refcount = 1;

    *ret = (xom_aes_ctr_context) {
            .aes_fun = NULL,
            .refcount = refcount,
            .has_vaes = ctx->has_vaes,
    };

    return ret;
}

void aes_128_ctr_freectx(void *vctx) {
    xom_aes_ctr_context *ctx = (xom_aes_ctr_context *) vctx;

    if (!--((*(ctx->refcount)))) {
        subpage_pool_free(ctx->aes_fun);
        free(ctx->refcount);
        memset(ctx->iv, 0, sizeof(ctx->iv));
    }
    free(ctx);
}

void *aes_128_ctr_dupctx(void *ctx) {
    xom_aes_ctr_context *ret = malloc(sizeof(*ret));

    memcpy(ret, ctx, sizeof(*ret));
    (*ret->refcount)++;
    return ret;
}

/////////////////////////////////////
// Encryption/Decryption Functions //
/////////////////////////////////////

/**
 * OSSL_FUNC_cipher_encrypt_init() initialises a cipher operation for encryption given a newly created provider side
 * cipher context in the cctx parameter. The key to be used is given in key which is keylen bytes long. The IV to be
 * sed is given in iv which is ivlen bytes long. The params, if not NULL, should be set on the context in a manner
 * similar to using OSSL_FUNC_cipher_set_ctx_params().
 *
 * OSSL_FUNC_cipher_decrypt_init() is the same as OSSL_FUNC_cipher_encrypt_init() except that it initialises the context
 * for a decryption operation.
 */
int aes_128_ctr_init(void *vctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen,
                     const OSSL_PARAM __attribute__((unused)) params[]) {
    const size_t vaes_size = (unsigned char*)aes_vaes_gctr_linear_end - (unsigned char*)aes_vaes_gctr_linear;
    const size_t aesni_size = (unsigned char*)aes_aesni_gctr_linear_end - (unsigned char*)aes_aesni_gctr_linear;
    xom_aes_ctr_context *ctx = vctx;
    unsigned i;
    unsigned char* staging_buffer = aligned_alloc(SUBPAGE_SIZE,SUBPAGE_SIZE * (max(vaes_size, aesni_size) / SUBPAGE_SIZE + 1));

    if (keylen != AES_128_CTR_KEY_SIZE)
        return 0;
    if (ivlen != AES_128_CTR_IV_SIZE)
        return 0;

    memcpy(ctx->oiv, iv, AES_128_CTR_IV_SIZE);
    memcpy(ctx->iv, iv, AES_128_CTR_IV_SIZE);

    if(ctx->has_vaes)
        memcpy(staging_buffer, aes_vaes_gctr_linear, vaes_size);
    else
        memcpy(staging_buffer, aes_aesni_gctr_linear, aesni_size);

    (ctx->has_vaes ? setup_vaes_128_key : setup_aesni_128_key)(staging_buffer, key);

    for (i = 0; i < sizeof(ctx->ctr.d); i++)
        ctx->ctr.b[i] = ctx->iv[(sizeof(ctx->iv) - 1) - i];

    ctx->aes_fun = subpage_pool_lock_into_xom(staging_buffer, ctx->has_vaes ? vaes_size : aesni_size);

    free(staging_buffer);
    if(!ctx->aes_fun)
        return 0;

    return 1;
}

/**
 * OSSL_FUNC_cipher_update() is called to supply data to be encrypted/decrypted as part of a previously initialised
 * cipher operation. The cctx parameter contains a pointer to a previously initialised provider side context.
 * OSSL_FUNC_cipher_update() should encrypt/decrypt inl bytes of data at the location pointed to by in. The encrypted
 * data should be stored in out and the amount of data written to *outl which should not exceed outsize bytes.
 * OSSL_FUNC_cipher_update() may be called multiple times for a single cipher operation. It is the responsibility of the
 * cipher implementation to handle input lengths that are not multiples of the block length. In such cases a cipher
 * implementation will typically cache partial blocks of input data until a complete block is obtained. The pointers out
 * and in may point to the same location, in which case the encryption must be done in-place. If out and in point to
 * different locations, the requirements of EVP_EncryptUpdate(3) and EVP_DecryptUpdate(3) guarantee that the two buffers
 * are disjoint. Similarly, the requirements of EVP_EncryptUpdate(3) and EVP_DecryptUpdate(3) ensure that the buffer
 * pointed to by out contains sufficient room for the operation being performed.
 */
int aes_128_ctr_stream_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in,
                              size_t inl) {
    xom_aes_ctr_context* ctx = vctx;
    size_t c_outl;
    unsigned char AVX_ALIGNED inbuf[AVX2_ALIGNMENT];

    *outl = 0;

    // If we cannot fill a block, save for later
    if (inl + ctx->block_offset < AES_128_CTR_BLOCK_SIZE) {
        memcpy(ctx->block + ctx->block_offset, in, inl);
        ctx->block_offset += inl;
        return 1;
    }

    // Handle stuff left over from last call
    if(ctx->block_offset) {
        if(outsize < AES_128_CTR_BLOCK_SIZE)
            return 0;
        memcpy(inbuf, ctx->block, ctx->block_offset);
        memcpy(inbuf + ctx->block_offset, in, AES_128_CTR_BLOCK_SIZE - ctx->block_offset);
        if(1 != aes_128_ctr_cipher(vctx, out, &c_outl, AES_128_CTR_BLOCK_SIZE, inbuf, AES_128_CTR_BLOCK_SIZE))
            return 0;
        *outl = c_outl;
        in += AES_128_CTR_BLOCK_SIZE - ctx->block_offset;
        inl -= AES_128_CTR_BLOCK_SIZE - ctx->block_offset;
        out += AES_128_CTR_BLOCK_SIZE;
        outsize -= AES_128_CTR_BLOCK_SIZE;
    }

    // Handle remaining input blocks
    if (1 != aes_128_ctr_cipher(vctx, out, &c_outl, outsize, in, inl))
        return 0;
    *outl += c_outl;

    // Save left over stuff for later
    memcpy(ctx->block,
           in + (inl & ~(AES_128_CTR_BLOCK_SIZE - 1)),
           inl - (inl & ~(AES_128_CTR_BLOCK_SIZE - 1))
       );
    ctx->block_offset = inl - (inl & ~(AES_128_CTR_BLOCK_SIZE - 1));

    return 1;
}

/**
 * OSSL_FUNC_cipher_final() completes an encryption or decryption started through previous
 * OSSL_FUNC_cipher_encrypt_init() or OSSL_FUNC_cipher_decrypt_init(), and OSSL_FUNC_cipher_update() calls. The cctx
 * parameter contains a pointer to the provider side context. Any final encryption/decryption output should be written
 * to out and the amount of data written to *outl which should not exceed outsize bytes. The same expectations apply to
 * outsize as documented for EVP_EncryptFinal(3) and EVP_DecryptFinal(3).
 */
int aes_128_ctr_stream_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    xom_aes_ctr_context *ctx = vctx;
    unsigned char __attribute__((aligned(32))) inbuf[sizeof(ctx->block)];
    unsigned char __attribute__((aligned(32))) outbuf[sizeof(ctx->block)];
    *outl = 0;

    if (!ctx->block_offset)
        return 1;

    memcpy(inbuf, ctx->block, ctx->block_offset);
    memset(inbuf + ctx->block_offset, 0, sizeof(inbuf) - ctx->block_offset);

    while (call_aes_implementation(ctx->iv, inbuf, outbuf, 1, ctx->aes_fun, ctx->has_vaes));

    memcpy(out, outbuf, outsize < ctx->block_offset ? outsize : ctx->block_offset);
    *outl = outsize < ctx->block_offset ? outsize : ctx->block_offset;
    return 1;
}

/**
 * OSSL_FUNC_cipher_cipher() performs encryption/decryption using the provider side cipher context in the cctx parameter
 * that should have been previously initialised via a call to OSSL_FUNC_cipher_encrypt_init() or
 * OSSL_FUNC_cipher_decrypt_init(). This should call the raw underlying cipher function without any padding. This will
 * be invoked in the provider as a result of the application calling EVP_Cipher(3). The application is responsible for
 * ensuring that the input is a multiple of the block length. The data to be encrypted/decrypted will be in in, and it
 * will be inl bytes in length. The output from the encryption/decryption should be stored in out and the amount of data
 * stored should be put in *outl which should be no more than outsize bytes.
 */
int
aes_128_ctr_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inl) {
    xom_aes_ctr_context *ctx = vctx;
    unsigned num_in_blocks = inl / AES_128_CTR_BLOCK_SIZE, num_out_blocks =
            outsize / AES_128_CTR_BLOCK_SIZE, blocks_processed, i;
    make_aligned(32, out, num_in_blocks * AES_128_CTR_BLOCK_SIZE)
    make_const_aligned(32, in, num_in_blocks * AES_128_CTR_BLOCK_SIZE)

    if (!outl)
        return 0;
    *outl = 0;

    if (num_in_blocks > num_out_blocks)
        num_in_blocks = num_out_blocks;
    num_out_blocks = num_in_blocks;

    while (num_in_blocks) {
        blocks_processed = num_in_blocks - call_aes_implementation(
                ctx->iv,
                in + ((num_out_blocks - num_in_blocks) * AES_128_CTR_BLOCK_SIZE),
                out + ((num_out_blocks - num_in_blocks) * AES_128_CTR_BLOCK_SIZE),
                num_in_blocks,
                ctx->aes_fun,
                ctx->has_vaes
        );
        if (blocks_processed > num_in_blocks)
            break;
        num_in_blocks -= blocks_processed;
        ctx->ctr.d += blocks_processed;
        for (i = 0; i < sizeof(ctx->ctr.d); i++)
            ctx->iv[(sizeof(ctx->iv) - 1) - i] = ctx->ctr.b[i];
    }

    free_aligned(out, num_out_blocks * AES_128_CTR_BLOCK_SIZE)
    free_const_aligned(in, num_out_blocks * AES_128_CTR_BLOCK_SIZE)
    *outl = num_out_blocks * AES_128_CTR_BLOCK_SIZE;

    return 1;
}


/////////////////////////
// Cipher Parameters   //
/////////////////////////
/*
See OSSL_PARAM(3) for further details on the parameters structure used by these functions.
 */

#define flag_zero(FLAG)                         \
    p = OSSL_PARAM_locate(params, FLAG);        \
    if (p != NULL && !OSSL_PARAM_set_int(p, 0)) \
        return 0;                               \


/**
 * OSSL_FUNC_cipher_get_params() gets details of the algorithm implementation and stores them in params.
 */
int aes_128_ctr_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_CTR_MODE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_CTR_KEY_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_CTR_IV_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_CTR_BLOCK_SIZE))
        return 0;

    flag_zero(OSSL_CIPHER_PARAM_AEAD)
    flag_zero(OSSL_CIPHER_PARAM_CUSTOM_IV)
    flag_zero(OSSL_CIPHER_PARAM_CTS)
    flag_zero(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK)
    flag_zero(OSSL_CIPHER_PARAM_HAS_RAND_KEY)

    return 1;
}

/**
 * OSSL_FUNC_cipher_set_ctx_params() sets cipher operation parameters for the provider side cipher context cctx to
 * params. Any parameter settings are additional to any that were previously set. Passing NULL for params should return
 * true.
 */
int aes_128_ctr_set_ctx_params(void __attribute__((unused)) *vctx, const OSSL_PARAM __attribute__((unused)) params[]) {
    return 1;
}

/**
 * OSSL_FUNC_cipher_get_ctx_params() gets cipher operation details details from the given provider side cipher context
 * cctx and stores them in params. Passing NULL for params should return true.
 */
int aes_128_ctr_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    xom_aes_ctr_context *ctx = vctx;
    OSSL_PARAM *p;

    if (!params)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_CTR_KEY_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_CTR_IV_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 1))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->num))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, AES_128_CTR_IV_SIZE)
        && !OSSL_PARAM_set_octet_string(p, &ctx->oiv, AES_128_CTR_IV_SIZE)) {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, AES_128_CTR_IV_SIZE)
        && !OSSL_PARAM_set_octet_string(p, &ctx->iv, AES_128_CTR_IV_SIZE)) {
        return 0;
    }

    return 1;
}

/**
 * OSSL_FUNC_cipher_gettable_params(), OSSL_FUNC_cipher_gettable_ctx_params(), and OSSL_FUNC_cipher_settable_ctx_params()
 * all return constant OSSL_PARAM(3) arrays as descriptors of the parameters that OSSL_FUNC_cipher_get_params(),
 * OSSL_FUNC_cipher_get_ctx_params(), and OSSL_FUNC_cipher_set_ctx_params() can handle, respectively.
 * OSSL_FUNC_cipher_gettable_ctx_params() and OSSL_FUNC_cipher_settable_ctx_params() will return the parameters
 * associated with the provider side context cctx in its current state if it is not NULL. Otherwise, they return the
 * parameters associated with the provider side algorithm provctx.
 *
 * Parameters currently recognised by built-in ciphers are listed in "PARAMETERS" in EVP_EncryptInit(3). Not all
 * parameters are relevant to, or are understood by all ciphers.
 */

static const OSSL_PARAM cipher_known_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
        OSSL_PARAM_END
};

static const OSSL_PARAM cipher_known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_END
};

static const OSSL_PARAM cipher_known_settable_ctx_params[] = {
        OSSL_PARAM_END
};

const OSSL_PARAM *aes_128_ctr_gettable_params(void __attribute__((unused)) *provctx) {
    return cipher_known_gettable_params;
}

const OSSL_PARAM *
aes_128_ctr_gettable_ctx_params(void __attribute__((unused)) *cctx, void __attribute__((unused)) *provctx) {
    return cipher_known_gettable_ctx_params;
}

const OSSL_PARAM *
aes_128_ctr_settable_ctx_params(void __attribute__((unused)) *cctx, void __attribute__((unused)) *provctx) {
    return cipher_known_settable_ctx_params;
}
