#include <malloc.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include "aes_xom.h"

//#define PRINT_DEBUG_INFO

#define AES_128_GCM_IV_SIZE bits(128)
#define AES_128_GCM_KEY_SIZE bits(128)
#define AES_128_GCM_BLOCK_SIZE bits(128)
#define AES_128_GCM_TAG_SIZE bits(128)

#define AES_128_GCM_BLOCK_SIZE_BITS (AES_128_GCM_BLOCK_SIZE << 3)

struct {
    unsigned char AVX_ALIGNED oiv[AES_128_GCM_IV_SIZE];
    unsigned char AVX_ALIGNED block[AES_128_GCM_BLOCK_SIZE];
    unsigned char AVX_ALIGNED tag[AES_128_GCM_TAG_SIZE];
    unsigned char AVX_ALIGNED J[AES_128_GCM_TAG_SIZE];
    __m128i AVX_ALIGNED H;
    __m128i AVX_ALIGNED hash_state;
    __m128i AVX_ALIGNED J0;
    union {
        unsigned int d;
        unsigned char b[sizeof(unsigned int)];
    } __attribute__((aligned(sizeof(unsigned int)))) ctr;
    void* Htable;
    unsigned char *aad;
    unsigned int *refcount;
    size_t ivlen;
    size_t aad_len;
    size_t num_ciphertext_blocks;
    unsigned char block_offset;
    void *aes_fun;
    unsigned char *staging_buffer;
    unsigned char decrypt: 1;
    unsigned char key_initialized: 1;
    unsigned char iv_initialized: 1;
    unsigned char first_update: 1;
    unsigned char has_h: 1;
    unsigned char has_vaes: 1;
    unsigned char has_vpclmulqdq : 1;
} typedef aes_128_gcm_context;

void gcm_init_avx(__m128i Htable[16], const uint64_t Xi[2]);
void gcm_ghash_avx(uint64_t Xi[2], const __m128i Htable[16], const uint8_t *inp, size_t len);

void gcm_init_clmul(__m128i Htable[16], const uint64_t Xi[2]);
void gcm_ghash_clmul(uint64_t Xi[2], const __m128i Htable[16], const uint8_t *inp,size_t len);

_Static_assert(sizeof(((aes_128_gcm_context * )NULL)->ctr) <= AES_128_GCM_IV_SIZE, "Counter is too large");

static int init_aad(aes_128_gcm_context *ctx, const unsigned char *data, size_t data_len) {
    size_t padded_size = (data_len & ~(128 - 1)) + ((data_len % 128) ? 128 : 0);

    if (ctx->aad)
        free(ctx->aad);

    ctx->aad = aligned_alloc(AVX2_ALIGNMENT, padded_size);
    ctx->aad_len = data_len;

    memset(ctx->aad + data_len, 0, padded_size - data_len);

    if(data)
        memcpy(ctx->aad, data, data_len);

    return 1;
}

void *aes_128_gcm_newctx(void *provctx) {
    xom_provctx* ctx = provctx;
    aes_128_gcm_context *ret = aligned_alloc(AVX2_ALIGNMENT, sizeof(aes_128_gcm_context));
    unsigned int *restrict refcount = malloc(sizeof(*refcount));

    memset(ret, 0, sizeof(*ret));

    *refcount = 1;

    *ret = (aes_128_gcm_context) {
            .aes_fun = NULL,
            .refcount = refcount,
            .Htable = aligned_alloc(AVX2_ALIGNMENT, sizeof(__m128i) * 16),
            .has_vaes = ctx->has_vaes,
            .has_vpclmulqdq = ctx->has_vpclmulqdq
    };

    return ret;
}

void aes_128_gcm_freectx(void *vctx) {
    aes_128_gcm_context *ctx = (aes_128_gcm_context *) vctx;

    if (!--(*(ctx->refcount))) {
        subpage_pool_free(ctx->aes_fun);
        if (ctx->staging_buffer)
            free(ctx->staging_buffer);
        free(ctx->refcount);
        if (ctx->aad)
            free(ctx->aad);
        if(ctx->Htable)
            free(ctx->Htable);
    }
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

void *aes_128_gcm_dupctx(void *ctx) {
    aes_128_gcm_context *ret = malloc(sizeof(*ret));

    memcpy(ret, ctx, sizeof(*ret));
    (*(ret->refcount))++;
    return ret;
}

/////////////////////////////////////
// Encryption/Decryption Functions //
/////////////////////////////////////

static inline __m128i ghash(aes_128_gcm_context* ctx, const void* in, const size_t num_blocks) {
    if(!num_blocks)
        return *(__m128i*) &ctx->hash_state;

    (ctx->has_vpclmulqdq ? gcm_ghash_avx : gcm_ghash_clmul)
        ((void*) &ctx->hash_state, ctx->Htable, in, num_blocks * AES_128_GCM_BLOCK_SIZE);

    return *(__m128i*) &ctx->hash_state;
}

static __m128i getJ0(aes_128_gcm_context *ctx) {
    __m128i J0 = _mm_set_epi64x(0, 0), length_block = _mm_set_epi64x(0, 0);
    const __m128i shuffle_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    if (ctx->ivlen == 12) {
        memcpy(&J0, ctx->oiv, ctx->ivlen);
        ((unsigned char *) &J0)[sizeof(J0) - 1] = 0x1;
    } else {
        J0 = ghash(ctx, ctx->oiv,
                   (ctx->ivlen / AES_128_GCM_BLOCK_SIZE) + ((ctx->ivlen % AES_128_GCM_BLOCK_SIZE) ? 1 : 0));
        *(uint64_t *) &length_block = ctx->ivlen * 8;
        length_block = _mm_shuffle_epi8(length_block, shuffle_mask);
        J0 = ghash(ctx, &length_block, 1);
        memset(&ctx->hash_state, 0, sizeof(ctx->hash_state));
    }
    return J0;
}


/**
 * OSSL_FUNC_cipher_encrypt_init() initialises a cipher operation for encryption given a newly created provider side
 * cipher context in the cctx parameter. The key to be used is given in key which is keylen bytes long. The IV to be
 * sed is given in iv which is ivlen bytes long. The params, if not NULL, should be set on the context in a manner
 * similar to using OSSL_FUNC_cipher_set_ctx_params().
 *
 * OSSL_FUNC_cipher_decrypt_init() is the same as OSSL_FUNC_cipher_encrypt_init() except that it initialises the context
 * for a decryption operation.
 */
int aes_128_gcm_einit(void *vctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM __attribute__((unused)) params[]) {
    const size_t vaes_size = (unsigned char*)aes_vaes_gctr_linear_end - (unsigned char*)aes_vaes_gctr_linear;
    const size_t aesni_size = (unsigned char*)aes_aesni_gctr_linear_end - (unsigned char*)aes_aesni_gctr_linear;
    aes_128_gcm_context *ctx = vctx;
    union { uint64_t u[2]; __m128i o;} AVX_ALIGNED H0;
    unsigned char AVX_ALIGNED zeroes[AVX2_ALIGNMENT];
    unsigned i;

    memset(zeroes, 0, sizeof(zeroes));

    if (key && keylen) {
        if(!ctx->staging_buffer)
            ctx->staging_buffer = aligned_alloc(SUBPAGE_SIZE,SUBPAGE_SIZE * (max(vaes_size, aesni_size) / SUBPAGE_SIZE + 1));

        if(ctx->has_vaes)
            memcpy(ctx->staging_buffer, aes_vaes_gctr_linear, vaes_size);
        else
            memcpy(ctx->staging_buffer, aes_aesni_gctr_linear, aesni_size);

        (ctx->has_vaes ? setup_vaes_128_key : setup_aesni_128_key)(ctx->staging_buffer, key);
        ctx->key_initialized = 1;

        if (!ctx->has_h) {
        memcpy(&ctx->H, key, sizeof(ctx->H));
        get_H(&ctx->H);

        // Prime Htable
        H0.o = ctx->H;

        asm (
            "bswapq %0\n"
            "bswapq %1\n"
            : "+r"(H0.u[0]), "+r"(H0.u[1])
        );
        (ctx->has_vpclmulqdq ? gcm_init_avx : gcm_init_clmul)(ctx->Htable, (void*) &H0);

        ctx->has_h = 1;
    }

    }
    if (iv) {
        ctx->ivlen = ivlen ? ivlen : ctx->ivlen;
        if (!ctx->ivlen)
            ctx->ivlen = 12;
        memcpy(ctx->oiv, iv, ctx->ivlen);
        ctx->iv_initialized = 1;
    }

    if (!(ctx->iv_initialized && ctx->key_initialized))
        return 1;

    if(ctx->staging_buffer) {
        ctx->aes_fun = subpage_pool_lock_into_xom(ctx->staging_buffer, ctx->has_vaes ? vaes_size : aesni_size);
        free(ctx->staging_buffer);
        ctx->staging_buffer = NULL;
    }

    // Build J0 and ICB
    ctx->J0 = getJ0(ctx);
    memcpy(ctx->J, &ctx->J0, sizeof(ctx->J));
    for (i = 0; i < sizeof(ctx->ctr.d); i++)
        ctx->ctr.b[i] = ((unsigned char *) &ctx->J0)[(sizeof(ctx->J0) - 1) - i];
    ctx->ctr.d += 1;
    for (i = 0; i < sizeof(ctx->ctr.d); i++)
        (ctx->J)[(sizeof(ctx->J) - 1) - i] = ctx->ctr.b[i];

    if (ctx->aad) {
        ctx->hash_state = ghash(
                ctx,
                ctx->aad,
                (ctx->aad_len / AES_128_GCM_BLOCK_SIZE) + ((ctx->aad_len % AES_128_GCM_BLOCK_SIZE) ? 1 : 0)
        );
    }

    return 1;
}

int aes_128_gcm_dinit(void *vctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[]) {
    aes_128_gcm_context *ctx = vctx;
    ctx->decrypt = 1;

    return aes_128_gcm_einit(vctx, key, keylen, iv, ivlen, params);
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
int aes_128_gcm_stream_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in,
                              size_t inl) {
    aes_128_gcm_context* ctx = vctx;
    size_t c_outl;
    unsigned char AVX_ALIGNED inbuf[AVX2_ALIGNMENT];

    *outl = 0;

    // Handle AAD if none present
    if (!ctx->first_update) {
        ctx->first_update = 1;
        if(!inl)
            return 1;
        if (inl < AES_128_GCM_BLOCK_SIZE) {
            init_aad(ctx, in, inl);
            ctx->hash_state = ghash(
                ctx,
                ctx->aad,
                (ctx->aad_len / AES_128_GCM_BLOCK_SIZE) + ((ctx->aad_len % AES_128_GCM_BLOCK_SIZE) ? 1 : 0)
            );
            return 1;
        }
    }

    // If we cannot fill a block, save for later
    if (inl + ctx->block_offset < AES_128_GCM_BLOCK_SIZE) {
        memcpy(ctx->block + ctx->block_offset, in, inl);
        ctx->block_offset += inl;
        return 1;
    }

    // Handle stuff left over from last call
    if(ctx->block_offset){
        if(outsize < AES_128_GCM_BLOCK_SIZE)
            return 0;
        memcpy(inbuf, ctx->block, ctx->block_offset);
        memcpy(inbuf + ctx->block_offset, in, AES_128_GCM_BLOCK_SIZE - ctx->block_offset);
        if(1 != aes_128_gcm_cipher(vctx, out, &c_outl, AES_128_GCM_BLOCK_SIZE, inbuf, AES_128_GCM_BLOCK_SIZE))
            return 0;
        *outl = c_outl;
        in += AES_128_GCM_BLOCK_SIZE - ctx->block_offset;
        inl -= AES_128_GCM_BLOCK_SIZE - ctx->block_offset;
        out += AES_128_GCM_BLOCK_SIZE;
        outsize -= AES_128_GCM_BLOCK_SIZE;
    }

    // Handle remaining input blocks
    if (1 != aes_128_gcm_cipher(vctx, out, &c_outl, outsize, in, inl))
        return 0;
    *outl += c_outl;

    // Save left over stuff for later
    memcpy(ctx->block,
           in + (inl & ~(AES_128_GCM_BLOCK_SIZE - 1)),
           inl - (inl & ~(AES_128_GCM_BLOCK_SIZE - 1))
       );
    ctx->block_offset = inl - (inl & ~(AES_128_GCM_BLOCK_SIZE - 1));

    return 1;
}

/**
 * OSSL_FUNC_cipher_final() completes an encryption or decryption started through previous
 * OSSL_FUNC_cipher_encrypt_init() or OSSL_FUNC_cipher_decrypt_init(), and OSSL_FUNC_cipher_update() calls. The cctx
 * parameter contains a pointer to the provider side context. Any final encryption/decryption output should be written
 * to out and the amount of data written to *outl which should not exceed outsize bytes. The same expectations apply to
 * outsize as documented for EVP_EncryptFinal(3) and EVP_DecryptFinal(3).
 */
int aes_128_gcm_stream_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    // TODO: avoid copying so much memory

    aes_128_gcm_context *ctx = vctx;
    const __m128i shuffle_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i AVX_ALIGNED tag_final_blocks[2];
    unsigned char AVX_ALIGNED outbuf[AVX2_ALIGNMENT];
    unsigned char AVX_ALIGNED tag_buf[AVX2_ALIGNMENT];
    int retval = 1;

    // Set up length block for hash
    ((uint64_t *) &tag_final_blocks[1])[0] =
            (ctx->num_ciphertext_blocks * AES_128_GCM_BLOCK_SIZE_BITS) + (ctx->block_offset * 8);
    ((uint64_t *) &tag_final_blocks[1])[1] = ctx->aad_len << 3;
    tag_final_blocks[1] = _mm_shuffle_epi8(tag_final_blocks[1], shuffle_mask);

    if (!ctx->block_offset) {
        // There is no data left over, so simply hash the length block
        ctx->hash_state = ghash(ctx, &tag_final_blocks[1], 1);
    } else {
        // Pad the remaining data, encrypt final block, and update hash state
        memcpy(tag_final_blocks, ctx->block, ctx->block_offset);
        memset((unsigned char *) tag_final_blocks + ctx->block_offset, 0,
               sizeof(tag_final_blocks[0]) - ctx->block_offset);

        while (call_aes_implementation(ctx->J, tag_final_blocks, outbuf, 1, ctx->aes_fun, ctx->has_vaes));

        memcpy(out, outbuf, outsize < ctx->block_offset ? outsize : ctx->block_offset);
        if (!ctx->decrypt)
            memcpy(tag_final_blocks, outbuf, ctx->block_offset);
        ctx->hash_state = ghash(ctx, tag_final_blocks, 2);
    }

    // Encrypt the final hash to obtain the tag
    while (call_aes_implementation(&ctx->J0, &ctx->hash_state, tag_buf, 1, ctx->aes_fun, ctx->has_vaes));

    if(!ctx->decrypt)
        memcpy(ctx->tag, tag_buf, sizeof(ctx->tag));

    *outl = ctx->block_offset;

    if (ctx->decrypt) {
        // If we decrypt, verify hash instead of updating the context
        // Use pxor instead of memcmp to guarantee that the code is free of timing side channels
        asm volatile (
                "xor %0, %0\n"
                "pxor %1, %2\n"
                "ptest %2, %2\n"
                "jnz .Lendcheck\n"
                "inc %0\n"
                ".Lendcheck:\n"
                : "=r" (retval)
                : "x"(*(__m128i *) tag_buf), "x"(*(__m128i *) ctx->tag)
                );
#ifdef PRINT_DEBUG_INFO
        printf("tag_buf: ");
        for(unsigned j = 0; j < sizeof(ctx->tag); j++)
            printf("%02x", tag_buf[j]);
        printf("\n");
        printf("ctx->tag: ");
        for(unsigned j = 0; j < sizeof(ctx->tag); j++)
            printf("%02x", (ctx->tag)[j]);
        printf("\n");
#endif
    }

    free(ctx->aad);
    ctx->aad = NULL;
    ctx->aad_len = 0;
    ctx->first_update = 0;
    ctx->block_offset = 0;
    ctx->num_ciphertext_blocks = 0;
    memset(&ctx->block, 0, sizeof(ctx->block));
    memset(&ctx->ctr, 0, sizeof(ctx->ctr));
    memset(&ctx->hash_state, 0, sizeof(ctx->hash_state));

    return retval;
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
aes_128_gcm_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inl) {
    const static size_t chunk_blocks = 0x800; // Process data in chunks to make use of cache for ghash
    aes_128_gcm_context *ctx = vctx;

    unsigned num_in_blocks = inl / AES_128_GCM_BLOCK_SIZE, num_out_blocks =
            outsize / AES_128_GCM_BLOCK_SIZE, blocks_processed, i;
    make_aligned(AVX2_ALIGNMENT, out, num_in_blocks * AES_128_GCM_BLOCK_SIZE)
    make_const_aligned(AVX2_ALIGNMENT, in, num_in_blocks * AES_128_GCM_BLOCK_SIZE)

    if (!outl)
        return 0;
    *outl = 0;

    if (num_in_blocks > num_out_blocks)
        num_in_blocks = num_out_blocks;
    num_out_blocks = num_in_blocks;

    while (num_in_blocks) {
        blocks_processed = min(num_in_blocks, chunk_blocks) - call_aes_implementation(
                ctx->J,
                in + ((num_out_blocks - num_in_blocks) * AES_128_GCM_BLOCK_SIZE),
                out + ((num_out_blocks - num_in_blocks) * AES_128_GCM_BLOCK_SIZE),
                min(num_in_blocks, chunk_blocks),
                ctx->aes_fun,
                ctx->has_vaes
        );
        if (blocks_processed > num_in_blocks)
            break;
        ctx->num_ciphertext_blocks += blocks_processed;

        ctx->hash_state = ghash(ctx, (ctx->decrypt ? in : out) + ((num_out_blocks - num_in_blocks) * AES_128_GCM_BLOCK_SIZE), blocks_processed);

        num_in_blocks -= blocks_processed;
        ctx->ctr.d += blocks_processed;
        for (i = 0; i < sizeof(ctx->ctr.d); i++)
            ctx->J[(sizeof(ctx->J) - 1) - i] = ctx->ctr.b[i];
    }

    free_aligned(out, num_out_blocks * AES_128_GCM_BLOCK_SIZE)
    free_const_aligned(in, num_out_blocks * AES_128_GCM_BLOCK_SIZE)
    *outl = num_out_blocks * AES_128_GCM_BLOCK_SIZE;

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
int aes_128_gcm_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_GCM_MODE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_GCM_KEY_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 12))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_GCM_BLOCK_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

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
int aes_128_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    aes_128_gcm_context *ctx = vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_get_size_t(p, &ctx->ivlen))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        memcpy(ctx->tag, p->data, min(p->data_size, sizeof(ctx->tag)));
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        init_aad(ctx, p->data, p->data_size);
    }

    // OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    // OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),

    return 1;
}

/**
 * OSSL_FUNC_cipher_get_ctx_params() gets cipher operation details details from the given provider side cipher context
 * cctx and stores them in params. Passing NULL for params should return true.
 */
int aes_128_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    aes_128_gcm_context *ctx = vctx;
    OSSL_PARAM *p;

    if (!params)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_GCM_KEY_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen ? ctx->ivlen : 12))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 1))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->ctr.d))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivlen)) {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, &ctx->J, ctx->ivlen)) {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AES_128_GCM_TAG_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, &ctx->tag, AES_128_GCM_TAG_SIZE)) {
        return 0;
    }

    // OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),

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
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        // OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
        // OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL, 0),
        OSSL_PARAM_END
};

static const OSSL_PARAM cipher_known_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
        //OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
        //OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
        OSSL_PARAM_END
};

const OSSL_PARAM *aes_128_gcm_gettable_params(void __attribute__((unused)) *provctx) {
    return cipher_known_gettable_params;
}

const OSSL_PARAM *
aes_128_gcm_gettable_ctx_params(void __attribute__((unused)) *cctx, void __attribute__((unused)) *provctx) {
    return cipher_known_gettable_ctx_params;
}

const OSSL_PARAM *
aes_128_gcm_settable_ctx_params(void __attribute__((unused)) *cctx, void __attribute__((unused)) *provctx) {
    return cipher_known_settable_ctx_params;
}

