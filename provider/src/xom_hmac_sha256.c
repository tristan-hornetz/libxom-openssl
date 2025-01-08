#define _GNU_SOURCE
#include <stdlib.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>
#include <ctype.h>
#include <immintrin.h>
#include "aes_xom.h"

typedef size_t (*hmac_fun) (
        void *__attribute__((aligned(0x20))) padded_msg,
        size_t block_count,
        void *__attribute__((aligned(0x20))) out,
        size_t resume_from_out);

extern void __attribute__((section(".data"))) hmac256_start();
extern void __attribute__((section(".data"))) hmac256_end();
extern size_t __attribute__((section(".data"))) hmac256(
        void *__attribute__((aligned(0x20))) padded_msg,
        size_t block_count,
        void *__attribute__((aligned(0x20))) out,
        size_t resume_from_out);

#define countof(x) (sizeof(x)/sizeof(*(x)))
#define min(x, y) ((x) < (y) ? (x) : (y))
#define keyptr(dst_buf, x) ( ((uint8_t*)dst_buf) + (((uint8_t*)(&(x))) - (uint8_t*)hmac256_start) + 2 )

#define HMAC_SHA256_BLOCK_SIZE  64
#define HMAC_SHA256_MAC_SIZE    32

// HMAC key
extern uint8_t quad0_key_lo;
extern uint8_t quad1_key_lo;
extern uint8_t quad2_key_lo;
extern uint8_t quad3_key_lo;

extern uint8_t quad0_key_hi;
extern uint8_t quad1_key_hi;
extern uint8_t quad2_key_hi;
extern uint8_t quad3_key_hi;

// Memory encryption parameters
extern uint8_t hmac_memenc_key_lo;
extern uint8_t hmac_memenc_key_hi;

extern uint8_t quad0_hkey;
extern uint8_t quad1_hkey;

struct {
    EVP_MAC_CTX* dflt_ctx;
    xom_provctx provctx;
    unsigned char* block;
    unsigned char* hash_state;
    unsigned int* refcount;
    unsigned int keylen;
    unsigned int bytes_compressed;
    struct xombuf* xbuf;
    hmac_fun hmac_fun;
    unsigned char block_offset;
    unsigned char use_passthrough : 1;
    unsigned char first_update : 1;
    unsigned char final_update : 1;
    unsigned char locked : 1;
    unsigned char marked : 1;
} typedef hmac_sha256_ctx;

static size_t __attribute__((optimize("O0"), target("avx2")))
call_hmac_implementation(const void *msg, size_t block_count, void *out, uint8_t resume_from_out,
                         uint8_t finish, const void* hmac_fun)
{
    size_t ret;
    asm volatile ("call *%1"
        : "=a" (ret)
        : "r"(hmac_fun), "D"(msg), "S" (block_count), "d"(out), "c" ((((size_t)resume_from_out) << 8) | finish)
        : "r14", "r15",
          "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12",
          "ymm13", "ymm14", "ymm15"
    );
    return ret;
}

static void set_hmac_sha256_keys(hmac_sha256_ctx* ctx, const void* key, size_t key_len) {
    const void* fn_base = *(void**)ctx->xbuf;
    uint8_t* const hmac_key_ptrs[] = {
            keyptr(fn_base, quad0_key_lo), keyptr(fn_base, quad1_key_lo),
            keyptr(fn_base, quad2_key_lo), keyptr(fn_base, quad3_key_lo),
            keyptr(fn_base, quad0_key_hi), keyptr(fn_base, quad1_key_hi),
            keyptr(fn_base, quad2_key_hi), keyptr(fn_base, quad3_key_hi),
    };
    uint8_t key_buf[64];
    unsigned i, j;

    if (!key)
        return;
    
    if (ctx->locked)
        return;

    memset(key_buf, 0, sizeof(key_buf));
    memcpy(key_buf, key, min(sizeof(key_buf), key_len));

    for (i = 0; i < countof(hmac_key_ptrs); i++) {
        for (j = 0; j < sizeof(uint64_t); j++) {
            hmac_key_ptrs[i][j] = key_buf[sizeof(uint64_t) * i + j];
        }
    }

    while(!_rdrand64_step((unsigned long long*) keyptr(fn_base, hmac_memenc_key_lo)));
    while(!_rdrand64_step((unsigned long long*) keyptr(fn_base, hmac_memenc_key_hi)));
}

static void *hmac_new(void *provctx) {
    hmac_sha256_ctx* ret = calloc(1, sizeof(*ret));

    memset(ret, 0, sizeof(*ret));

    ret->refcount = calloc(1, sizeof(*(ret->refcount)));
    *(ret->refcount) = 1;
    memcpy(&ret->provctx, provctx, sizeof(ret->provctx));
    ret->dflt_ctx = EVP_MAC_CTX_new(ret->provctx.dflt_hmac);
    ret->block = aligned_alloc(AVX2_ALIGNMENT, HMAC_SHA256_BLOCK_SIZE * 4);
    ret->hash_state = aligned_alloc(AVX2_ALIGNMENT, HMAC_SHA256_MAC_SIZE + AVX2_ALIGNMENT * 2);
    ret->keylen = 64;
    ret->xbuf = xom_alloc(PAGE_SIZE);
    ret->hmac_fun = (void*)(*(unsigned char**)ret->xbuf + ((unsigned char*)hmac256 - (unsigned char*)hmac256_start));
    ret->use_passthrough = 1;

    xom_write(ret->xbuf, hmac256_start, ((unsigned char*)hmac256_end - (unsigned char*)hmac256_start), 0);

    return ret;
}

static void hmac_free(void *vctx) {
    hmac_sha256_ctx* ctx = vctx;

    if(!--(*(ctx->refcount))){
        xom_free(ctx->xbuf);
        free(ctx->refcount);
        free(ctx->hash_state);
        free(ctx->block);
    }
    EVP_MAC_CTX_free(ctx->dflt_ctx);
    free(ctx);
}

static void *hmac_dup(void *vctx) {
     hmac_sha256_ctx* ctx = vctx;
     hmac_sha256_ctx* ret = calloc(1, sizeof(*ret));
     memcpy(ret, ctx, sizeof(*ret));
     ctx->dflt_ctx = EVP_MAC_CTX_dup(ctx->dflt_ctx);
     (*(ret->refcount))++;
     return ret;
}

static int hmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[]);

static int hmac_init(void *vctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[]) {
    hmac_sha256_ctx* ctx = vctx;
    if(params)
        hmac_set_ctx_params(vctx, params);

    if (ctx->use_passthrough)
        return EVP_MAC_init(ctx->dflt_ctx, key, keylen, params);

    if (key) {
        keylen = keylen ? keylen : ctx->keylen;
        ctx->keylen = keylen;

        set_hmac_sha256_keys(ctx, key, keylen);
    }

    xom_lock(ctx->xbuf);
    ctx->locked = 1;
    if(get_xom_mode() == XOM_MODE_SLAT && !ctx->marked) {
        if(xom_mark_register_clear(ctx->xbuf, 0, 0))
            return 0;
        ctx->marked = 1;
    }
    return 1;
}

static int hmac_update(void *vctx, const unsigned char *data, size_t datalen) {
    hmac_sha256_ctx* ctx = vctx;
    unsigned char AVX_ALIGNED inbuf[HMAC_SHA256_BLOCK_SIZE];

    if (ctx->use_passthrough)
        return EVP_MAC_update(ctx->dflt_ctx, data, datalen);

    // If we cannot fill a block, save for later
    if (datalen + ctx->block_offset < HMAC_SHA256_BLOCK_SIZE) {
        memcpy(ctx->block + ctx->block_offset, data, datalen);
        ctx->block_offset += datalen;
        return 1;
    }

    // Handle stuff left over from last call
    if(ctx->block_offset){
        memcpy(inbuf, ctx->block, ctx->block_offset);
        memcpy(inbuf + ctx->block_offset, data, HMAC_SHA256_BLOCK_SIZE - ctx->block_offset);
        call_hmac_implementation(inbuf, 1, ctx->hash_state, 1, 0, ctx->hmac_fun);
        data += HMAC_SHA256_BLOCK_SIZE - ctx->block_offset;
        datalen -= HMAC_SHA256_BLOCK_SIZE - ctx->block_offset;
        ctx->bytes_compressed += HMAC_SHA256_BLOCK_SIZE;
    }

    make_const_aligned(AVX2_ALIGNMENT, data, datalen);

    // Handle remaining input blocks
    call_hmac_implementation((void*) data, datalen / HMAC_SHA256_BLOCK_SIZE, ctx->hash_state, ctx->first_update, 0, ctx->hmac_fun);
    ctx->first_update = 1;
    ctx->bytes_compressed += datalen & ~(HMAC_SHA256_BLOCK_SIZE - 1);

    // Save left over stuff for later
    memcpy(ctx->block,
           data + (datalen & ~(HMAC_SHA256_BLOCK_SIZE - 1)),
           datalen - (datalen & ~(HMAC_SHA256_BLOCK_SIZE - 1))
       );
    ctx->block_offset = datalen - (datalen & ~(HMAC_SHA256_BLOCK_SIZE - 1));

    free_const_aligned(data, datalen);

    return 1;
}

// Add padding for SHA256
static int setup_padding(size_t bytes_compressed, uint8_t* first_non_data, uint8_t* final_block) {
    uint64_t L = (bytes_compressed << 3) + 0x200;
    unsigned i;
    int ret = 0;

    if (first_non_data - final_block > 48) {
        final_block += HMAC_SHA256_BLOCK_SIZE;
        ret = 1;
    }

    for (i = 0; i < sizeof(L); i++)
        final_block[HMAC_SHA256_BLOCK_SIZE - 1 - i] = ((uint8_t *) &L)[i];
    *first_non_data |= 0x80;

    return ret;
}

static int hmac_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    int input_extended;
    hmac_sha256_ctx* ctx = vctx;

    if (ctx->use_passthrough)
        return EVP_MAC_final(ctx->dflt_ctx, out, outl, outsize);

    *outl = HMAC_SHA256_MAC_SIZE;
    if(ctx->final_update)
        goto exit;

    // Setup padding
    memset(ctx->block + ctx->block_offset, 0, (2*HMAC_SHA256_BLOCK_SIZE) - ctx->block_offset);
    ctx->bytes_compressed += ctx->block_offset;
    input_extended = setup_padding(ctx->bytes_compressed,
                  ctx->block + (ctx->block_offset ? ctx->block_offset : 0),
                  ctx->block);

    call_hmac_implementation(
            (void*) ctx->block,
            input_extended ? 2 : 1,
            ctx->hash_state,
            ctx->first_update, 1, ctx->hmac_fun);

    ctx->final_update = 1;
exit:
    if(out)
        memcpy(out, ctx->hash_state, min(HMAC_SHA256_MAC_SIZE, outsize));

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_gettable_ctx_params(ossl_unused void *ctx,
                                                  ossl_unused void *provctx) {
    return known_gettable_ctx_params;
}

static int hmac_get_ctx_params(void *vmacctx, OSSL_PARAM params[])
{
    hmac_sha256_ctx* ctx = vmacctx;
    OSSL_PARAM *p;

    if(ctx->use_passthrough)
        return EVP_MAC_CTX_get_params(ctx->dflt_ctx, params);

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL
            && !OSSL_PARAM_set_size_t(p, HMAC_SHA256_MAC_SIZE))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL
            && !OSSL_PARAM_set_size_t(p, HMAC_SHA256_BLOCK_SIZE))
        return 0;

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_NOINIT, NULL),
    OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_ONESHOT, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_settable_ctx_params(ossl_unused void *ctx,
                                                  ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int hmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])
{
    hmac_sha256_ctx* ctx = vmacctx;
    const OSSL_PARAM *p;
    char md_spec[32];
    unsigned int i;

    if(!EVP_MAC_CTX_set_params(ctx->dflt_ctx, params))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p) {
        if((p->data_type != OSSL_PARAM_OCTET_STRING && p->data_type != OSSL_PARAM_UTF8_STRING) || !p->data)
            return 0;
        for (i = 0; i < sizeof(md_spec) - 1 && i < p->data_size && ((char*)p->data)[i]; i++)
            md_spec[i] = (char) toupper(((char*)p->data)[i]);
        md_spec[i] = '\0';
        if (memmem(p->data, p->data_size, "SHA256", 6) == 0 || memmem(p->data, p->data_size, "SHA2-256", 7) == 0)
            ctx->use_passthrough = 0;
        else 
            ctx->use_passthrough = 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p) {
        if(p->data_type != OSSL_PARAM_OCTET_STRING || !p->data)
            return 0;
        set_hmac_sha256_keys(ctx, p->data, p->data_size);
        ctx->keylen = min(64, p->data_size);
    }

    return 1;
}

#define fun(x) ((void(*)(void)) x)
#ifndef OSSL_DISPATCH_END
#define OSSL_DISPATCH_END {0, NULL}
#endif

const OSSL_DISPATCH ossl_hmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, fun(hmac_new) },
    { OSSL_FUNC_MAC_DUPCTX, fun(hmac_dup) },
    { OSSL_FUNC_MAC_FREECTX, fun(hmac_free) },
    { OSSL_FUNC_MAC_INIT, fun(hmac_init) },
    { OSSL_FUNC_MAC_UPDATE, fun(hmac_update) },
    { OSSL_FUNC_MAC_FINAL, fun(hmac_final) },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, fun(hmac_gettable_ctx_params) },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS, fun(hmac_get_ctx_params) },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, fun(hmac_settable_ctx_params) },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, fun(hmac_set_ctx_params) },
    OSSL_DISPATCH_END
};
