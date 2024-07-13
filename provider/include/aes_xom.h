#ifndef OSSL_XOM_PROVIDER_AES_XOM_H
#define OSSL_XOM_PROVIDER_AES_XOM_H

#include "xom.h"
#include <openssl/provider.h>

#define bits(x) ((x) >> 3)

// The number of 'opcode' bytes before the immediate value starts in a "mov imm64 -> reg64" instruction
#define MOV_OPCODE_SIZE 2

#define AVX2_ALIGNMENT 32
#define AVX_ALIGNED __attribute__((aligned(AVX2_ALIGNMENT)))

#define AES_128_CTR_IV_SIZE bits(128)
#define AES_128_CTR_KEY_SIZE bits(128)
#define AES_128_CTR_BLOCK_SIZE bits(128)

#define make_aligned(alignment, ptr, len)   \
    void* backup_##ptr = NULL;              \
    if(((unsigned long)ptr) % alignment) {  \
        backup_##ptr = ptr;                 \
        ptr = aligned_alloc(alignment, (len & ~(alignment - 1)) + ((len % alignment) ? alignment : 0) );\
        memcpy(ptr, backup_##ptr, len);     \
    }

#define free_aligned(ptr, len)              \
    if(backup_##ptr) {                      \
        memcpy(backup_##ptr, ptr, len);     \
        free(ptr);                          \
    }

#define make_const_aligned(alignment, ptr, len)         \
    void* backup_##ptr = NULL;                          \
    if(((unsigned long)ptr) % alignment) {              \
        backup_##ptr = aligned_alloc(alignment, (len & ~(alignment - 1)) + ((len % alignment) ? alignment : 0) );\
        memcpy(backup_##ptr, ptr, len);                 \
        ptr = backup_##ptr;                             \
    }

#define free_const_aligned(ptr, len)        \
    if(backup_##ptr)                        \
        free(backup_##ptr);

#ifdef __cplusplus
extern "C" {
#else
#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

struct {
    OSSL_PROVIDER *dflt_provider;
    void *_padding;
    EVP_MAC *dflt_hmac;
    unsigned char has_vaes;
    unsigned char has_vpclmulqdq;
    unsigned char has_sha;
} typedef xom_provctx;

extern size_t __attribute__((section(".data")))
aes_aesni_gctr_linear(void *icb, void *x, void *y, unsigned int num_blocks);

extern void __attribute__((section(".data"))) aes_aesni_gctr_linear_end(void);

extern unsigned char aes_aesni_key_lo;
extern unsigned char aes_aesni_key_hi;

extern size_t __attribute__((section(".data")))
aes_vaes_gctr_linear(void *icb, void *x, void *y, unsigned int num_blocks);

extern void __attribute__((section(".data"))) aes_vaes_gctr_linear_end(void);

extern unsigned char aes_vaes_key_lo;
extern unsigned char aes_vaes_key_hi;

void setup_aesni_128_key(unsigned char *dest, const unsigned char *key);

void setup_vaes_128_key(unsigned char *dest, const unsigned char *key);

extern void get_H_unprotected(void *data);

static void __attribute__((optimize("O0"))) get_H(void *data) {
    asm volatile ("call *%0"::"r"(get_H_unprotected), "D"(data):
            "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
            "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
}

static size_t __attribute__((optimize("O0")))
call_aesni_implementation(void *icb, const void *x, void *y, unsigned int num_blocks, const void *aes_fun) {
    size_t ret;
    asm volatile ("call *%1" : "=a" (ret) : "r"(aes_fun), "D"(icb), "S" (x), "d"(y), "c"(num_blocks) : "r14", "r15", "r8",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
    "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
    return ret;
}

static size_t __attribute__((optimize("O0"), target("avx2")))
call_vaes_implementation(void *icb, const void *x, void *y, unsigned int num_blocks, const void *aes_fun) {
    size_t ret;
    asm volatile ("call *%1" : "=a" (ret) : "r"(aes_fun), "D"(icb), "S" (x), "d"(y), "c"(num_blocks)
            : "r14", "r15", "r8",
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9",
    "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15");
    return ret;
}

static inline size_t
call_aes_implementation(void *icb, const void *x, void *y, unsigned int num_blocks, const void *aes_fun,
                        unsigned char has_vaes) {
    return (has_vaes ? call_vaes_implementation : call_aesni_implementation)(icb, x, y, num_blocks, aes_fun);
}

// AES-128-CTR
const OSSL_PARAM *aes_128_ctr_gettable_params(void *provctx);

const OSSL_PARAM *aes_128_ctr_gettable_ctx_params(void *cctx, void *provctx);

const OSSL_PARAM *aes_128_ctr_settable_ctx_params(void *cctx, void *provctx);

int aes_128_ctr_init(void *vctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen,
                     const OSSL_PARAM __attribute__((unused)) params[]);

int aes_128_ctr_stream_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in,
                              size_t inl);

int aes_128_ctr_stream_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize);

int
aes_128_ctr_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inl);

int aes_128_ctr_get_ctx_params(void *vctx, OSSL_PARAM params[]);

int aes_128_ctr_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

void *aes_128_ctr_newctx(void *provctx);

void aes_128_ctr_freectx(void *vctx);

void *aes_128_ctr_dupctx(void *ctx);

int aes_128_ctr_get_params(OSSL_PARAM params[]);


// AES-128-GCM
int aes_128_gcm_einit(void *vctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[]);

int aes_128_gcm_dinit(void *vctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[]);

const OSSL_PARAM *aes_128_gcm_gettable_params(void *provctx);

const OSSL_PARAM *aes_128_gcm_gettable_ctx_params(void *cctx, void *provctx);

const OSSL_PARAM *aes_128_gcm_settable_ctx_params(void *cctx, void *provctx);

int aes_128_gcm_stream_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in,
                              size_t inl);

int aes_128_gcm_stream_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize);

int
aes_128_gcm_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inl);

int aes_128_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[]);

int aes_128_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

void *aes_128_gcm_newctx(void *provctx);

void aes_128_gcm_freectx(void *vctx);

void *aes_128_gcm_dupctx(void *ctx);

int aes_128_gcm_get_params(OSSL_PARAM params[]);

const extern OSSL_DISPATCH ossl_hmac_functions[];

extern unsigned char xom_provider_debug_prints;

extern int (*const printf_d)(const char *__restrict format, ...);

#define printf(...) if (xom_provider_debug_prints) printf_d(__VA_ARGS__);

void *subpage_pool_lock_into_xom(const unsigned char *data, size_t size);

void subpage_pool_free(void *data);

void destroy_subpage_pool(void);

#ifdef __cplusplus
}
#endif
#endif