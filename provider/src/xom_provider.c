#include <string.h>
#include <cpuid.h>
#include <stdio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

int (*const printf_d) (const char *__restrict format, ...) = printf;
#include "aes_xom.h"

#ifndef OSSL_DISPATCH_END
#define OSSL_DISPATCH_END {0, NULL}
#endif

#define PROVIDER_DEBUG_FLAG "LIBXOM_PROVIDER_DEBUG"
#define PROVIDER_NO_HMAC_FLAG "LIBXOM_PROVIDER_NO_HMAC"
#define PROVIDER_NAME "xom"
#define countof(x) (sizeof(x) / sizeof((x)[0]))

extern char **__environ;
unsigned char xom_provider_debug_prints = 0;
unsigned char xom_hmac_disabled = 0;

static OSSL_ALGORITHM *default_algorithms[OSSL_OP__HIGHEST + 1];

static OSSL_ALGORITHM empty_algo[] = {
        {NULL, NULL, NULL, NULL},
};

const static unsigned opcodes[] = {
        OSSL_OP_DIGEST,
        OSSL_OP_CIPHER,
        OSSL_OP_MAC,
        OSSL_OP_KDF,
        OSSL_OP_RAND,
        OSSL_OP_KEYMGMT,
        OSSL_OP_KEYEXCH,
        OSSL_OP_SIGNATURE,
        OSSL_OP_ASYM_CIPHER,
        OSSL_OP_KEM,
        OSSL_OP_ENCODER,
        OSSL_OP_DECODER,
        OSSL_OP_STORE,
};

/* Parameters we provide to the core */
static const OSSL_PARAM xom_param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END
};

static size_t count_algos(const OSSL_ALGORITHM *algos) {
    size_t ret = 0;
    while (algos->algorithm_names) {
        algos++;
        ret++;
    }
    return ret + 1;
}

static const OSSL_PARAM *xom_gettable_params(const OSSL_PROVIDER *prov) {
    return xom_param_types;
}

static int xom_get_params(const OSSL_PROVIDER *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "XOM Provider for OpenSSL"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

#define fun(x) ((void(*)(void)) (x))

const static OSSL_DISPATCH aes_128_ctr_functions[] = {
        {OSSL_FUNC_CIPHER_NEWCTX, fun(aes_128_ctr_newctx)},
        {OSSL_FUNC_CIPHER_FREECTX, fun(aes_128_ctr_freectx)},
        {OSSL_FUNC_CIPHER_DUPCTX, fun(aes_128_ctr_dupctx)},
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, fun(aes_128_ctr_init)},
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, fun(aes_128_ctr_init)},
        {OSSL_FUNC_CIPHER_UPDATE, fun(aes_128_ctr_stream_update)},
        {OSSL_FUNC_CIPHER_FINAL, fun(aes_128_ctr_stream_final)},
        {OSSL_FUNC_CIPHER_CIPHER, fun(aes_128_ctr_cipher)},
        {OSSL_FUNC_CIPHER_GET_PARAMS, fun(aes_128_ctr_get_params)},
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, fun(aes_128_ctr_get_ctx_params)},
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, fun(aes_128_ctr_set_ctx_params)},
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, fun(aes_128_ctr_gettable_params)},
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, fun(aes_128_ctr_gettable_ctx_params)},
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, fun(aes_128_ctr_settable_ctx_params)},
        OSSL_DISPATCH_END
};

const static OSSL_DISPATCH aes_128_gcm_functions[] = {
        {OSSL_FUNC_CIPHER_NEWCTX, fun(aes_128_gcm_newctx)},
        {OSSL_FUNC_CIPHER_FREECTX, fun(aes_128_gcm_freectx)},
        {OSSL_FUNC_CIPHER_DUPCTX, fun(aes_128_gcm_dupctx)},
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, fun(aes_128_gcm_einit)},
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, fun(aes_128_gcm_dinit)},
        {OSSL_FUNC_CIPHER_UPDATE, fun(aes_128_gcm_stream_update)},
        {OSSL_FUNC_CIPHER_FINAL, fun(aes_128_gcm_stream_final)},
        {OSSL_FUNC_CIPHER_CIPHER, fun(aes_128_gcm_cipher)},
        {OSSL_FUNC_CIPHER_GET_PARAMS, fun(aes_128_gcm_get_params)},
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, fun(aes_128_gcm_get_ctx_params)},
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, fun(aes_128_gcm_set_ctx_params)},
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, fun(aes_128_gcm_gettable_params)},
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, fun(aes_128_gcm_gettable_ctx_params)},
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, fun(aes_128_gcm_settable_ctx_params)},
        OSSL_DISPATCH_END
};

#undef fun

static const OSSL_ALGORITHM *provider_query_operation(void *provctx, int operation_id, const int *no_store) {
    if (operation_id >= countof(default_algorithms) || operation_id < 0)
        return NULL;

    return default_algorithms[operation_id];
}


static int xom_get_capabilities(void *provctx, const char *capability,
                                OSSL_CALLBACK *cb, void *arg) {
    xom_provctx *ctx = provctx;
    return OSSL_PROVIDER_get_capabilities(ctx->dflt_provider, capability, cb, arg);
}


static void xom_teardown(void *provctx) {
    xom_provctx *ctx = provctx;
    unsigned i;

    if(ctx->dflt_hmac)
        EVP_MAC_free(ctx->dflt_hmac);

    if (ctx->dflt_provider)
        OSSL_PROVIDER_unload(ctx->dflt_provider);

    for (i = 0; i < countof(default_algorithms); i++)
        if (default_algorithms[i])
            free(default_algorithms[i]);

    free(provctx);
    destroy_subpage_pool();
}

static const OSSL_DISPATCH xom_dispatch_table[] = {
        {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) xom_teardown},
        {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void)) xom_gettable_params},
        {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void)) xom_get_params},
        {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) provider_query_operation},
        {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void)) xom_get_capabilities},
        OSSL_DISPATCH_END
};

static void discover_hardware_support(xom_provctx* ctx) {
    size_t a, b, c, d;

    __cpuid_count(0x7, 0, a, b, c, d);
    ctx->has_vaes = (c >> 9) & 1;
    ctx->has_vpclmulqdq = (c >> 10) & 1;
    ctx->has_sha = xom_hmac_disabled ? 0 : ((b >> 29) & 1);
}

static void check_xom_mode() {
    switch(get_xom_mode()){
        case 1:
            printf("Using PKU for XOM enforcement!\n");
            return;
        case 2:
            printf("Using EPT/SLAT for XOM enforcement!\n");
            return;
        default:;
    }
    printf("XOM is not supported!\n");
}

static void process_environment_vars() {
    char **envp;

    for(envp = __environ; envp && *envp; envp++) {
        if (strstr(*envp, PROVIDER_DEBUG_FLAG "=1"))
            xom_provider_debug_prints = 1;
        if (strstr(*envp, PROVIDER_NO_HMAC_FLAG "=1"))
            xom_hmac_disabled = 1;
    }
}

extern int
OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx) {
    unsigned i, j;
    int no_cache = 1;
    size_t algo_count;
    const OSSL_ALGORITHM *algo;
    xom_provctx *local_provctx = calloc(1, sizeof(*local_provctx));
    OSSL_ALGORITHM hmac_entry = {
            "HMAC",
            "provider=xom",
            ossl_hmac_functions,
            "Wrapper for XOM-protected HMAC/SHA256"
    };
    const static OSSL_ALGORITHM aes_128_gcm_entry = {
            "AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6",
            "provider=" PROVIDER_NAME,
            aes_128_gcm_functions,
            "XOM-protected implementation of AES-128-GCM"
    };
    const static OSSL_ALGORITHM aes_128_ctr_entry ={
            "AES-128-CTR",
            "provider=" PROVIDER_NAME,
            aes_128_ctr_functions,
            "XOM-protected implementation of AES-128-CTR"
    };

    memset(default_algorithms, 0, sizeof(default_algorithms));
    process_environment_vars();

    local_provctx->dflt_provider = OSSL_PROVIDER_load(NULL, "default");
    local_provctx->dflt_hmac = EVP_MAC_fetch(NULL, "HMAC", "provider=default");

    discover_hardware_support(local_provctx);

    // Simply re-export algorithms from the default provider for compatibility, but override
    // entries that we implement ourselves
    for (i = 0; i < countof(opcodes); i++) {
        algo = OSSL_PROVIDER_query_operation(local_provctx->dflt_provider, (int) opcodes[i], &no_cache);
        if (!algo) {
            default_algorithms[opcodes[i]] = empty_algo;
            continue;
        }

        algo_count = count_algos(algo);
        default_algorithms[opcodes[i]] = calloc(algo_count, sizeof(*default_algorithms[0]));
        memcpy(default_algorithms[opcodes[i]], algo, algo_count * sizeof(*default_algorithms[0]));


        for (j = 0; j < algo_count - 1; j++) {
            default_algorithms[opcodes[i]][j].property_definition = "provider=" PROVIDER_NAME;
            if(opcodes[i] == OSSL_OP_CIPHER) {
                if(strstr(default_algorithms[opcodes[i]][j].algorithm_names, "AES-128-GCM") != NULL)
                    default_algorithms[opcodes[i]][j] = aes_128_gcm_entry;
                else if(strstr(default_algorithms[opcodes[i]][j].algorithm_names, "AES-128-CTR") != NULL)
                    default_algorithms[opcodes[i]][j] = aes_128_ctr_entry;
            }
            if(!local_provctx->has_sha)
                continue;
            if(opcodes[i] == OSSL_OP_MAC) {
                if(strstr(default_algorithms[opcodes[i]][j].algorithm_names, "HMAC") != NULL)
                    default_algorithms[opcodes[i]][j] = hmac_entry;
            }
        }

    }

    EVP_set_default_properties(NULL, "provider=xom");
    printf("If you can read this, the XOM provider was successfully initialized!\n");
    printf("Using %s-based implementation!\n", local_provctx->has_vaes ? "VAES" : "AES-NI");
    if(!local_provctx->has_sha)
        printf("SHA instructions are not supported - not exporting HMAC implementation!\n");
    check_xom_mode();

    *out = xom_dispatch_table;
    *provctx = local_provctx;

    return 1;
}
