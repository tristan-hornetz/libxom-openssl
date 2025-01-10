#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <cpuid.h>
#include <unistd.h>
#include <libgen.h>
#include <syscall.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <perfmon/pfmlib.h>
#include <perfmon/pfmlib_perf_event.h>
//#include <linux/perf_event.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/core_names.h>


#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define CYN "\e[0;36m"
#define YLL "\033[33m"
#define CRESET "\e[0m"
#define STR_WARN "[" YLL "WARNING" CRESET "] "
#define STR_OK "[" GRN "+" CRESET "] "
#define STR_PEND "[" CYN "*" CRESET "] "
#define STR_FAIL "[" RED "-" CRESET "] "

#define TSC_PROCESSOR "Intel Core i5 13600kf"
#define TSC_DENOMINATOR 0x2
#define TSC_NUMERATOR 0xb6
#define TSC_CRYSTAL_FREQUENCY 0x249f000

#define ALDER_LAKE_MEM_STALLS_L1D_MISS "r347"
#define ALDER_LAKE_MEM_STALLS_L3_MISS "r947"
#define ALDER_LAKE_STALLS_TOTAL "r4a3"
#define ALDER_LAKE_BOUND_ON_LOAD "r21a6"
#define ALDER_LAKE_STALLS "r1b1"
#define ALDER_LAKE_STALLS_SB "r8a2"
#define ALDER_LAKE_L1D_MISS_PENDING_CYCLES "r148"
#define ALDER_LAKE_L1D_MISS_L2_STALLS "r448"
#define ALDER_LAKE_STLB_MISS_LOADS "r11d0"

#define TEST_PROV "xom"
#define TEST_CHUNK_SIZE (1 << 28)
#define GIGABYTE        (1 << 30)
#define NUM_REPEATS     0x80
#define countof(x)      (sizeof(x)/sizeof(*(x)))
#define min(x, y)       ((x) < (y) ? (x) : (y))

const static unsigned char test_key[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
const static unsigned char test_iv[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

static uint32_t tsc_denominator = 0, tsc_numerator = 0, tsc_crystal_frequency = 0;
static char cpu_ident[49] = {0, };

#define tsc_to_seconds(x) (tsc_numerator && tsc_numerator && tsc_crystal_frequency ? (              \
    (double)(x) / ((double)tsc_crystal_frequency * ((double)tsc_numerator/(double)tsc_denominator)) \
    ) : 0.0)

struct cipher_benchmark {
    const char* cipher_spec;
    EVP_CIPHER* test_cipher;
    EVP_CIPHER* verify_cipher;
} typedef cipher_benchmark;

struct mac_benchmark {
    const char* mac_spec;
    const char* hash_spec;
    EVP_MAC* test_mac;
    EVP_MAC* verify_mac;
} typedef mac_benchmark;

static uint64_t rdtsc(void) {
    uint64_t a, d;
    asm volatile("mfence\nrdtsc" : "=a"(a), "=d"(d));
    return a | (d << 32);
}

static int perf_fd;
static unsigned long perf_test[NUM_REPEATS];
static unsigned long perf_verify[NUM_REPEATS];

static void get_cpu_ident(char o[49]){
    uint64_t a, b, c, d;
    uint32_t* out = (uint32_t*) o;
    unsigned i;

    for(i = 0; i < 3; i++) {
        __cpuid(0x80000002ul + i, a, b, c, d);
        out[i * 4] = a;
        out[i * 4 + 1] = b;
        out[i * 4 + 2] = c;
        out[i * 4 + 3] = d;
    }

    o[48] = 0;
}

static const unsigned char has_sha(void) {
     size_t a, b, c, d;

    __cpuid_count(0x7, 0, a, b, c, d);
    return ((b >> 29) & 1);
}

static void get_tsc_freq(void) {
    uint32_t _d;
    __cpuid_count(0x15, 0, tsc_denominator, tsc_numerator, tsc_crystal_frequency, _d);

    if (tsc_numerator && tsc_numerator && tsc_crystal_frequency)
        return;

    puts(STR_WARN "Could not determine TSC frequency. Resorting to predefined values for the " TSC_PROCESSOR);
    tsc_numerator = TSC_NUMERATOR;
    tsc_denominator = TSC_DENOMINATOR;
    tsc_crystal_frequency = TSC_CRYSTAL_FREQUENCY;
}

static void __attribute__((noreturn)) handle_error(const char *msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static int get_random_data(unsigned char* dst, size_t size) {
    int status = -1;
    FILE* rand = fopen("/dev/urandom", "r");

    if(!rand || !~(uintptr_t)rand)
        return -1;

    if (fread(dst, size, 1, rand) != 1)
        goto exit;

    status = 0;
exit:
    fclose(rand);
    return status;
}

static OSSL_PROVIDER* get_xom_provider() {
    size_t cwdlen;
    char provider_path[PATH_MAX];

    getcwd(provider_path, sizeof(provider_path));
    cwdlen = strnlen(provider_path, sizeof(provider_path));
    strncpy(provider_path + cwdlen, "/libxom_provider.so", sizeof(provider_path) - cwdlen);

    return OSSL_PROVIDER_load(NULL, provider_path);
}

static int init_cipher_benchmark(cipher_benchmark* benchmark) {
    benchmark->test_cipher = EVP_CIPHER_fetch(NULL, benchmark->cipher_spec, "provider=" TEST_PROV);
    benchmark->verify_cipher = EVP_CIPHER_fetch(NULL, benchmark->cipher_spec, "provider=default");

    return benchmark->test_cipher && benchmark->verify_cipher;
}

static int init_mac_benchmark(mac_benchmark* benchmark) {
    benchmark->test_mac = EVP_MAC_fetch(NULL, benchmark->mac_spec, "provider=" TEST_PROV);
    benchmark->verify_mac = EVP_MAC_fetch(NULL, benchmark->mac_spec, "provider=default");

    return benchmark->test_mac && benchmark->verify_mac;
}

static void free_cipher_benchmark(cipher_benchmark* benchmark){
    if (benchmark->test_cipher)
        EVP_CIPHER_free(benchmark->test_cipher);
    if (benchmark->verify_cipher)
        EVP_CIPHER_free(benchmark->verify_cipher);
}

static void free_mac_benchmark(mac_benchmark* benchmark){
    if (benchmark->test_mac)
        EVP_MAC_free(benchmark->test_mac);
    if (benchmark->verify_mac)
        EVP_MAC_free(benchmark->verify_mac);
}

static ssize_t encrypt(EVP_CIPHER* ciph, const unsigned char* src_buf, unsigned char *dest_buf){
    int len = 0, lensum;
    ssize_t ret = -1;
    uint64_t duration;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if(!ctx)
        return -1;

    if (1 != EVP_EncryptInit_ex(ctx, ciph, NULL, test_key, test_iv))
        goto exit;

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, 0))
        goto exit;

    duration = rdtsc();
    if (1 != EVP_EncryptUpdate(ctx, dest_buf, &len, src_buf, TEST_CHUNK_SIZE))
        goto exit;
    lensum = len;

    if (1 != EVP_EncryptFinal_ex(ctx, dest_buf + lensum, &len))
        goto exit;
    duration = rdtsc() - duration;
    lensum += len;

    if(lensum != TEST_CHUNK_SIZE)
        goto exit;

    ret = (ssize_t) duration;
exit:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int digest(EVP_MD* md, const unsigned char* src_buf, unsigned char *dest_buf, unsigned int len){
    int ret = -1;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if(!ctx)
        return -1;

    if (1 != EVP_DigestInit_ex(ctx, md, NULL))
        goto exit;

    if (1 != EVP_DigestUpdate(ctx, src_buf, TEST_CHUNK_SIZE))
        goto exit;

    if (1 != EVP_DigestFinal_ex(ctx, dest_buf, &len))
        goto exit;

    ret = 0;
exit:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static ssize_t authenticate (EVP_MAC* mac, const char* benchmark_hash, unsigned char* out, const unsigned char* test_msg, size_t msg_size) {
    char* mac_key = "unpwnable";
    char hash_spec[16] = {0, };
    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, hash_spec, strnlen(benchmark_hash, sizeof(hash_spec))),
            OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, mac_key, strlen(mac_key)),
            OSSL_PARAM_construct_end(),
    };
    ssize_t ret = -1, timing;
    size_t outl = 0;
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);

    strncpy(hash_spec, benchmark_hash, sizeof(hash_spec));

    if(EVP_MAC_init(ctx, NULL, 0, params) < 1)
        goto exit;

    timing = (ssize_t) rdtsc();
    if(EVP_MAC_update(ctx, (const unsigned char*) test_msg, msg_size) < 1)
        goto exit;

    if (EVP_MAC_final(ctx, out, &outl, 32) < 1)
        goto exit;

    ret = (ssize_t) rdtsc() - timing;
exit:
    if(ctx)
        EVP_MAC_CTX_free(ctx);
    return ret;
}

int verify_cipher_correctness(cipher_benchmark* benchmark, const unsigned char* src_buf, unsigned char* dst_buf) {
    int ret = -1;
    unsigned size;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    unsigned char test_buf[32], verify_buf[sizeof(test_buf)];

    encrypt(benchmark->test_cipher, src_buf, dst_buf);
    size = sizeof(test_buf);
    if(!EVP_DigestInit_ex2(md, EVP_get_digestbyname("SHA256"), NULL))
        goto exit;
    if(!EVP_DigestUpdate(md, dst_buf, TEST_CHUNK_SIZE))
        goto exit;
    if(!EVP_DigestFinal(md, test_buf, &size))
        goto exit;

    encrypt(benchmark->verify_cipher, src_buf, dst_buf);
    size = sizeof(verify_buf);
    if(!EVP_DigestInit_ex2(md, EVP_get_digestbyname("SHA256"), NULL))
        goto exit;
    if(!EVP_DigestUpdate(md, dst_buf, TEST_CHUNK_SIZE))
        goto exit;
    if(!EVP_DigestFinal(md, verify_buf, &size))
        goto exit;

    if(memcmp(test_buf, verify_buf, sizeof(verify_buf)) != 0)
        goto exit;

    ret = 0;
exit:
    if(md)
        EVP_MD_CTX_free(md);
    return ret;
}

int verify_mac_correctness(mac_benchmark* benchmark, const unsigned char* msg) {
    unsigned char __attribute__((aligned(32))) test_out[32];
    unsigned char __attribute__((aligned(32))) verify_out[32];

    authenticate(benchmark->verify_mac, benchmark->hash_spec, verify_out, msg, TEST_CHUNK_SIZE / 16);
    authenticate(benchmark->test_mac, benchmark->hash_spec, test_out, msg, TEST_CHUNK_SIZE / 16);

    if(memcmp(test_out, verify_out, sizeof(verify_out)) != 0)
        return -1;

    return 0;
}

static FILE* get_benchmark_file(const char* spec){
    char path[PATH_MAX], f_dirname_buf[sizeof(path)];
    char* f_dirname;
    size_t cwdlen;
    FILE* ret = NULL;

    getcwd(path, sizeof(path));
    cwdlen = strnlen(path, sizeof(path) - 1);

    snprintf(path + cwdlen, sizeof(path) - cwdlen, "/benchmark_results/%s.py", spec);
    strncpy(f_dirname_buf, path, sizeof(f_dirname_buf));
    f_dirname = dirname(f_dirname_buf);
    if(!f_dirname)
        return NULL;

    if(access(f_dirname, F_OK)) {
        if(mkdir(f_dirname, 0777))
            return NULL;
    }

    if(!access(path, F_OK))
        remove(path);

    ret = fopen(path, "w");
    fprintf(ret, "_CPU = \"%s\"\n", cpu_ident);
    fprintf(ret, "_TEST_CHUNK_SIZE = 0x%lx # Bytes\n\n", (unsigned long) TEST_CHUNK_SIZE);

    return ret;
}

static void run_cipher_benchmark(cipher_benchmark* benchmark, const unsigned char* src_buf, unsigned char *dest_buf) {
    const struct {const char* name; EVP_CIPHER* ciph;} runs[] = {{"test", benchmark->test_cipher}, {"verify", benchmark->verify_cipher}};
    ssize_t timing, avg;
    unsigned long perf_avg;
    FILE* f;
    unsigned i, r;

    f = get_benchmark_file(benchmark->cipher_spec);
    if(!f) {
        printf( STR_FAIL "%s: Could not open output file!\n", benchmark->cipher_spec);
        return;
    }

    for(r = 0; r < countof(runs); r++) {
        avg = 0;
        perf_avg = 0;
        fprintf(f, "timings_%s = [", runs[r].name);
        for (i = 0; i < NUM_REPEATS; i++) {
            printf("\r" STR_PEND "%s %s cipher (%04u/%04u)                            ", benchmark->cipher_spec, runs[r].name, i, NUM_REPEATS);
            fflush(stdout);
            ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
            ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
            timing = encrypt(runs[r].ciph, src_buf, dest_buf);
            ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
            read(perf_fd, (r ? &perf_test[i] : &perf_verify[i]), sizeof(unsigned long));
            if (timing < 0) {
                printf("\r" STR_FAIL "%s %s cipher (%04u/%04u) --> Error! Aborting test                          \n",
                       benchmark->cipher_spec, runs[r].name, i, NUM_REPEATS);
                goto exit;
            }
            perf_avg += r ? perf_test[i] : perf_verify[i];
            avg += timing;
            fprintf(f, "0x%lx, ", timing);
        }
        fprintf(f, "]\n");
        printf("\r" STR_OK "%s %s cipher (%04u/%04u) --> Done! Avg. %f GB/s  Avg. perf. %lu                        \n",
               benchmark->cipher_spec, runs[r].name, i, NUM_REPEATS, ((double) TEST_CHUNK_SIZE / GIGABYTE) / tsc_to_seconds((double) avg / NUM_REPEATS), (unsigned long)((double)perf_avg/NUM_REPEATS));
    }

exit:
    fprintf(f, "\n");
    fclose(f);
}

static void run_mac_benchmark(mac_benchmark* benchmark, const unsigned char* src_buf, unsigned char *dest_buf) {
    const struct {const char* name; EVP_MAC* mac;} runs[] = {{"test", benchmark->test_mac}, {"verify", benchmark->verify_mac}};
    ssize_t timing, avg;
    unsigned char __attribute__((aligned(32))) mac_out[32];
    FILE* f;
    unsigned i, r;

    f = get_benchmark_file(benchmark->mac_spec);
    if(!f) {
        printf( STR_FAIL "%s: Could not open output file!\n", benchmark->mac_spec);
        return;
    }

    for(r = 0; r < countof(runs); r++) {
        avg = 0;
        fprintf(f, "timings_%s = [", runs[r].name);
        for (i = 0; i < NUM_REPEATS; i++) {
            printf("\r" STR_PEND "%s %s MAC (%04u/%04u)                            ", benchmark->mac_spec, runs[r].name, i, NUM_REPEATS);
            fflush(stdout);
            timing = authenticate(runs[r].mac, benchmark->hash_spec, mac_out, src_buf, TEST_CHUNK_SIZE);
            if (timing < 0) {
                printf("\r" STR_FAIL "%s %s MAC (%04u/%04u) --> Error! Aborting test                          \n",
                       benchmark->mac_spec, runs[r].name, i, NUM_REPEATS);
                goto exit;
            }
            avg += timing;
            fprintf(f, "0x%lx, ", timing);
        }
        fprintf(f, "]\n");
        printf("\r" STR_OK "%s %s MAC (%04u/%04u) --> Done! Avg. %f GB/s                          \n",
               benchmark->mac_spec, runs[r].name, i, NUM_REPEATS, ((double) TEST_CHUNK_SIZE / GIGABYTE) / tsc_to_seconds((double) avg / NUM_REPEATS));
    }

exit:
    fprintf(f, "\n");
    fclose(f);
}

int main() {
    int ret = 1;
    const char* perf_ctr_spec = ALDER_LAKE_MEM_STALLS_L3_MISS;
    unsigned char __attribute__((aligned(32))) mac_buf[64];
    unsigned char* src_buf = NULL, *dest_buf = NULL;
    OSSL_PROVIDER *custom_provider;
    unsigned i;
    struct perf_event_attr pe;
    pfm_perf_encode_arg_t perf_args;
    cipher_benchmark cipher_benchmarks[] = {
            {.cipher_spec = "AES-128-GCM"},
            {.cipher_spec = "AES-128-CTR"},
    };
    mac_benchmark mac_benchmarks[] = {
            {.mac_spec = "HMAC", .hash_spec = "SHA256"},
    };

    printf( STR_PEND "Setting up benchmark ...\n");

    get_tsc_freq();
    get_cpu_ident(cpu_ident);

    if (pfm_initialize() != PFM_SUCCESS) {
        printf( STR_FAIL "PFM initialization failed!\n");
        return -1;
    }

    memset(&pe, 0, sizeof(struct perf_event_attr));
    memset(&perf_args, 0, sizeof(perf_args));
    perf_args.attr = &pe;
    ret = pfm_get_os_event_encoding(perf_ctr_spec, PFM_PLM0 | PFM_PLM3, PFM_OS_PERF_EVENT, &perf_args);
    if (ret != PFM_SUCCESS) {
        printf( STR_FAIL "Could not find performance counter!\n");
        return -1;
    }
    perf_fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (perf_fd < 0) {
        printf( STR_FAIL "Could not open performance counter - errno %d\n", errno);
        return -1;
    }
    printf(STR_OK "Successfully opened handle to performance counter '%s'\n", perf_ctr_spec);

    custom_provider = get_xom_provider();

    src_buf = aligned_alloc(getpagesize(), TEST_CHUNK_SIZE);
    dest_buf = aligned_alloc(getpagesize(), TEST_CHUNK_SIZE);
    if (!src_buf || !dest_buf) {
        printf(STR_FAIL "Out of memory!\n");
        goto exit;
    }

    if(get_random_data(src_buf, TEST_CHUNK_SIZE))
        goto exit;

    for(i = 0; i < countof(cipher_benchmarks); i++)
        init_cipher_benchmark(&cipher_benchmarks[i]);
    for(i = 0; i < countof(mac_benchmarks) && has_sha(); i++)
        init_mac_benchmark(&mac_benchmarks[i]);

    printf("\r" STR_OK "Successfully initialized benchmarks! Performing %u repetitions with %u MB per test!\n", NUM_REPEATS, (unsigned)(TEST_CHUNK_SIZE/(1 << 20)));

    for(i = 0; i < countof(cipher_benchmarks); i++){
        memset(perf_test, 0, sizeof(perf_test));
        memset(perf_verify, 0, sizeof(perf_verify));
        printf(STR_PEND "Testing correctness of cipher '%s' ...", cipher_benchmarks[i].cipher_spec);
        fflush(stdout);
        if(verify_cipher_correctness(&cipher_benchmarks[i], src_buf, dest_buf) < 0) {
            printf("\r" STR_FAIL "Output of cipher '%s' diverges from default implementation! Skipping...\n",
                   cipher_benchmarks[i].cipher_spec);
            continue;
        }
        printf("\r" STR_OK "Testing correctness of cipher '%s' ... OK!\n", cipher_benchmarks[i].cipher_spec);
        run_cipher_benchmark(&cipher_benchmarks[i], src_buf, dest_buf);
    }


    for(i = 0; i < countof(mac_benchmarks) && has_sha(); i++){
        printf(STR_PEND "Testing correctness of MAC '%s' ...", mac_benchmarks[i].mac_spec);
        fflush(stdout);
        if(verify_mac_correctness(&mac_benchmarks[i], src_buf) < 0) {
            printf("\r" STR_FAIL "Output of MAC '%s' diverges from default implementation! Skipping...\n",
                   mac_benchmarks[i].mac_spec);
            continue;
        }
        printf("\r" STR_OK "Testing correctness of MAC '%s' ... OK!\n", mac_benchmarks[i].mac_spec);
        run_mac_benchmark(&mac_benchmarks[i], src_buf, dest_buf);
    }

    ret = 0;
exit:
    for(i = 0; i < countof(cipher_benchmarks); i++)
        free_cipher_benchmark(&cipher_benchmarks[i]);
    for(i = 0; i < countof(mac_benchmarks) && has_sha(); i++)
        free_mac_benchmark(&mac_benchmarks[i]);
    if(custom_provider)
        OSSL_PROVIDER_unload(custom_provider);
    OPENSSL_cleanup();
    free(src_buf);
    free(dest_buf);
    return ret;
}