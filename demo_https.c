#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <curl/curl.h>

#if !CURL_AT_LEAST_VERSION(7, 62, 0)
#error "This demo requires libcurl 7.62.0 or later!"
#endif

#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define CYN "\e[0;36m"
#define YLL "\033[33m"
#define CRESET "\e[0m"
#define STR_WARN "[" YLL "WARNING" CRESET "] "
#define STR_OK "[" GRN "+" CRESET "] "
#define STR_PEND "[" CYN "*" CRESET "] "
#define STR_FAIL "[" RED "-" CRESET "] "

#define URL_STR_SIZE 256
#define PROVIDER_LIB_FILE "libxom_provider.so"
#define URL "https://www.example.com/"
#define PORT 443

static void handle_error(const char *msg) {
    fprintf(stderr, STR_FAIL);
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static int find_provider_lib(char path[PATH_MAX]) {
    char* dir;
    char exe[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

    if(len < 0)
        return -1;
    exe[len & (PATH_MAX - 1)] = '\0';
    dir = dirname(exe);

    snprintf(path, sizeof(exe), "%s/" PROVIDER_LIB_FILE, dir);

    return access(path, F_OK) ? -1 : 0;
}

static int parse_url(const char* url, char url_host[URL_STR_SIZE], char url_path[URL_STR_SIZE]){
    int rc = -1;
    CURLU *h = curl_url();
    CURLUcode uc;
    char* host = NULL, *path = NULL;

    if(!h)
        return -1;

    uc = curl_url_set(h, CURLUPART_URL, url, CURLU_URLENCODE);
    if(uc)
        goto exit;
    uc = curl_url_get(h, CURLUPART_HOST, &host, 0);
    if(uc)
        goto exit;
    uc = curl_url_get(h, CURLUPART_PATH, &path, 0);
    if(uc)
        goto exit;
    if(!host || !path)
        goto exit;

    strncpy(url_host, host, URL_STR_SIZE);
    strncpy(url_path, path, URL_STR_SIZE);

    rc = 0;
exit:
    if(host)
        curl_free(host);
    if(path)
        curl_free(path);
    curl_url_cleanup(h);
    return rc;
}

static void perform_request(char* url_host, char* url_path) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server, recv_bytes;
    struct hostent *host;
    struct sockaddr_in addr;
    char request[URL_STR_SIZE * 3];
    char recv_buffer[1024];

    // Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create new SSL context
    ctx = SSL_CTX_new_ex(NULL, "provider=xom", TLS_client_method());
    if (ctx == NULL)
        handle_error("SSL_CTX_new");

    if (!SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"))
            handle_error("SSL_CTX_set_cipher_list");
    // Set the minimum and maximum protocol version to TLS 1.3
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION))
        handle_error("SSL_CTX_set_min_proto_version");
    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION))
        handle_error("SSL_CTX_set_max_proto_version");

    // Resolve hostname
    host = gethostbyname(url_host);
    if (host == NULL)
        handle_error("gethostbyname");

    // Create socket
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0)
        handle_error("socket");

    // Set up the sockaddr_in structure
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = *(in_addr_t *)(host->h_addr);

    // Connect to the server
    if (connect(server, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        handle_error("connect");

    // Create new SSL connection state
    ssl = SSL_new(ctx);
    if (ssl == NULL)
        handle_error("SSL_new");

    // Attach the SSL session to the socket
    SSL_set_fd(ssl, server);

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0)
        handle_error("SSL_connect");

    printf(STR_OK "TLS handshake was successful!\n");

    // Send an HTTP GET request
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", url_path, url_host);
    if (SSL_write(ssl, request, (int) strlen(request)) <= 0)
        handle_error("SSL_write");

    printf("\n"STR_OK "Request:\n%s", request);
    printf(STR_OK "Response:\n");

    // Receive the response
    while ((recv_bytes = SSL_read(ssl, recv_buffer, sizeof(recv_buffer) - 1)) > 0) {
        recv_buffer[recv_bytes] = '\0';
        printf("%s", recv_buffer);
    }
    if (recv_bytes < 0)
        handle_error("SSL_read");

    printf(STR_OK "Done!\n");

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
}

int main(int argc, char* argv[]) {
    OSSL_PROVIDER *custom_provider;

    char path[PATH_MAX] = {0, };
    char url_host[URL_STR_SIZE];
    char url_path[URL_STR_SIZE];
    const char* url = URL;

    if (find_provider_lib(path) < 0) {
        puts(STR_FAIL "Cannot find provider library! Please make sure that it is located in the same directory as this executable!\n");
        return 1;
    }

    if (argc > 1) {
        if(!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            printf("Usage: demo_https [url]\n  or: demo_https -h\n  or: demo_https --help\n");
            return 0;
        }
        url = argv[1];
    }

    if(parse_url(url, url_host, url_path)) {
        puts(STR_FAIL "Could not parse URL!");
        return 1;
    }

    custom_provider = OSSL_PROVIDER_load(NULL, path);
    if(!custom_provider){
        puts(STR_FAIL "Could not load provider library!");
        return 1;
    }

    printf(STR_PEND "Performing HTTP/1.1 GET request to %s\n", url);
    perform_request(url_host, url_path);


    OSSL_PROVIDER_unload(custom_provider);
    EVP_cleanup();
    OPENSSL_cleanup();

    return 0;
}