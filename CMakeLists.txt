cmake_minimum_required(VERSION 3.14.0)
project (libxom-provider C ASM)

find_package(OpenSSL REQUIRED)

add_subdirectory(libxom)
include_directories(libxom)

add_link_options("-znoexecstack")

add_library(xom_provider SHARED
        provider/src/xom_provider.c
        provider/src/xom_aes_128_ctr.c
        provider/src/xom_aes_128_gcm.c
        provider/src/xom_aes_common.c
        provider/src/aes_aesni.s
        provider/src/aes_vaes.s
        provider/src/ghash.s
        provider/src/hmac_sha256.s
        provider/src/xom_hmac_sha256.c
)

target_include_directories(xom_provider PUBLIC provider/include)
target_compile_options(xom_provider PUBLIC "-fPIE;-mssse3;-mpclmul;-mrdrnd;-O3;-mshstk;-fcf-protection=full")
target_link_libraries(xom_provider PUBLIC OpenSSL::Crypto xom)

if(DEMO)
    find_package(CURL REQUIRED)
    add_executable(demo_https demo_https.c)
    target_link_libraries(demo_https PUBLIC OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)
endif()
