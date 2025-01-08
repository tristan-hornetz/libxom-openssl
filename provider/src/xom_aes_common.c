#include <string.h>
#include "aes_xom.h"

void setup_aesni_128_key(unsigned char* dest, const unsigned char *key) {
    const size_t key_offset_lo = &aes_aesni_key_lo - (unsigned char *) aes_aesni_gctr_linear + MOV_OPCODE_SIZE;
    const size_t key_offset_hi = &aes_aesni_key_hi - (unsigned char *) aes_aesni_gctr_linear + MOV_OPCODE_SIZE;

    memcpy(dest + key_offset_lo, key, AES_128_CTR_KEY_SIZE >> 1);
    memcpy(dest + key_offset_hi, key + (AES_128_CTR_KEY_SIZE >> 1), AES_128_CTR_KEY_SIZE >> 1);
}

void setup_vaes_128_key(unsigned char* dest, const unsigned char *key) {
    const size_t key_offset_lo = &aes_vaes_key_lo - (unsigned char *) aes_vaes_gctr_linear + MOV_OPCODE_SIZE;
    const size_t key_offset_hi = &aes_vaes_key_hi - (unsigned char *) aes_vaes_gctr_linear + MOV_OPCODE_SIZE;

    memcpy(dest + key_offset_lo, key, AES_128_CTR_KEY_SIZE >> 1);
    memcpy(dest + key_offset_hi, key + (AES_128_CTR_KEY_SIZE >> 1), AES_128_CTR_KEY_SIZE >> 1);
}

