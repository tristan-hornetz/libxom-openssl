.file "hmac_sha256.s"

// SHA code is based on "Intel SHA Extensions - New Instructions Supporting the Secure
// Hash Algorithm on Intel Architecture Processors" by Gulley et al., 2013

// gfmul implementation is based on "Intel® Carry-Less Multiplication Instruction 
// and its Usage for Computing the GCM Mode" by Gueron and Kounavis, 2014

////////////////////////
// Register assignments
////////////////////////

.set msg, %xmm0
.set inner_hash_backup_lo, %xmm1
.set inner_hash_backup_hi, %xmm14

.set freeusexmm0, %xmm3
.set freeusexmm1, %xmm4

.set state_backup_hi, %xmm2
.set state_backup_lo, %xmm9

.set tmsg0, %xmm5
.set state_lo, %xmm6
.set state_hi, %xmm7
.set ishuf_mask, %xmm8
.set tmsg1, %xmm10
.set tmsg2, %xmm11
.set tmsg3, %xmm12
.set tmsg4, %xmm13

.set block_lolo, msg
.set block_lohi, tmsg1
.set block_hilo, tmsg2
.set block_hihi, tmsg3

.set gfmul_in_a, %xmm3
.set gfmul_in_b, %xmm5
.set gfmul_clobber1, %xmm7
.set gfmul_clobber2, %xmm8
.set gfmul_clobber3, %xmm9
.set gfmul_clobber4, %xmm10
.set gfmul_clobber5, %xmm11
.set gfmul_clobber6, %xmm12
.set gfmul_clobber7, %xmm13
.set gfmul_clobber8, %xmm14

.set gfmul_in_a, %xmm3
.set gfmul_in_b, %xmm5
.set gfmul_clobber1, %xmm7
.set gfmul_clobber2, %xmm8
.set gfmul_clobber3, %xmm9
.set gfmul_clobber4, %xmm10
.set gfmul_clobber5, %xmm11
.set gfmul_clobber6, %xmm12
.set gfmul_clobber7, %xmm13
.set gfmul_clobber8, %xmm14

////////////////////////
// Macros
////////////////////////

.macro load_128bit_constant, quad0, quad1, dest
    mov $\quad0, %r14
    vmovq %r14, %xmm2
    mov $\quad1, %r14
    vmovq %r14, %xmm3
    vpshufd $0x40, %xmm3, %xmm3
    vpblendw $0xf0, %xmm3, %xmm2, %xmm2
    vmovdqa %xmm2, \dest
.endm

.macro load_128bit_constant_custom, name, quad0, quad1, dest, t1
    .globl quad0_\name
    quad0_\name:
    mov $\quad0, %r14
    vmovq %r14, \dest
    .globl quad1_\name
    quad1_\name:
    mov $\quad1, %r14
    vmovq %r14, \t1
    vpshufd $0x40, \t1, \t1
    vpblendw $0xf0, \t1, \dest, \dest
.endm

.macro load_256bit_constant_xmm, quad0, quad1, quad2, quad3, dest_lo, dest_hi
    mov $\quad0, %r14
    vmovq %r14, %xmm2
    mov $\quad1, %r14
    vmovq %r14, %xmm3
    vpshufd $0x40, %xmm3, %xmm3
    vpblendw $0xf0, %xmm3, %xmm2, \dest_lo
    mov $\quad2, %r14
    vmovq %r14, %xmm4
    mov $\quad3, %r14
    vmovq %r14, %xmm5
    vpshufd $0x40, %xmm5, %xmm5
    vpblendw $0xf0, %xmm5, %xmm4, \dest_hi
.endm

.macro load_256bit_constant_xmm_named, quad0, quad1, quad2, quad3, dest_lo, dest_hi, name
    .globl quad0_\name
    quad0_\name:
    mov $\quad0, %r14
    vmovq %r14, %xmm2
    .globl quad1_\name
    quad1_\name:
    mov $\quad1, %r14
    vmovq %r14, %xmm3
    vpshufd $0x40, %xmm3, %xmm3
    vpblendw $0xf0, %xmm3, %xmm2, \dest_lo
    .globl quad2_\name
    quad2_\name:
    mov $\quad2, %r14
    vmovq %r14, %xmm4
    .globl quad3_\name
    quad3_\name:
    mov $\quad3, %r14
    vmovq %r14, %xmm5
    vpshufd $0x40, %xmm5, %xmm5
    vpblendw $0xf0, %xmm5, %xmm4, \dest_hi
.endm

.macro load_256bit_constant, quad0, quad1, quad2, quad3, dest, name
    .globl quad0_\name
    quad0_\name:
    mov $\quad0, %r14
    vmovq %r14, %xmm2
    .globl quad1_\name
    quad1_\name:
    mov $\quad1, %r14
    vmovq %r14, %xmm3
    vpshufd $0x40, %xmm3, %xmm3
    vpblendw $0xf0, %xmm3, %xmm2, %xmm2
    .globl quad2_\name
    quad2_\name:
    mov $\quad2, %r14
    vmovq %r14, %xmm4
    .globl quad3_\name
    quad3_\name:
    mov $\quad3, %r14
    vmovq %r14, %xmm5
    vpshufd $0x40, %xmm5, %xmm5
    vpblendw $0xf0, %xmm5, %xmm4, %xmm4
    vinserti128    $1, %xmm4, %ymm2, \dest
    xor %r14, %r14
.endm

.macro roundconst_get_inline, c_lolo, c_lohi, c_hilo, c_hihi
    movq $0x\c_lohi\c_lolo, %r10
    movq $0x\c_hihi\c_hilo, %r11
    movq %r10, freeusexmm0
    movq %r11, freeusexmm1
    pshufd $0x40, freeusexmm1, freeusexmm1
    pblendw $0xf0, freeusexmm1, freeusexmm0
    paddd freeusexmm0, msg
.endm

// Place code into .data section, so that we can overwrite the keys
.section .rodata
.align 0x1000

// This symbol only indicates the start of the memory range to be copied into XOM. Do not call.
.globl hmac256_start
hmac256_start:

/////////////////////////////////////////
//  ▗▄▖ ▗▄▄▄▖ ▗▄▄▖     ▗▄▄▖ ▗▄▄▖▗▖  ▗▖ //
// ▐▌ ▐▌▐▌   ▐▌       ▐▌   ▐▌   ▐▛▚▞▜▌ //
// ▐▛▀▜▌▐▛▀▀▘ ▝▀▚▖    ▐▌▝▜▌▐▌   ▐▌  ▐▌ //
// ▐▌ ▐▌▐▙▄▄▖▗▄▄▞▘    ▝▚▄▞▘▝▚▄▄▖▐▌  ▐▌ //
/////////////////////////////////////////                         

// Output goes into gfmul_in_a
// input_in_b does not chanage
// r11 decides the return option
.Lgfmul:
    vmovdqa gfmul_in_a, gfmul_clobber2
    vpclmulqdq $0, gfmul_in_b, gfmul_clobber2, gfmul_clobber2
    vmovdqa gfmul_in_a, gfmul_clobber3
    vpclmulqdq $16, gfmul_in_b, gfmul_clobber3, gfmul_clobber3
    vmovdqa gfmul_in_a, gfmul_clobber4
    vpclmulqdq $1, gfmul_in_b, gfmul_clobber4, gfmul_clobber4
    vmovdqa gfmul_in_a, gfmul_clobber5
    vpclmulqdq $17, gfmul_in_b, gfmul_clobber5, gfmul_clobber5
    vpxor gfmul_clobber4, gfmul_clobber3, gfmul_clobber3
    vmovdqa gfmul_clobber3, gfmul_clobber4
    vpsrldq $8, gfmul_clobber3, gfmul_clobber3
    vpslldq $8, gfmul_clobber4, gfmul_clobber4
    vpxor gfmul_clobber4, gfmul_clobber2, gfmul_clobber2
    vpxor gfmul_clobber3, gfmul_clobber5, gfmul_clobber5
    vmovdqa gfmul_clobber2, gfmul_clobber6
    vmovdqa gfmul_clobber5, gfmul_clobber7
    vpslld $1, gfmul_clobber2, gfmul_clobber2
    vpslld $1, gfmul_clobber5, gfmul_clobber5
    vpsrld $31, gfmul_clobber6, gfmul_clobber6
    vpsrld $31, gfmul_clobber7, gfmul_clobber7
    vmovdqa gfmul_clobber6, gfmul_clobber8
    vpslldq $4, gfmul_clobber7, gfmul_clobber7
    vpslldq $4, gfmul_clobber6, gfmul_clobber6
    vpsrldq $12, gfmul_clobber8, gfmul_clobber8
    vpor gfmul_clobber6, gfmul_clobber2, gfmul_clobber2
    vpor gfmul_clobber7, gfmul_clobber5, gfmul_clobber5
    vpor gfmul_clobber8, gfmul_clobber5, gfmul_clobber5
    vmovdqa gfmul_clobber2, gfmul_clobber6
    vmovdqa gfmul_clobber2, gfmul_clobber7
    vmovdqa gfmul_clobber2, gfmul_clobber8
    vpslld $31, gfmul_clobber6, gfmul_clobber6
    vpslld $30, gfmul_clobber7, gfmul_clobber7
    vpslld $25, gfmul_clobber8, gfmul_clobber8
    vpxor gfmul_clobber7, gfmul_clobber6, gfmul_clobber6
    vpxor gfmul_clobber8, gfmul_clobber6, gfmul_clobber6
    vmovdqa gfmul_clobber6, gfmul_clobber7
    vpslldq $12, gfmul_clobber6, gfmul_clobber6
    vpsrldq $4, gfmul_clobber7, gfmul_clobber7
    vpxor gfmul_clobber6, gfmul_clobber2, gfmul_clobber2
    vmovdqa gfmul_clobber2,gfmul_clobber1
    vmovdqa gfmul_clobber2,gfmul_clobber3
    vmovdqa gfmul_clobber2,gfmul_clobber4
    vpsrld $1, gfmul_clobber1, gfmul_clobber1
    vpsrld $2, gfmul_clobber3, gfmul_clobber3
    vpsrld $7, gfmul_clobber4, gfmul_clobber4
    vpxor gfmul_clobber3, gfmul_clobber1, gfmul_clobber1
    vpxor gfmul_clobber4, gfmul_clobber1, gfmul_clobber1
    vpxor gfmul_clobber7, gfmul_clobber1, gfmul_clobber1
    vpxor gfmul_clobber1, gfmul_clobber2, gfmul_clobber2
    vpxor gfmul_clobber2, gfmul_clobber5, gfmul_clobber5
    vmovdqa gfmul_clobber5, gfmul_in_a
    dec %r11
    jz .Lgfmul_r1
    dec %r11
    jz .Lgfmul_r2
    jmp .Lgfmul_r3

// ymm0-5 remain unaffected
.Lprime_memory_encryption:
    // Load key from immediates
    .globl hmac_memenc_key_lo
    hmac_memenc_key_lo:
    mov $0x123456789abcdef,%r14
    vmovq %r14, %xmm9
    .globl hmac_memenc_key_hi
    hmac_memenc_key_hi:
    mov $0x123456789abcdef,%r14
    vmovq %r14, %xmm8
    vpshufd $0x40, %xmm8, %xmm8
    vpblendw $0xf0, %xmm8, %xmm9, %xmm9

    // Prepare for round key generation
    vmovdqa %xmm9, %xmm8
    vinserti128 $1, %xmm9, %ymm10, %ymm10

    vaeskeygenassist $1, %xmm8, %xmm7
    mov $1, %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr1:
    vinserti128 $1, %xmm8, %ymm11, %ymm11
    vaeskeygenassist $2, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr2:
    vinserti128 $1, %xmm8, %ymm12, %ymm12
    vaeskeygenassist $4, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr3:
    vinserti128 $1, %xmm8, %ymm13, %ymm13
    vaeskeygenassist $8, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr4:
    vinserti128 $1, %xmm8, %ymm14, %ymm14
    vaeskeygenassist $16, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr5:
    vmovdqa %xmm8, %xmm10
    vaeskeygenassist $32, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr6:
    vmovdqa %xmm8, %xmm11
    vaeskeygenassist $64, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr7:
    vmovdqa %xmm8, %xmm12
    vaeskeygenassist $0x80, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr8:
    vmovdqa %xmm8, %xmm13
    vaeskeygenassist $0x1b, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr9:
    vmovdqa %xmm8, %xmm14
    vaeskeygenassist $0x36, %xmm8, %xmm7
    inc %al
    jmp .Laes_gctr_linear_prepare_roundkey_128
.Laespkeyr10:
    vmovdqa %xmm8, %xmm15

    test %r8, %r8
    jz .Lbackup_internal_state_primed
    jmp .Lrestore_internal_state_primed


.Laes_gctr_linear_prepare_roundkey_128:
    vpshufd $255, %xmm7, %xmm7
    vmovdqa %xmm8, %xmm6
    vpslldq $4, %xmm6, %xmm6
    vpxor %xmm6, %xmm8, %xmm8
    vpslldq $4, %xmm6, %xmm6
    vpxor %xmm6, %xmm8, %xmm8
    vpslldq $4, %xmm6, %xmm6
    vpxor %xmm6, %xmm8, %xmm8
    vpxor %xmm7, %xmm8, %xmm8
    mov %al, %cl
    dec %cl
    jz .Laespkeyr1
    dec %cl
    jz .Laespkeyr2
    dec %cl
    jz .Laespkeyr3
    dec %cl
    jz .Laespkeyr4
    dec %cl
    jz .Laespkeyr5
    dec %cl
    jz .Laespkeyr6
    dec %cl
    jz .Laespkeyr7
    dec %cl
    jz .Laespkeyr8
    dec %cl
    jz .Laespkeyr9
    dec %cl
    jz .Laespkeyr10

// dest addr: %rdi
// For save: ymm0-2 remain unaffected
// For load: ymm2 remains unaffected
.Lsave_ymm0_unpack:
    xor %r8, %r8
    jmp .Lunpack_round_keys
.Lload_ymm0_unpack:
    mov $1, %r8

.Lunpack_round_keys:
    vpxor %ymm3, %ymm3, %ymm3
    vmovdqa %ymm3, %ymm4
    vpermq $0xee, %ymm10, %ymm5
    vpermq $0xee, %ymm11, %ymm6
    vpermq $0xee, %ymm12, %ymm7
    vpermq $0xee, %ymm13, %ymm8
    vpermq $0xee, %ymm14, %ymm9
    vpermq $0x44, %ymm10, %ymm10
    vpermq $0x44, %ymm11, %ymm11
    vpermq $0x44, %ymm12, %ymm12
    vpermq $0x44, %ymm13, %ymm13
    vpermq $0x44, %ymm14, %ymm14
    vpermq $0x44, %ymm14, %ymm15
    test %r8, %r8
    jnz .Lload_ymm0

.Lsave_ymm0:
    // Generate new 96-bit IV
    xor %r8, %r8
    xor %r14, %r14
    rdrand %r14d
    jae .Lsave_ymm0
    vmovq %r14, %xmm3
.Lsave_ymm0_rdrand2:
    rdrand %r14
    jae .Lsave_ymm0_rdrand2
    vmovq %r14, %xmm4
    vpshufd $0x4e, %xmm3, %xmm3
    vpblendw $0xf0, %xmm3, %xmm4, %xmm4
    vpshufd $0x4e, %xmm3, %xmm3
    vmovdqa %xmm4, 0x68(%rsp)
    vmovq %xmm3, %r10
    jmp .Lencrypt_counter_block

.Lload_ymm0:
    // Load old IV
    mov $1, %r8
    vmovdqa 0x50(%rdx), %xmm4
    vpshufd $0x4e, %xmm4, %xmm4
    vpblendw $0x0f, %xmm4, %xmm3, %xmm3
    vpshufd $0x4e, %xmm4, %xmm4
    vmovq %xmm4, %r14
    vmovq %xmm3, %r10
.Lencrypt_counter_block:
    // Encrypt the counter block with AES-128

    // Build counter block
    vmovhlps %xmm4, %xmm3, %xmm3
    vinserti128 $1, %xmm4, %ymm4, %ymm4
    vmovq %xmm3, %r11
    bswap %r11
    add $1, %r11d # Big endian 32-bit add
    bswap %r11
    vmovq %r11, %xmm3
    vmovlhps %xmm3, %xmm4, %xmm4
    vpermq $0x4e, %ymm4, %ymm4

    // Encrypt counter block
    vpxor   %ymm5, %ymm4, %ymm4
    vaesenc %ymm6, %ymm4, %ymm4
    vaesenc %ymm7, %ymm4, %ymm4
    vaesenc %ymm8, %ymm4, %ymm4
    vaesenc %ymm9, %ymm4, %ymm4
    vaesenc %ymm10, %ymm4, %ymm4
    vaesenc %ymm11, %ymm4, %ymm4
    vaesenc %ymm12, %ymm4, %ymm4
    vaesenc %ymm13, %ymm4, %ymm4
    vaesenc %ymm14, %ymm4, %ymm4
    vaesenclast %ymm15, %ymm4, %ymm4

    // Here starts the GCM part
    // Encrypt Zero-Block to get Hash Subkey
    // We could pre-compute this, but computing it here is not substantially slower than loading it from immediates
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm5, %ymm3, %ymm3
    vaesenc %ymm6, %ymm3, %ymm3
    vaesenc %ymm7, %ymm3, %ymm3
    vaesenc %ymm8, %ymm3, %ymm3
    vaesenc %ymm9, %ymm3, %ymm3
    vaesenc %ymm10, %ymm3, %ymm3
    vaesenc %ymm11, %ymm3, %ymm3
    vaesenc %ymm12, %ymm3, %ymm3
    vaesenc %ymm13, %ymm3, %ymm3
    vaesenc %ymm14, %ymm3, %ymm3
    vaesenclast %ymm15, %ymm3, %ymm3

    // We can drop the values in %xmm5-15 now

    // Get J0 -> 96 bit special case
    vmovq %r10, %xmm6
    vmovq %r14, %xmm5
    vmovlhps %xmm6, %xmm5, %xmm5
    mov $1, %r14
    bswap %r14
    vmovq %r14, %xmm7
    vpxor %xmm6, %xmm6, %xmm6
    vmovlhps %xmm7, %xmm6, %xmm6
    vpxor %xmm6, %xmm5, %xmm5

    // Encrypt J0
    // The round keys are still in the upper halves of %ymm5-15
    vextracti128 $1, %ymm5, %xmm6
    vpxor %xmm6, %xmm5, %xmm5
    vinserti128 $1, %xmm5, %ymm5, %ymm5
    vaesenc %ymm6, %ymm5, %ymm5
    vaesenc %ymm7, %ymm5, %ymm5
    vaesenc %ymm8, %ymm5, %ymm5
    vaesenc %ymm9, %ymm5, %ymm5
    vaesenc %ymm10, %ymm5, %ymm5
    vaesenc %ymm11, %ymm5, %ymm5
    vaesenc %ymm12, %ymm5, %ymm5
    vaesenc %ymm13, %ymm5, %ymm5
    vaesenc %ymm14, %ymm5, %ymm5
    vaesenclast %ymm15, %ymm5, %ymm5
    vextracti128 $1, %ymm5, %xmm15
    
    // Encrypted J0 is in xmm15
    // We can now safely forget the round keys
    
    vmovdqa %xmm3, gfmul_in_b

    // Put ciphertext into ymm3
    test %r8, %r8
    jnz .Lload_get_ciph
.Lstore_get_ciph:
    vpxor %ymm4, %ymm0, %ymm3
    jmp .Lload_ciph_done
.Lload_get_ciph:
    vmovdqa 0x20(%rdx), %ymm3
.Lload_ciph_done:

    // cipher text is in ymm3 - note that xmm3 is gfmul_in_a
    // encrypted counter block is in ymm4

    // Hash first and second block into xmm3
    mov $1, %r11
    jmp .Lgfmul
    .Lgfmul_r1:
    vextracti128 $1, %ymm3, %xmm8
    vpxor %xmm8, %xmm3, %xmm3
    mov $2, %r11
    jmp .Lgfmul
    .Lgfmul_r2:
    
    // Hash length block
    mov $256, %r11
    bswap %r11
    vmovq %r11, %xmm8
    vpxor %xmm8, %xmm3, %xmm3
    mov $3, %r11
    jmp .Lgfmul
    .Lgfmul_r3:

    // XOR with encrypted J0
    vpxor %xmm15, %xmm3, %xmm3

    // For store: ymm0 still contains the data to be stored
    // xmm3 now contains the GCM tag
    // ymm4 still contains the encrypted counter block

    test %r8, %r8
    jnz .Lload_ymm0_memaccess

.Lsave_ymm0_memaccess:
    vpxor %ymm4, %ymm0, %ymm4

    // Save to temporary location first
    // If we got interrupted while saving, we can still recover previous backup
    vmovdqa %ymm4, 0x38(%rsp)
    vmovdqa %xmm3, 0x58(%rsp)
    test %r15, %r15
    jnz restore_internal_state

.Lsave_ymm0_save_to_final:
    // Unset the 'no backup available' flag, so that we know that we can safely restore from here on
    and $~0x10000, %r12

    // Now, move backup from temporary location to final location, overwriting the previous backup
    // If we are interrupted during this process, simply repeat until it is done
    
    vmovdqa 0x38(%rsp), %ymm4
    vmovdqa 0x58(%rsp), %xmm3
    vmovdqa 0x68(%rsp), %xmm5
    vmovdqa %ymm4, 0x20(%rdx)
    vmovdqa %xmm3, 0x40(%rdx)
    vmovdqa %xmm5, 0x50(%rdx)
    
    mov %rdi, 0x8(%rsp)
    mov %rsi, (%rsp)

    test %r15, %r15
    jz .Lymm0_crypt_return
    xor %r15, %r15
    inc %r8b
    jmp .Lsave_ymm0_save_to_final

.Lload_ymm0_memaccess:
    // Validate Tag
    vmovdqa 0x20(%rdx), %ymm5
    vmovdqa 0x40(%rdx), %xmm6
    mfence
    mov 0x8(%rsp), %rdi
    mov (%rsp), %rsi
    vpxor %xmm3, %xmm6, %xmm6
    vptest %xmm6, %xmm6
    jz .Lload_ymm0_decrypt
    // Fault if the tag does not match
    test %r15, %r15
    jnz restore_internal_state
    ud2 
.Lload_ymm0_decrypt:
    vpxor %ymm4, %ymm5, %ymm0
    xor %r8b, %r8b

.Lymm0_crypt_return:
    test %r8b, %r8b
    jnz restore_internal_state
    dec %al
    jmp .Lrestore_sha_registers


/////////////////////////////////////////////////////////////
// ▗▖ ▗▖▗▖  ▗▖ ▗▄▖  ▗▄▄▖     ▗▄▄▖▗▖ ▗▖ ▗▄▖ ▄▄▄▄ ▄▄▄▄ ▄▄▄▄  //
// ▐▌ ▐▌▐▛▚▞▜▌▐▌ ▐▌▐▌       ▐▌   ▐▌ ▐▌▐▌ ▐▌   █ █    █     //
// ▐▛▀▜▌▐▌  ▐▌▐▛▀▜▌▐▌        ▝▀▚▖▐▛▀▜▌▐▛▀▜▌█▀▀▀ ▀▀▀█ █▀▀█  //
// ▐▌ ▐▌▐▌  ▐▌▐▌ ▐▌▝▚▄▄▖    ▗▄▄▞▘▐▌ ▐▌▐▌ ▐▌█▄▄▄ ▄▄▄█ █▄▄█  //
/////////////////////////////////////////////////////////////

// Load and pad HMAC key
// if %r8 == 0 then ipad else opad
load_key:
    load_256bit_constant_xmm_named 0x1234567890abdef,0x1234567890abdef,0x1234567890abdef,0x1234567890abdef, block_lolo, block_lohi, key_lo
    load_256bit_constant_xmm_named 0x1234567890abdef,0x1234567890abdef,0x1234567890abdef,0x1234567890abdef, block_hilo, block_hihi, key_hi
    test %r8, %r8
    jz .Lload_key_ipad
    mov $0x5c5c5c5c5c5c5c5c, %r9
    jmp .Lload_key_pad
.Lload_key_ipad:
    mov $0x3636363636363636, %r9
.Lload_key_pad:
    vmovq %r9, freeusexmm0
    vpshufd $0x44, freeusexmm0, freeusexmm0
    vpxor freeusexmm0, block_lolo, block_lolo
    vpxor freeusexmm0, block_lohi, block_lohi
    vpxor freeusexmm0, block_hilo, block_hilo
    vpxor freeusexmm0, block_hihi, block_hihi

    test %r8, %r8
    jz .Lhmac_compress_key
    jmp .Lhmac_compress_outer_key


// Compress a single 512-bit block
sha256_compress_block:
    movdqa state_lo, state_backup_lo
    movdqa state_hi, state_backup_hi

    /* Rounds 0-3 */
    pshufb ishuf_mask, msg
    movdqa msg, tmsg0
    roundconst_get_inline 428a2f98,71374491,b5c0fbcf,e9b5dba5

    sha256rnds2    state_lo, state_hi
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo

    /* Rounds 4-7 */
    pshufb ishuf_mask, tmsg1
    movdqa tmsg1, msg
    roundconst_get_inline 3956c25b,59f111f1,923f82a4,ab1c5ed5

    sha256rnds2    state_lo, state_hi
    pshufd         $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1    tmsg1, tmsg0

    /* Rounds 8-11 */
    pshufb ishuf_mask, tmsg2
    movdqa tmsg2, msg
    roundconst_get_inline d807aa98,12835b01,243185be,550c7dc3

    sha256rnds2    state_lo, state_hi
    pshufd         $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1    tmsg2, tmsg1

    /* Rounds 12-15 */
    pshufb ishuf_mask, tmsg3
    movdqa tmsg3, msg
    roundconst_get_inline 72be5d74,80deb1fe,9bdc06a7,c19bf174

    sha256rnds2    state_lo, state_hi
    movdqa tmsg3, tmsg4
    palignr $0x4, tmsg2, tmsg4
    paddd tmsg4, tmsg0
    sha256msg2 tmsg3, tmsg0
    pshufd         $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1 tmsg3, tmsg2

    /* Rounds 16-19 */
    movdqa tmsg0, msg
    roundconst_get_inline e49b69c1,efbe4786,0fc19dc6,240ca1cc

    sha256rnds2    state_lo, state_hi
    movdqa tmsg0, tmsg4
    palignr    $0x04, tmsg3, tmsg4
    paddd tmsg4, tmsg1
    sha256msg2    tmsg0, tmsg1
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1 tmsg0, tmsg3

    /* Rounds 20-23 */
    movdqa tmsg1, msg
    roundconst_get_inline 2de92c6f,4a7484aa,5cb0a9dc,76f988da

    sha256rnds2    state_lo, state_hi
    movdqa tmsg1, tmsg4
    palignr $4, tmsg0, tmsg4
    paddd tmsg4, tmsg2
    sha256msg2 tmsg1, tmsg2
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1 tmsg1, tmsg0

    /* Rounds 24-27 */
    movdqa tmsg2, msg
    roundconst_get_inline 983e5152,a831c66d,b00327c8,bf597fc7

    sha256rnds2    state_lo, state_hi
    movdqa tmsg2, tmsg4
    palignr    $0x04, tmsg1, tmsg4
    paddd tmsg4, tmsg3
    sha256msg2 tmsg2, tmsg3
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1    tmsg2, tmsg1

    /* Rounds 28-31 */
    movdqa tmsg3, msg
    roundconst_get_inline c6e00bf3,d5a79147,06ca6351,14292967

    sha256rnds2    state_lo, state_hi
    movdqa tmsg3, tmsg4
    palignr    $0x04, tmsg2, tmsg4
    paddd tmsg4, tmsg0
    sha256msg2 tmsg3, tmsg0
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1 tmsg3, tmsg2

    /* Rounds 32-35 */
    movdqa tmsg0, msg
    roundconst_get_inline 27b70a85,2e1b2138,4d2c6dfc,53380d13

    sha256rnds2    state_lo, state_hi
    movdqa tmsg0, tmsg4
    palignr    $0x04, tmsg3, tmsg4
    paddd tmsg4, tmsg1
    sha256msg2    tmsg0, tmsg1
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1 tmsg0, tmsg3

    /* Rounds 36-39 */
    movdqa tmsg1, msg
    roundconst_get_inline 650a7354,766a0abb,81c2c92e,92722c85

    sha256rnds2    state_lo, state_hi
    movdqa tmsg1, tmsg4
    palignr $4, tmsg0, tmsg4
    paddd tmsg4, tmsg2
    sha256msg2 tmsg1, tmsg2
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1 tmsg1, tmsg0

    /* Rounds 40-43 */
    movdqa tmsg2, msg
    roundconst_get_inline a2bfe8a1,a81a664b,c24b8b70,c76c51a3

    sha256rnds2    state_lo, state_hi
    movdqa tmsg2, tmsg4
    palignr    $0x04, tmsg1, tmsg4
    paddd tmsg4, tmsg3
    sha256msg2 tmsg2, tmsg3
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1    tmsg2, tmsg1

    /* Rounds 44-47 */
    movdqa tmsg3, msg
    roundconst_get_inline d192e819,d6990624,f40e3585,106aa070

    sha256rnds2    state_lo, state_hi
    movdqa tmsg3, tmsg4
    palignr    $0x04, tmsg2, tmsg4
    paddd tmsg4, tmsg0
    sha256msg2 tmsg3, tmsg0
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1 tmsg3, tmsg2

    /* Rounds 48-51 */
    movdqa tmsg0, msg
    roundconst_get_inline 19a4c116,1e376c08,2748774c,34b0bcb5

    sha256rnds2    state_lo, state_hi
    movdqa tmsg0, tmsg4
    palignr $0x04, tmsg3, tmsg4
    paddd tmsg4, tmsg1
    sha256msg2 tmsg0, tmsg1
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo
    sha256msg1 tmsg0, tmsg3

    /* Rounds 52-55 */
    movdqa tmsg1, msg
    roundconst_get_inline 391c0cb3,4ed8aa4a,5b9cca4f,682e6ff3

    sha256rnds2 state_lo, state_hi
    movdqa tmsg1, tmsg4
    palignr $0x04, tmsg0, tmsg4
    paddd tmsg4, tmsg2
    sha256msg2 tmsg1, tmsg2
    pshufd  $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo

    /* Rounds 56-59 */
    movdqa tmsg2, msg
    roundconst_get_inline 748f82ee,78a5636f,84c87814,8cc70208

    sha256rnds2    state_lo, state_hi
    movdqa tmsg2, tmsg4
    palignr    $0x04, tmsg1, tmsg4
    paddd tmsg4, tmsg3
    sha256msg2 tmsg2, tmsg3
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo

    /* Rounds 60-63 */
    movdqa tmsg3, msg
    roundconst_get_inline 90befffa,a4506ceb,bef9a3f7,c67178f2

    sha256rnds2    state_lo, state_hi
    pshufd $0x0e, msg, msg
    sha256rnds2    state_hi, state_lo

    /* Add to hash state */
    paddd state_backup_lo, state_lo
    paddd state_backup_hi, state_hi

    dec %al
    jz .Lhmac_inner_key_compressed
    dec %al
    jz .Lhmac_compression_done
    dec %al
    jz .Lhmac_compress_outer_key_done
    jmp .Lhmac_leave


backup_internal_state:
    // Move state into %ymm0
    vmovdqa state_lo, %xmm0
    vinserti128 $1, state_hi, %ymm0, %ymm0

    // Load round keys
    xor %r8, %r8
    jmp .Lprime_memory_encryption
.Lbackup_internal_state_primed:

    // Save %ymm0 and address of current message block to memory
.Lbackup_internal_state_begin_store:
    // Saving the block counter to memory is okay, because it is not secret and
    // any modifications to it can at worst modify the length of the authenticated message,
    // something which the user can do anyway

    mov $1, %al
    jmp .Lsave_ymm0_unpack


restore_internal_state:
    // Reset signal register
    xor %r15, %r15

    // If we did not yet back up our state, we cannot restore, and must start from scratch again
    // If we were to continue here, the GCM tag validation would fail, causing us to crash
    test $0x10000, %r12
    jnz .Lhmac_start

    // After restoring, we always return to .Lhmac_compression_start
    mov $2, %r9b

    // Load round keys
    xor %r8, %r8
    inc %r8
    jmp .Lprime_memory_encryption
.Lrestore_internal_state_primed:

    // Load ymm0 from memory
    mov $2, %al
    jmp .Lload_ymm0_unpack

.Lrestore_sha_registers:
    // If we were interrupted, we have to load the value again
    test %r15, %r15
    jnz restore_internal_state

    vextracti128 $1, %ymm0, state_hi
    vmovdqa %xmm0, state_lo
    load_128bit_constant 0x0405060700010203, 0x0c0d0e0f08090a0b, ishuf_mask

    vzeroupper

    dec %r9b
    jz .Lhmac_compression_next_round
    dec %r9b
    jz .Lhmac_compression_start
    dec %r9b
    jz .Lhmac_start_outer_hash

    jmp .Lexit


// Main HMAC function
// msg: %rdi (0x20 aligned, already padded if final update)
// num_block: %rsi
// out/hash state backup: %rdx (should be at least 48 bytes to contain state backup and iv)
// (resume_from_out:8 || finish:8) : %rcx
.globl hmac256
hmac256:
    .cfi_startproc
    .byte    243,15,30,250
    .cfi_undefined %r15
    .cfi_undefined %r14
    push %rbp
    mov %rsp, %rbp
    sub $0xa0, %rsp
    shr $5, %rsp
    shl $5, %rsp
    push %r12
    push %rdi
    push %rsi
    mov %rcx, %r12
.Lhmac_start:
    xor %r15, %r15
    vzeroall

    // Check whether this is the first call, or a subsequent one
    test $0x100, %r12
    jz .Lhmac_start_from_scratch

    // If this is a subsequent call, restore state, and continue compression
    jmp restore_internal_state

.Lhmac_start_from_scratch:
    // Set the 'no backup available' flag to indicate that it is currently unsafe to restore from memory
    // No backup was saved yet, so we cannot restore anything
    or $0x10000, %r12

    // Load shuffle mask
    load_128bit_constant 0x0405060700010203, 0x0c0d0e0f08090a0b, ishuf_mask
    load_256bit_constant_xmm 0xbb67ae856a09e667, 0xa54ff53a3c6ef372, 0x9b05688c510e527f, 0x5be0cd191f83d9ab, state_lo, state_hi
    vpshufd        $0xb1, state_lo, state_lo
    vpshufd        $0x1b, state_hi, state_hi
    vmovdqa        state_lo, tmsg4
    vpalignr        $0x08, state_hi, state_lo, state_lo
    vpblendw        $0xf0, tmsg4, state_hi, state_hi

    // Compress inner key
    xor %r8, %r8
    jmp load_key
.Lhmac_compress_key:
    mov $1, %al
    vzeroupper
    jmp sha256_compress_block

.Lhmac_inner_key_compressed:

    // Backup state after compressing inner key
    mov $2, %r9b
    jmp backup_internal_state

    // Compress message
.Lhmac_compression_start:
    movdqa (%rdi), block_lolo
    movdqa 0x10(%rdi), block_lohi
    movdqa 0x20(%rdi), block_hilo
    movdqa 0x30(%rdi), block_hihi
    add $0x40, %rdi
    dec %rsi

    mov $2, %al
    jmp sha256_compress_block
.Lhmac_compression_done:

    // If we were interrupted, restore state
    test %r15, %r15
    jnz restore_internal_state

    // Backup hash state every 512 blocks
    test $0x1ff, %si
    jnz .Lhmac_compression_next_round

    mov $1, %r9b
    jmp backup_internal_state

.Lhmac_compression_next_round:
    test %rsi, %rsi
    jnz .Lhmac_compression_start

    // Is this the final call? If not, save state and exit here
    mov $0xff, %r9b
    test %r12b, %r12b
    jz backup_internal_state

    // Bring hash bytes into correct order
    vpshufd $0x1b, state_lo, state_lo
    vpshufd $0xb1, state_hi, state_hi
    vmovdqa state_lo, tmsg4
    vpblendw $0xf0, state_hi, state_lo, state_lo
    vpalignr $0x08, tmsg4, state_hi, state_hi

    vpshufb ishuf_mask, state_lo, state_lo
    vpshufb ishuf_mask, state_hi, state_hi

.Lhmac_start_outer_hash:
    // Backup inner hash
    vmovdqa state_lo, inner_hash_backup_lo
    vmovdqa state_hi, inner_hash_backup_hi

    // Load initial hash state for outer hash
    load_256bit_constant_xmm 0xbb67ae856a09e667, 0xa54ff53a3c6ef372, 0x9b05688c510e527f, 0x5be0cd191f83d9ab, state_lo, state_hi
    vpshufd $0xb1, state_lo, state_lo
    vpshufd $0x1b, state_hi, state_hi
    vmovdqa state_lo, tmsg4
    vpalignr $0x08, state_hi, state_lo, state_lo
    vpblendw $0xf0, tmsg4, state_hi, state_hi

    // Compress outer key
    xor %r8, %r8
    inc %r8
    jmp load_key
.Lhmac_compress_outer_key:

    mov $3, %al
    vzeroupper
    jmp sha256_compress_block

.Lhmac_compress_outer_key_done:
    // Padding
    load_256bit_constant_xmm 0x0000000000000080, 0x0, 0x0, 0x0003000000000000, block_hilo, block_hihi

    vmovdqa inner_hash_backup_lo, block_lolo
    vmovdqa inner_hash_backup_hi, block_lohi

    mov $4, %al
    vzeroupper
    jmp sha256_compress_block

.Lhmac_leave:
    // Bring hash bytes into correct order
    vpshufd $0xb1, state_lo, state_lo
    vpshufd $0x1b, state_hi, state_hi
    vmovdqa state_lo, tmsg4
    vpalignr $0x08, state_hi, state_lo, state_lo
    vpblendw $0xf0, tmsg4, state_hi, state_hi

    vpshufb ishuf_mask, state_lo, state_lo
    vpshufb ishuf_mask, state_hi, state_hi
    vpshufd $0x4e, state_lo, state_lo
    vpshufd $0x4e, state_hi, state_hi

    // Save HMAC
    vmovdqa state_hi, (%rdx)
    vmovdqa state_lo, 0x10(%rdx)

    // If we were interrupted while computing the outer hash, we have to start again
    test %r15, %r15
    jnz restore_internal_state

    // If we were interrupted while computing the outer hash, we have to start again
    test %r15, %r15
    jnz restore_internal_state

.Lexit:
    vzeroall
    mov 0x10(%rsp), %r12
    mov %r15, %rax
    xor %r14, %r14
    leave
    mfence
    .byte    0xf3,0xc3
    .cfi_endproc

.globl hmac256_end
hmac256_end:
    ret
