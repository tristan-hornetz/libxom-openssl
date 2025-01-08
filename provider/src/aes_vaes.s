.file "src/aes_vaes.s"
.section .rodata
.text
// This version of the AES implementation uses the VAES extensions for better performance

.align 0x100

// void aes_vaes_gctr_linear(void *icb, void* x, void *y, unsigned int num_blocks)
// icb: %rdi
// x: %rsi
// y: %rdx
// num_blocks: %rcx
.global aes_vaes_gctr_linear
aes_vaes_gctr_linear:
    .cfi_startproc
    .byte	243,15,30,250
    xor %r15b, %r15b

    // Load key from immediates
.global aes_vaes_key_lo
aes_vaes_key_lo:
    mov $0x1234567890abcdef,%r14
    vmovq   %r14,%xmm0
.global aes_vaes_key_hi
aes_vaes_key_hi:
    mov $0x1234567890abcdef,%r14
    vmovq   %r14,%xmm1
    vpshufd $0x40, %xmm1, %xmm1
    vpblendw $0xf0, %xmm1, %xmm0, %xmm0
    xor %r14, %r14

    jmp .Lexpand_round_keys

.Laes_vaes_gctr_linear_prepare_roundkey_128:
    inc %al
    vpshufd $255, %xmm2, %xmm2
    vmovdqa %xmm1, %xmm3
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vpermq $0x44, %ymm1, %ymm1

    mov %al, %r8b
    dec %r8b
    jz .Laeskeygenret1
    dec %r8b
    jz .Laeskeygenret2
    dec %r8b
    jz .Laeskeygenret3
    dec %r8b
    jz .Laeskeygenret4
    dec %r8b
    jz .Laeskeygenret5
    dec %r8b
    jz .Laeskeygenret6
    dec %r8b
    jz .Laeskeygenret7
    dec %r8b
    jz .Laeskeygenret8
    dec %r8b
    jz .Laeskeygenret9
    jmp .Laeskeygenret10

.Lexpand_round_keys:
    // Prepare for round key generation
    vmovdqa %xmm0, %xmm1
    vpermq $0x44, %ymm0, %ymm4

    vaeskeygenassist $1, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret1:
    vmovdqa %ymm1, %ymm5
    vaeskeygenassist $2, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret2:
    vmovdqa %ymm1, %ymm6
    vaeskeygenassist $4, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret3:
    vmovdqa %ymm1, %ymm7
    vaeskeygenassist $8, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret4:
    vmovdqa %ymm1, %ymm8
    vaeskeygenassist $16, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret5:
    vmovdqa %ymm1, %ymm9
    vaeskeygenassist $32, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret6:
    vmovdqa %ymm1, %ymm10
    vaeskeygenassist $64, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret7:
    vmovdqa %ymm1, %ymm11
    vaeskeygenassist $0x80, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret8:
    vmovdqa %ymm1, %ymm12
    vaeskeygenassist $0x1b, %xmm1, %xmm2
    jmp .Lexp_trampoline
.Laeskeygenret9:
    vmovdqa %ymm1, %ymm13
    vaeskeygenassist $0x36, %xmm1, %xmm2
.Lexp_trampoline:
    jmp .Laes_vaes_gctr_linear_prepare_roundkey_128
.Laeskeygenret10:
    vmovdqa %ymm1, %ymm14

    // Load shuffle mask
    mov $0x8090a0b0c0d0e0f, %r14
    vmovq %r14, %xmm0
    mov $0x001020304050607, %r14
    vmovq %r14, %xmm1
    vpshufd $0x40, %xmm1, %xmm1
    vpblendw $0xf0, %xmm1, %xmm0, %xmm0
    vmovdqa %xmm0, %xmm15
    vinserti128 $1, %xmm15, %ymm15, %ymm15

    // Load initial counter block
    vmovdqa (%rdi), %xmm3

    // Reverse CB bytes so we can do big-endian incrementation
    vpshufb %xmm15, %xmm3, %xmm3

    // Expand to upper half of %ymm3
    xor %r8, %r8
    inc %r8
    vmovq %r8, %xmm2
    vpaddq %xmm2, %xmm3, %xmm0
    vinserti128 $1, %xmm0, %ymm3, %ymm3

    vpaddd %xmm2, %xmm2, %xmm2
    vpermq $0x44, %ymm2, %ymm2

    // ceil(%rcx / 2)
    inc %rcx
    shr $1, %rcx

.Laes_vaes_gctr_linear_enc_block:
    prefetcht1 0x2000(%rsi)
    prefetcht0 0x100(%rsi)
    prefetchw 0x100(%rdx)

    // Load plain text block
    vmovdqa (%rsi), %ymm1

    // Load counter block into xmm0
    vpshufb %ymm15, %ymm3, %ymm0

    // Encrypt the counter block
    vpxor      %ymm4, %ymm0, %ymm0
    vaesenc     %ymm5, %ymm0, %ymm0
    vaesenc     %ymm6, %ymm0, %ymm0
    vaesenc     %ymm7, %ymm0, %ymm0
    vaesenc     %ymm8, %ymm0, %ymm0
    vaesenc     %ymm9, %ymm0, %ymm0
    vaesenc     %ymm10, %ymm0, %ymm0
    vaesenc     %ymm11, %ymm0, %ymm0
    vaesenc     %ymm12, %ymm0, %ymm0
    vaesenc     %ymm13, %ymm0, %ymm0
    vaesenclast %ymm14, %ymm0, %ymm0

    // XOR encrypted counter with plain text block
    vpxor %ymm1, %ymm0, %ymm0

    // Store to output buffer
    vmovdqa %ymm0, (%rdx)

    // Were our registers cleared?
    // If so, abort and tell caller where to restart
    test %r15b, %r15b
    jnz .Laes_vaes_gctr_linear_enc_done

    // Decrement counter
    dec %rcx
    jz .Laes_vaes_gctr_linear_enc_done

    // Increment counter block
    vpaddd %ymm2, %ymm3, %ymm3

    // Increment input and output pointers
    add $0x20, %rdx
    add $0x20, %rsi

    jmp .Laes_vaes_gctr_linear_enc_block

.Laes_vaes_gctr_linear_enc_done:
    // Clear AVX registers before returning
    vzeroall

    // Return the amount of remaining blocks
    shl $1, %rcx
    mov %rcx, %rax

    .byte	0xf3,0xc3
    .cfi_endproc

.global aes_vaes_gctr_linear_end
aes_vaes_gctr_linear_end:
    ret

// The following is an alternative, size-optimized version of the round key derivation
// Currently unused
.if 0
.text
.align 16,0x90

.Lprepare:
    vpshufd $255, %xmm2, %xmm2
    vmovdqa %xmm1, %xmm3
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    inc %cl
    mov %cl, %al
    dec %al
    jz .Laeskeygenret1_r
    dec %al
    jz .Laeskeygenret2_r
    dec %al
    jz .Laeskeygenret3_r
    dec %al
    jz .Laeskeygenret4_r
    dec %al
    jz .Laeskeygenret5_r
    dec %al
    jz .Laeskeygenret6_r
    dec %al
    jz .Laeskeygenret7_r
    dec %al
    jz .Laeskeygenret8_r
    dec %al
    jz .Laeskeygenret9_r
    jmp .Laeskeygenret10_r

    // CALL HERE
    // parameter xmm1: key
    // fills xmm5-14 with round keys 2 - 10
key_expansion:
    xor %cl, %cl
    vmovdqa %xmm1, %xmm4
    vaeskeygenassist $1, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret1_r:
    vmovdqa %xmm0, %xmm5
    vaeskeygenassist $2, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret2_r:
    vmovdqa %xmm1, %xmm6
    vaeskeygenassist $4, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret3_r:
    vmovdqa %xmm1,  %xmm7
    vaeskeygenassist $8, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret4_r:
    vmovdqa %xmm1,  %xmm8
    vaeskeygenassist $16, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret5_r:
    vmovdqa %xmm1, %xmm9
    vaeskeygenassist $32, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret6_r:
    vmovdqa %xmm1,  %xmm10
    vaeskeygenassist $64, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret7_r:
    vmovdqa %xmm1,  %xmm11
    vaeskeygenassist $0x80, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret8_r:
    vmovdqa %xmm1,  %xmm12
    vaeskeygenassist $0x1b, %xmm1, %xmm2
    jmp .Lexp_trampoline
    .Laeskeygenret9_r:
    vmovdqa %xmm1,  %xmm13
    vaeskeygenassist $0x36, %xmm1, %xmm2
    .Lexp_trampoline:
    jmp .Lprepare
    .Laeskeygenret10_r:
    vmovdqa %xmm1,  %xmm14

    ret
.endif
