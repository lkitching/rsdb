.global main

.section .data

hex_format:     .asciz "%#x"
float_format:   .asciz "%.2f"
long_float_format:   .asciz "%.2Lf"

.section .text

.macro trap
    # kill(pid, SIGTRAP)
    movq    $62, %rax
    movq    %r12, %rdi
    movq    $5, %rsi
    syscall
.endm

main:
    push    %rbp
    movq    %rsp, %rbp

    # get pid and move to r12
    movq    $39, %rax
    syscall
    movq    %rax, %r12

    trap

    # print contents of rsi
    leaq    hex_format(%rip), %rdi
    movq    $0, %rax
    call    printf@plt

    # fflush(NULL)
    movq    $0, %rdi
    call    fflush@plt

    trap

    # print contents of mm0
    movq    %mm0, %rsi
    leaq    hex_format(%rip), %rdi
    movq    $0, %rax
    call    printf@plt

    # fflush(NULL)
    movq    $0, %rdi
    call    fflush@plt

    trap

    # print contents of xmm0
    # use 1 as second argument to printf to indicate argument in vector register
    leaq    float_format(%rip), %rdi
    movq    $1, %rax
    call    printf@plt

    # fflush(NULL)
    movq    $0, %rdi
    call    fflush@plt

    trap

    # Print contents of st0
    # make space for 16-byte float and pop top of floating point stack into it
    subq    $16, %rsp
    fstpt   (%rsp)

    # print
    leaq    long_float_format(%rip), %rdi
    movq    $0, %rax
    call    printf@plt

    # fflush(NULL)
    movq    $0, %rdi
    call    fflush@plt

    # de-allocate float
    addq    $16, %rsp

    popq    %rbp
    movq    $0, %rax
    ret

