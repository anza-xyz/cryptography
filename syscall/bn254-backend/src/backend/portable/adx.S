# Copyright 2022 Firedancer Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Adapted from Firedancer's CIOS Montgomery kernel:
# https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bigint/fd_uint256_mul.inc
# Changes: register-return Rust inline assembly; pointer stores removed.
# This crate restricts use to BN254 Fq operands below 2q, with 4q < 2^256.

    sub     $128, %rsp
    push    %rbp
    push    %r15
    push    %r14
    push    %r13
    push    %r12
    push    %rbx

    mov     %rdx, %rax

    xor     %r9d, %r9d
    xor     %r10d, %r10d
    xor     %r11d, %r11d
    xor     %ebx, %ebx
    xor     %r14d, %r14d

    /* Iteration 0: b[0] */
    mov     (%rax), %rdx
    xor     %r9d, %r9d
    mulx    (%rsi), %r12, %r15
    adcx    %r12, %r10
    mulx    0x8(%rsi), %r12, %rbp
    adox    %r15, %r11
    adcx    %r12, %r11
    mulx    0x10(%rsi), %r12, %r15
    adox    %rbp, %rbx
    adcx    %r12, %rbx
    mulx    0x18(%rsi), %r12, %rbp
    adox    %r15, %r14
    adcx    %r12, %r14
    adox    %r9, %rbp
    adcx    %r9, %rbp

    mov     %r10, %rdx
    imul    %r8, %rdx
    xor     %r9d, %r9d
    mulx    (%rcx), %r12, %r15
    adcx    %r10, %r12
    mulx    0x8(%rcx), %r12, %r13
    adox    %r15, %r11
    adcx    %r12, %r11
    mulx    0x10(%rcx), %r12, %r15
    adox    %r13, %rbx
    adcx    %r12, %rbx
    mulx    0x18(%rcx), %r12, %r13
    adox    %r15, %r14
    adcx    %r12, %r14
    adox    %r9, %r13
    adcx    %r9, %r13
    add     %r13, %rbp
    mov     %rbp, %r10

    /* Iteration 1: b[1] */
    mov     0x8(%rax), %rdx
    xor     %r9d, %r9d
    mulx    (%rsi), %r12, %r15
    adcx    %r12, %r11
    mulx    0x8(%rsi), %r12, %rbp
    adox    %r15, %rbx
    adcx    %r12, %rbx
    mulx    0x10(%rsi), %r12, %r15
    adox    %rbp, %r14
    adcx    %r12, %r14
    mulx    0x18(%rsi), %r12, %rbp
    adox    %r15, %r10
    adcx    %r12, %r10
    adox    %r9, %rbp
    adcx    %r9, %rbp

    mov     %r11, %rdx
    imul    %r8, %rdx
    xor     %r9d, %r9d
    mulx    (%rcx), %r12, %r15
    adcx    %r11, %r12
    mulx    0x8(%rcx), %r12, %r13
    adox    %r15, %rbx
    adcx    %r12, %rbx
    mulx    0x10(%rcx), %r12, %r15
    adox    %r13, %r14
    adcx    %r12, %r14
    mulx    0x18(%rcx), %r12, %r13
    adox    %r15, %r10
    adcx    %r12, %r10
    adox    %r9, %r13
    adcx    %r9, %r13
    add     %r13, %rbp
    mov     %rbp, %r11

    /* Iteration 2: b[2] */
    mov     0x10(%rax), %rdx
    xor     %r9d, %r9d
    mulx    (%rsi), %r12, %r15
    adcx    %r12, %rbx
    mulx    0x8(%rsi), %r12, %rbp
    adox    %r15, %r14
    adcx    %r12, %r14
    mulx    0x10(%rsi), %r12, %r15
    adox    %rbp, %r10
    adcx    %r12, %r10
    mulx    0x18(%rsi), %r12, %rbp
    adox    %r15, %r11
    adcx    %r12, %r11
    adox    %r9, %rbp
    adcx    %r9, %rbp

    mov     %rbx, %rdx
    imul    %r8, %rdx
    xor     %r9d, %r9d
    mulx    (%rcx), %r12, %r15
    adcx    %rbx, %r12
    mulx    0x8(%rcx), %r12, %r13
    adox    %r15, %r14
    adcx    %r12, %r14
    mulx    0x10(%rcx), %r12, %r15
    adox    %r13, %r10
    adcx    %r12, %r10
    mulx    0x18(%rcx), %r12, %r13
    adox    %r15, %r11
    adcx    %r12, %r11
    adox    %r9, %r13
    adcx    %r9, %r13
    add     %r13, %rbp
    mov     %rbp, %rbx

    /* Iteration 3: b[3] */
    mov     0x18(%rax), %rdx
    xor     %r9d, %r9d
    mulx    (%rsi), %r12, %r15
    adcx    %r12, %r14
    mulx    0x8(%rsi), %r12, %rbp
    adox    %r15, %r10
    adcx    %r12, %r10
    mulx    0x10(%rsi), %r12, %r15
    adox    %rbp, %r11
    adcx    %r12, %r11
    mulx    0x18(%rsi), %r12, %rbp
    adox    %r15, %rbx
    adcx    %r12, %rbx
    adox    %r9, %rbp
    adcx    %r9, %rbp

    mov     %r14, %rdx
    imul    %r8, %rdx
    xor     %r9d, %r9d
    mulx    (%rcx), %r12, %r15
    adcx    %r14, %r12
    mulx    0x8(%rcx), %r12, %r13
    adox    %r15, %r10
    adcx    %r12, %r10
    mulx    0x10(%rcx), %r12, %r15
    adox    %r13, %r11
    adcx    %r12, %r11
    mulx    0x18(%rcx), %r12, %r13
    adox    %r15, %rbx
    adcx    %r12, %rbx
    adox    %r9, %r13
    adcx    %r9, %r13
    add     %r13, %rbp
    mov     %rbp, %r14

    /* Conditional subtraction: result = min(t, t - p)
       Result in r10, r11, rbx, r14.  Reuse %rsi, %r8 as scratch. */
    mov     %r10, %rax
    sub     (%rcx), %rax
    mov     %r11, %rdx
    sbb     0x8(%rcx), %rdx
    mov     %rbx, %rsi
    sbb     0x10(%rcx), %rsi
    mov     %r14, %r8
    sbb     0x18(%rcx), %r8
    cmovb   %r10, %rax
    cmovb   %r11, %rdx
    cmovb   %rbx, %rsi
    cmovb   %r14, %r8

    pop     %rbx
    pop     %r12
    pop     %r13
    pop     %r14
    pop     %r15
    pop     %rbp
    add     $128, %rsp
