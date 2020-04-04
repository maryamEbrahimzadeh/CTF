# [182pts] Unary (20 solves)
# Overview

Original Title: unary
File: libc-2.27.so, unary

We can apply an unary to our inputs.
```sh
$ ./unary 
0. EXIT
1. x++
2. x--
3. ~x
4. -x
Operator: 1
x = 123
f(x) = 124
```
PIE, SSP and RELRO are disabled.

```sh
$ checksec -f unary
RELRO / STACK CANARY / NX / PIE / RPATH / RUNPATH / Symbols / FORTIFY / Fortified / Fortifiable / FILE
Partial RELRO / No canary found / NX enabled / No PIE / No RPATH / No RUNPATH / 77 Symbols / Yes / 2 /  2 /  unary
```
# Plan
# Vulnerability
The vulnerability is very simple. It has Out-Of-Bound error on the menu index.
```sh
mov     rdi, r14
call    read_int
sub     ebx, 1
movsxd  rbx, ebx
mov     rsi, r13
mov     edi, eax
call    qword ptr [r12+rbx*8]
```