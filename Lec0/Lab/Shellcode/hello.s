section .text
global _start
_start:
	jmp msg
write:
	mov eax, 4
	mov ebx, 1
	pop ecx
	mov edx, 14
	int 0x80

	mov eax, 1
	int 0x80
msg:
	call write
	db 'Hello, World', 0xa