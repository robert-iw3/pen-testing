code

PUBLIC sideChannel

sideChannel proc

	xor r8, r8
	xor r9, r9
	xor r10, r10

	xor rax, rax
	xor rdx, rdx

	mov r10, rcx

	mfence

	rdtscp

	mov r8, rax
	mov r9, rdx

	shl r9, 32
	or r9, r8

	lfence

	prefetchnta byte ptr [r10]
	prefetcht2 byte ptr [r10]

	mfence

	rdtscp

	shl rdx, 32
	or rdx, rax

	lfence

	sub rax, r9

	ret

sideChannel endp

end
