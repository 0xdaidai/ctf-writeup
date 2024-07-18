exp: clean exp.o
	aarch64-linux-gnu-ld -static -T  exp.lds -o  exp  exp.o
	aarch64-linux-gnu-objcopy -O binary  exp  exp.bin
exp.o: exp.c 
	aarch64-linux-gnu-gcc -fomit-frame-pointer -c -o  exp.o  exp.c
clean:
	rm -f  exp  exp.o