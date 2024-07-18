all:
	gcc prefetch.c -O3 -c -o ./prefetch.o
	gcc exp.c -O3 -c -o exp.o -masm=intel
	gcc prefetch.o exp.o -static -o exp
