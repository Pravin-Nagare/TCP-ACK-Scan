all:output
output:ackscan.c
	gcc -o ackscan ackscan.c
clean:
	rm ackscan
