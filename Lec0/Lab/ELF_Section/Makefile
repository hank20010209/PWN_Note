all:
	gcc -g welcome.c -o welcome
noPIC:
	gcc -g -fno-stack-protector -no-pie welcome.c -o welcome_NO_PIC
clean:
	rm welcome_NO_PIC welcome