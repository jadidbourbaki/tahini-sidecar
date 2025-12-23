.PHONY: all clean

all: hello

hello: hello.c
	gcc -o hello hello.c

clean:
	rm -f hello

run: hello
	./hello --tahini-secret 1234567890abcdef