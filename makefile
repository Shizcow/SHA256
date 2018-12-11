default:

test:
	gcc -Wall -O2 -lcrypto testing.c
	./a.out

clean:
	rm *~
	rm a.out
