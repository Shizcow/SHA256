default:

test:
	gcc -Wall -O2 -lcrypto testing.c
	./a.out

clean:
	rm -f *~
	rm -f a.out
	rm -f \#*
