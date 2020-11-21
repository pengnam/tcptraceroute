all:
	gcc -o traceroute -std=gnu99 -Wall -Wextra traceroute.c
clean:
	rm traceroute
