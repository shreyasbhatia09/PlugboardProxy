all: pbproxy

pbproxy: source/pbproxy.c
	gcc -Wall -Werror source/server.c source/client.c source/pbproxy.c source/util.c -o bin/pbproxy -lcrypto

clean:
	rm -f pbproxy


