all: pbproxy

pbproxy: source/pbproxy.c
	gcc source/server.c source/client.c source/pbproxy.c -o bin/pbproxy -lcrypto

clean:
	rm -f pbproxy
