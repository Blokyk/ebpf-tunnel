all: tunnel

tunnel: tunnel.c utils.h utils.c
	$(CC) $(CFLAGS) tunnel.c utils.c -o tunnel

clean:
	rm -f c-tunnel tunnel connect