all: 1919.o

%.o: %.c
	clang -O2 -I/usr/include/x86_64-linux-gnu -target bpf -mcpu=probe -c $< -o $@

clean:
	rm *.o