all: warp-ebpf.o

warp-ebpf.o: warp-ebpf.c config.h
	clang -O2 -I/usr/include/x86_64-linux-gnu -target bpf -mcpu=probe -c warp-ebpf.c -o $@

clean:
	rm *.o
