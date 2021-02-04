all: 1919-ingress.o 1919-egress.o

%.o: %.c
	clang -O2 -target bpf -mcpu=probe -c $< -o $@

clean:
	rm *.o