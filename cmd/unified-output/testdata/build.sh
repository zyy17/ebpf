clang -O2 -g -target bpf -c event.bpf.c -o event.bpf.o
gcc gen-testdata.c -o gen-testdata