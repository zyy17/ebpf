mkdir bin
clang -O2 -g -target bpf -c ./testdata/event.bpf.c -o ./bin/event.bpf.o
gcc ./testdata/gen-testdata.c -o ./bin/gen-testdata
cd ./bin && ./gen-testdata 1> /dev/null