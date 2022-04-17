#include <stdio.h>
#include "event.bpf.c"

int main(void) {
    struct event e = {
        .pid = 1234,
        .delta_ns = 899999888,
        .filename = "foo.c",
        .task = "foo",
        .f = {
            .a = 1,
            .b = 2,
        },
        .info = {
            .type = ACCESS_FILE,
            .info = {
                .file = {
                    .file_name = "foo",
                }
            }
        }
    };

    unsigned char *pe = (unsigned char *)&e;
    size_t size = sizeof(e);

    while (size--) {
        printf("%d, ", *pe++);
    }
}