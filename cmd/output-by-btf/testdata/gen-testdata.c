#include <stdio.h>
#include <stdlib.h>
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
        .info1 = {
            .type = ACCESS_FILE,
            .info = {
                .file = {
                    .file_name = "/etc/foo.conf",
                }
            }
        },
        .info2 = {
            .type = ACCESS_PROCESS,
            .info = {
                .process = {
                    .process_name = "/bin/foo",
                }
            }
        },
        .unsigned_int_data = {
            99999,
            99998,
        },
        .short_int_data = {
            1,2,3,4,
        },
        .embed_a = {
            .ea = 1,
            .eb = 2,
            .eb2 = {
                .eb1 = 345,
            }
        },
    };

    unsigned char *pe = (unsigned char *)&e;
    size_t size = sizeof(e);

    FILE *fp = fopen("./testdata.bin", "wb");
    if (!fp) {
        perror("fopen");
        exit(1);
    }

    printf("sizeof(e) = %zu\n", size);
    while (size--) {
        printf("%x", *pe);
        fwrite(pe++, 1, 1, fp);
    }

    fclose(fp);
}