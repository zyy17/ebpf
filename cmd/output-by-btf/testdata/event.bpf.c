typedef unsigned int tgid_t;

#define FILENAME_LEN  32
#define TASK_COMM_LEN 16

struct foo {
    int a;
    unsigned int b;
};

typedef struct {
    char process_name[TASK_COMM_LEN];
} process;

typedef struct {
    char file_name[FILENAME_LEN];
} file;

typedef enum {
    ACCESS_PROCESS,
    ACCESS_FILE
} access_type;

struct access_info {
    access_type type;
    union {
        process process;
        file file;
    } info;
};

struct embed_b {
    int eb1;
};

struct embed_a {
    int ea;
    int eb;
    struct embed_b eb2;
};

struct event {
    tgid_t pid;
    unsigned long delta_ns;
    char filename[FILENAME_LEN];
    unsigned char task[TASK_COMM_LEN];
    struct foo f;
    struct access_info info1;
    struct access_info info2;
    unsigned int unsigned_int_data[10];
    short short_int_data[4];
    struct embed_a embed_a;
};

// Force emitting struct event into the ELF.
const struct event *__pangolin_output_e __attribute__((unused));
