typedef unsigned int pid_t;

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

struct event {
    pid_t pid;
    unsigned long delta_ns;
    char filename[FILENAME_LEN];
    unsigned char task[TASK_COMM_LEN];
    struct foo f;
    struct access_info info;
};

// Force emitting struct event into the ELF.
const struct event *e __attribute__((unused));
