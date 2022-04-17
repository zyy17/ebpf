typedef unsigned int pid_t;

#define FILENAME_LEN  32
#define TASK_COMM_LEN 16

struct foo {
    int a;
    unsigned int b;
};

struct event {
    pid_t pid;
    unsigned long delta_ns;
    char filename[FILENAME_LEN];
    unsigned char task[TASK_COMM_LEN];
    struct foo f;
};

// Force emitting struct event into the ELF.
const struct event *e __attribute__((unused));
