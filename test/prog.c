#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main()
{
    struct bpf_object *obj;
    int prog_fd;

    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj) {
        printf("Erreur open\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        printf("Erreur load\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "handle_hook");
    prog_fd = bpf_program__fd(prog);

    if (bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_write") == NULL) {
        printf("Erreur attach\n");
        return 1;
    }

    printf("Programme chargé\n");
    while (1) {
        sleep(1);
    }

    return 0;
}